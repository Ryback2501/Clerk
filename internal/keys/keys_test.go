package keys

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func tempKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "nested", "signing.pem")
}

func TestLoadOrGenerateCreatesKey(t *testing.T) {
	path := tempKeyPath(t)

	s, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate() error: %v", err)
	}
	if s.KeyID() == "" {
		t.Error("KeyID() is empty; clients need a kid to select the verification key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file was not written: %v", err)
	}
}

// Acceptance criterion 22: signing keys survive container restarts. A second
// call must load the existing key, never mint a new one.
func TestLoadOrGenerateIsStableAcrossRestarts(t *testing.T) {
	path := tempKeyPath(t)

	first, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("first LoadOrGenerate() error: %v", err)
	}
	second, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("second LoadOrGenerate() error: %v", err)
	}

	if first.KeyID() != second.KeyID() {
		t.Errorf("kid changed across reload: %q -> %q; previously issued tokens would stop verifying",
			first.KeyID(), second.KeyID())
	}
	if first.Public().N.Cmp(second.Public().N) != 0 {
		t.Error("public modulus changed across reload; the key was regenerated")
	}
}

// The private key is secret material: the file must not be group/world readable.
func TestGeneratedKeyFileIsPrivate(t *testing.T) {
	path := tempKeyPath(t)
	if _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", perm)
	}
}

func TestJWKSPublishesPublicKeyOnly(t *testing.T) {
	path := tempKeyPath(t)
	s, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate() error: %v", err)
	}

	raw, err := json.Marshal(s.JWKS())
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	body := string(raw)

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(set.Keys))
	}

	k := set.Keys[0]
	for field, want := range map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": s.KeyID()} {
		if k[field] != want {
			t.Errorf("JWKS key %q = %v, want %v", field, k[field], want)
		}
	}
	for _, required := range []string{"n", "e"} {
		if _, ok := k[required]; !ok {
			t.Errorf("JWKS key is missing %q; clients cannot reconstruct the public key", required)
		}
	}

	// Never publish private parameters. "d" is the private exponent; p/q/dp/dq/qi
	// are the CRT factors.
	for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, leaked := k[secret]; leaked {
			t.Errorf("JWKS leaks private key parameter %q", secret)
		}
	}
	if strings.Contains(body, "PRIVATE") {
		t.Error("JWKS output contains PEM private key material")
	}
}

func TestLoadOrGenerateRejectsCorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Silently regenerating would invalidate every token ever issued by this
	// provider, so a damaged key must be a hard failure the operator sees.
	if _, err := LoadOrGenerate(path); err == nil {
		t.Fatal("LoadOrGenerate() accepted a corrupt key file, want error")
	}
}

// Two instances sharing one keys volume must converge on a single key. If both
// generated and the loser's write clobbered the winner's file, the loser would
// keep serving a JWKS for a key that is no longer on disk, and every token it
// issued would stop verifying after its next restart.
func TestConcurrentLoadOrGenerateConvergesOnOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")

	const racers = 8
	var wg sync.WaitGroup
	kids := make([]string, racers)
	errs := make([]error, racers)

	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together to widen the race window
			s, err := LoadOrGenerate(path)
			if err != nil {
				errs[i] = err
				return
			}
			kids[i] = s.KeyID()
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d failed: %v", i, err)
		}
	}
	for i, kid := range kids {
		if kid != kids[0] {
			t.Errorf("racer %d got kid %q, racer 0 got %q; instances disagree on the signing key",
				i, kid, kids[0])
		}
	}

	// The key on disk must be the one everybody reported.
	reloaded, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.KeyID() != kids[0] {
		t.Errorf("on-disk kid %q does not match the kid handed out (%q)", reloaded.KeyID(), kids[0])
	}

	// No temporary files may be left behind in the keys directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".signing-") {
			t.Errorf("temporary key file %q was left on disk", e.Name())
		}
	}
}

// A half-written key must not be silently replaced: regenerating would
// invalidate every token this provider ever issued, so an operator has to see it.
func TestTruncatedKeyFileIsNotSilentlyReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	if _, err := LoadOrGenerate(path); err != nil {
		t.Fatal(err)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original[:len(original)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerate(path); err == nil {
		t.Fatal("a truncated key file was accepted or silently regenerated")
	}
}
