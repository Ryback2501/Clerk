// Package keys manages the RSA key pair Clerk signs ID tokens with.
//
// The key is generated once and then persisted: regenerating it would
// invalidate every token the provider has ever issued and break clients that
// have cached the JWKS. Only the public half is ever exposed.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	jose "github.com/go-jose/go-jose/v4"
)

// rsaBits is the modulus size for newly generated keys. 2048 is the floor most
// OIDC clients accept for RS256.
const rsaBits = 2048

// pemBlockType is the PEM label for an unencrypted PKCS#8 private key.
const pemBlockType = "PRIVATE KEY"

// Signer holds the provider's signing key and the key id clients use to select
// it from the JWKS.
type Signer struct {
	private *rsa.PrivateKey
	kid     string
}

// errKeyRaceLost reports that another process created the key file first, so
// this one should load that key instead of its own.
var errKeyRaceLost = errors.New("signing key was created concurrently")

// LoadOrGenerate reads the signing key at path, creating it (and any missing
// parent directories) on first run. A key that exists but cannot be parsed is
// an error rather than a trigger to regenerate: silently minting a new key
// would invalidate every previously issued token.
func LoadOrGenerate(path string) (*Signer, error) {
	// At most two passes: either the key is there, or we create it, or we lost
	// a creation race and the second pass loads the winner's key.
	for attempt := 0; attempt < 2; attempt++ {
		pemBytes, err := os.ReadFile(path)
		switch {
		case err == nil:
			key, err := parsePrivateKey(pemBytes)
			if err != nil {
				return nil, fmt.Errorf("signing key at %s is unreadable (refusing to regenerate, which would invalidate every issued token): %w", path, err)
			}
			return newSigner(key)

		case errors.Is(err, os.ErrNotExist):
			key, err := generateAndPersist(path)
			if errors.Is(err, errKeyRaceLost) {
				continue
			}
			if err != nil {
				return nil, err
			}
			return newSigner(key)

		default:
			return nil, fmt.Errorf("read signing key %s: %w", path, err)
		}
	}
	return nil, fmt.Errorf("signing key at %s could not be loaded or created", path)
}

func newSigner(key *rsa.PrivateKey) (*Signer, error) {
	// RFC 7638 thumbprint: deterministic in the public key, so the kid is stable
	// across restarts without being stored alongside the key.
	jwk := jose.JSONWebKey{Key: key.Public()}
	thumb, err := jwk.Thumbprint(defaultThumbprintHash)
	if err != nil {
		return nil, fmt.Errorf("compute key id: %w", err)
	}
	return &Signer{private: key, kid: base64url(thumb)}, nil
}

func generateAndPersist(path string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}

	// Write to a temporary file and link it into place, rather than writing the
	// destination directly. os.WriteFile truncates first, so a crash mid-write
	// would leave a half-written PEM that LoadOrGenerate refuses to replace —
	// the container would then crashloop until someone deleted the file by
	// hand. os.Link is atomic and fails if the destination exists, which also
	// settles the race between two instances sharing one keys volume.
	tmp, err := os.CreateTemp(dir, ".signing-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// 0600: the private key is secret material and must not be readable by
	// other accounts sharing the volume. CreateTemp already uses 0600, but the
	// mode is set explicitly so the guarantee does not rest on that detail.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secure temporary key file: %w", err)
	}
	if _, err := tmp.Write(pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: der})); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	// Flush to disk before publishing the name, so a crash cannot expose an
	// empty file under the real path.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("flush signing key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close temporary key file: %w", err)
	}

	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errKeyRaceLost
		}
		return nil, fmt.Errorf("publish signing key: %w", err)
	}
	return key, nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key must be RSA, got %T", parsed)
	}
	if bits := key.N.BitLen(); bits < rsaBits {
		return nil, fmt.Errorf("signing key is %d bits, need at least %d for RS256", bits, rsaBits)
	}
	return key, nil
}

// KeyID returns the "kid" published in the JWKS and stamped into ID token headers.
func (s *Signer) KeyID() string { return s.kid }

// Public returns the public half of the signing key.
func (s *Signer) Public() *rsa.PublicKey { return &s.private.PublicKey }

// Private returns the signing key. It is used to mint ID tokens and must never
// reach an HTTP response or a log line.
func (s *Signer) Private() *rsa.PrivateKey { return s.private }

// JWKS returns the public key set served at the jwks endpoint. Marshalling a
// jose.JSONWebKey built from a public key emits only public parameters.
func (s *Signer) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       s.Public(),
			KeyID:     s.kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}},
	}
}
