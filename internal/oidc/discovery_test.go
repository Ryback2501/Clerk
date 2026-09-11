package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/keys"
	"github.com/Ryback2501/Clerk/internal/store"
)

func newTestProvider(t *testing.T, issuer string) (*Provider, *keys.Signer) {
	t.Helper()
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	signer, err := keys.LoadOrGenerate(filepath.Join(dir, "signing.pem"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "clerk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	p, err := New(Options{Issuer: u, Signer: signer, Store: s})
	if err != nil {
		t.Fatal(err)
	}
	return p, signer
}

func get(t *testing.T, p *Provider, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	p.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func discoveryDoc(t *testing.T, p *Provider) map[string]any {
	t.Helper()
	rec := get(t, p, strings.TrimRight(p.issuer.Path, "/")+DiscoveryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", DiscoveryPath, rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery document is not JSON: %v", err)
	}
	return doc
}

// Acceptance criterion 12.
func TestDiscoveryAdvertisesIssuerAndEndpoints(t *testing.T) {
	const issuer = "https://idp.example.com"
	p, _ := newTestProvider(t, issuer)
	doc := discoveryDoc(t, p)

	// The issuer must match byte-for-byte what is put in the "iss" claim, or
	// strict clients reject every token.
	if doc["issuer"] != issuer {
		t.Errorf("issuer = %v, want %q", doc["issuer"], issuer)
	}

	for field, wantPath := range map[string]string{
		"authorization_endpoint": AuthorizePath,
		"token_endpoint":         TokenPath,
		"userinfo_endpoint":      UserInfoPath,
		"jwks_uri":               JWKSPath,
	} {
		got, _ := doc[field].(string)
		want := issuer + wantPath
		if got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
		if !strings.HasPrefix(got, "https://") {
			t.Errorf("%s = %q, want an absolute URL", field, got)
		}
	}
}

func TestDiscoveryHandlesIssuerWithPath(t *testing.T) {
	p, _ := newTestProvider(t, "https://example.com/oidc")
	doc := discoveryDoc(t, p)

	if got, want := doc["authorization_endpoint"], "https://example.com/oidc/authorize"; got != want {
		t.Errorf("authorization_endpoint = %v, want %q", got, want)
	}
	if strings.Contains(doc["jwks_uri"].(string), "//jwks") {
		t.Errorf("jwks_uri has a doubled slash: %v", doc["jwks_uri"])
	}
}

// A trailing slash on the issuer must not leak into the published metadata:
// the issuer and the endpoints derived from it have to agree (RFC 8414 §3.3).
func TestDiscoveryNormalisesTrailingSlashes(t *testing.T) {
	p, _ := newTestProvider(t, "https://example.com//")
	doc := discoveryDoc(t, p)

	if got, want := doc["issuer"], "https://example.com"; got != want {
		t.Errorf("issuer = %v, want %q", got, want)
	}
	if got, want := doc["authorization_endpoint"], "https://example.com/authorize"; got != want {
		t.Errorf("authorization_endpoint = %v, want %q", got, want)
	}
}

// Discovery is a promise: whatever URL it advertises, this server must answer
// on. When the issuer carries a path the endpoints move with it, so mounting
// the handlers at the server root would 404 every client that follows the
// document — and a client that cannot fetch JWKS cannot verify any ID token.
func TestAdvertisedEndpointsAreActuallyServed(t *testing.T) {
	for _, issuer := range []string{"https://example.com", "https://example.com/oidc"} {
		t.Run(issuer, func(t *testing.T) {
			p, _ := newTestProvider(t, issuer)
			doc := discoveryDoc(t, p)

			mux := http.NewServeMux()
			p.Register(mux)

			for _, field := range []string{"jwks_uri"} {
				advertised, _ := doc[field].(string)
				u, err := url.Parse(advertised)
				if err != nil {
					t.Fatalf("%s = %q is not a URL: %v", field, advertised, err)
				}

				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.Path, nil))
				if rec.Code != http.StatusOK {
					t.Errorf("%s advertises %s but GET %s returned %d",
						field, advertised, u.Path, rec.Code)
				}
			}

			// The discovery document itself must sit under the issuer too.
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u_path(t, issuer)+DiscoveryPath, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("discovery is not served at %s%s", u_path(t, issuer), DiscoveryPath)
			}
		})
	}
}

func u_path(t *testing.T, issuer string) string {
	t.Helper()
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(u.Path, "/")
}

func TestDiscoveryAdvertisesSupportedCapabilities(t *testing.T) {
	p, _ := newTestProvider(t, "https://idp.example.com")
	doc := discoveryDoc(t, p)

	for field, want := range map[string][]string{
		"response_types_supported":              {"code"},
		"grant_types_supported":                 {"authorization_code"},
		"subject_types_supported":               {"public"},
		"id_token_signing_alg_values_supported": {"RS256"},
		"scopes_supported":                      {"openid", "profile"},
		"code_challenge_methods_supported":      {"S256"},
	} {
		got := stringSlice(t, doc, field)
		if !equalStrings(got, want) {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}

	// Refresh tokens are deliberately not implemented, so they must not be
	// advertised — a client that sees them would request one and fail.
	for _, g := range stringSlice(t, doc, "grant_types_supported") {
		if g == "refresh_token" {
			t.Error("grant_types_supported advertises refresh_token, which is out of scope")
		}
	}
	if _, present := doc["response_types_supported"]; present {
		for _, rt := range stringSlice(t, doc, "response_types_supported") {
			if strings.Contains(rt, "token") || strings.Contains(rt, "id_token") {
				t.Errorf("implicit/hybrid response type %q advertised; only the code flow is supported", rt)
			}
		}
	}
}

func TestDiscoveryIsJSONAndCacheable(t *testing.T) {
	p, _ := newTestProvider(t, "https://idp.example.com")
	rec := get(t, p, DiscoveryPath)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// Acceptance criterion 21.
func TestJWKSEndpointPublishesTheSigningKey(t *testing.T) {
	p, signer := newTestProvider(t, "https://idp.example.com")
	rec := get(t, p, JWKSPath)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", JWKSPath, rec.Code)
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("JWKS is not JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(set.Keys))
	}
	if got := set.Keys[0]["kid"]; got != signer.KeyID() {
		t.Errorf("kid = %v, want %v", got, signer.KeyID())
	}
	if got := set.Keys[0]["alg"]; got != "RS256" {
		t.Errorf("alg = %v, want RS256", got)
	}
}

// The private key must never be reachable over HTTP.
func TestJWKSEndpointNeverLeaksPrivateKeyMaterial(t *testing.T) {
	p, _ := newTestProvider(t, "https://idp.example.com")
	body := get(t, p, JWKSPath).Body.String()

	for _, secret := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, "PRIVATE"} {
		if strings.Contains(body, secret) {
			t.Errorf("JWKS response contains private key material %s", secret)
		}
	}
}

func TestDiscoveryAndJWKSRejectNonGET(t *testing.T) {
	p, _ := newTestProvider(t, "https://idp.example.com")
	mux := http.NewServeMux()
	p.Register(mux)

	for _, path := range []string{DiscoveryPath, JWKSPath} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("POST %s returned 200; only GET should be served", path)
		}
	}
}

func stringSlice(t *testing.T, doc map[string]any, field string) []string {
	t.Helper()
	raw, ok := doc[field]
	if !ok {
		t.Fatalf("discovery document is missing %q", field)
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("%q is %T, want an array", field, raw)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(string))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
