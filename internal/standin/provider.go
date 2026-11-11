// Package standin holds stand-ins for the services Clerk talks to, for tests
// only: an OpenID Connect sign-in provider for the admin interface. Nothing
// outside a _test.go file may import it.
package standin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The credentials and identity the stand-in provider and its tests agree on.
const (
	ProviderClientID     = "integration-google-client"
	ProviderClientSecret = "integration-google-secret"
	AdminSubject         = "integration-admin"
)

// Secret is a secret value the provider exchanged, with a name to report it by.
type Secret struct{ Name, Value string }

// Provider is a stand-in OpenID Connect sign-in provider for the admin
// interface, started by a test. Its authorization step signs the stand-in administrator in at
// once and sends the browser straight back with a code. Its token endpoint
// checks what a real provider checks: the client's credentials, the redirect
// URI the code was issued for, and the PKCE verifier against the challenge.
type Provider struct {
	URL    string
	server *httptest.Server
	key    *rsa.PrivateKey

	mu     sync.Mutex
	issued map[string]issuedCode // code → the request that issued it
	seen   []Secret              // every secret of an admin sign-in, for log checks
}

// Secrets returns the secret values the admin sign-ins exchanged with this
// provider so far: codes, PKCE verifiers and tokens.
func (p *Provider) Secrets() []Secret {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Secret(nil), p.seen...)
}

// remember records a secret; the caller must not hold p.mu.
func (p *Provider) remember(name, value string) {
	if value == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, Secret{Name: name, Value: value})
}

type issuedCode struct {
	nonce, challenge, redirectURI string
}

func NewProvider(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{key: key, issued: map[string]issuedCode{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/auth",
			"token_endpoint":                        p.URL + "/token",
			"jwks_uri":                              p.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: "integration", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("GET /auth", p.authorize)
	mux.HandleFunc("POST /token", p.token)

	p.server = httptest.NewServer(mux)
	p.URL = p.server.URL
	t.Cleanup(p.server.Close)
	return p
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("client_id") != ProviderClientID ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := rand.Text() // unique per request, so sign-ins never collide
	p.mu.Lock()
	p.issued[code] = issuedCode{
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"),
	}
	p.mu.Unlock()

	v := back.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	back.RawQuery = v.Encode()
	p.remember("admin sign-in provider code", code)
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		// Basic credentials are form-encoded first (RFC 6749 §2.3.1).
		var errID, errSecret error
		id, errID = url.QueryUnescape(id)
		secret, errSecret = url.QueryUnescape(secret)
		if errID != nil || errSecret != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_request", "error_description": "badly encoded basic credentials",
			})
			return
		}
	} else {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != ProviderClientID || secret != ProviderClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	// Like a real provider's, a code is single-use: any exchange attempt uses
	// it up, successful or not. Each refusal still says why.
	code := r.PostFormValue("code")
	p.mu.Lock()
	issued, ok := p.issued[code]
	delete(p.issued, code)
	p.mu.Unlock()
	p.remember("admin sign-in PKCE verifier", r.PostFormValue("code_verifier"))
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	switch {
	case !ok:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
		return
	case r.PostFormValue("redirect_uri") != issued.redirectURI:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	case base64.RawURLEncoding.EncodeToString(sum[:]) != issued.challenge:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "pkce verifier mismatch"})
		return
	}

	idToken, err := p.idToken(issued.nonce)
	if err != nil {
		// Reported to Clerk, which then fails the sign-in: a handler must not
		// touch the test's *testing.T from the server's goroutine.
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error", "error_description": err.Error(),
		})
		return
	}
	accessToken := "provider-access-token-" + rand.Text()
	p.remember("admin sign-in provider access token", accessToken)
	p.remember("admin sign-in provider ID token", idToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *Provider) idToken(nonce string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "integration"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(map[string]any{
		"iss":   p.URL,
		"aud":   ProviderClientID,
		"sub":   AdminSubject,
		"name":  "Integration Admin",
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}).Serialize()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
