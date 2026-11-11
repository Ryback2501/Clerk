package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The integration tests start the whole server the way main does — real
// configuration parsing, a real database file, a real signing key, the real
// routes — on a real local HTTP server. Only the outside world is replaced: the
// admin sign-in provider and Bouncer are stand-ins started by the test, so no
// network access or credentials are needed.
//
// The helpers here are meant to be reused by any test that needs a running
// Clerk, not only by integration_test.go.

const (
	// The values the stand-ins and the configuration agree on.
	itAdminSubject     = "integration-admin"
	itBouncerAPIKey    = "bncr_integration-test-key"
	itProviderClientID = "integration-google-client"
	itProviderSecret   = "integration-google-secret"
	itRedirectURI      = "https://client.example.com/callback"
)

// skipUnlessIntegration keeps the slow tests out of the fast run.
func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: run with go test ./... -run Integration")
	}
}

// stackOptions adjusts the stack a test starts.
type stackOptions struct {
	// Logger receives everything Clerk logs. Nil discards it.
	Logger *slog.Logger
	// BouncerAPIKey is the key Clerk is configured with. Empty means the key the
	// stand-in Bouncer expects.
	BouncerAPIKey string
	// BouncerDown points Clerk at an address where nothing is listening.
	BouncerDown bool
}

// stack is a running Clerk with its stand-ins.
type stack struct {
	// URL is Clerk's address, which is also its issuer.
	URL      string
	App      *app
	Provider *fakeProvider
	Bouncer  *fakeBouncer
	// Client never follows redirects, so every step can be checked.
	Client *http.Client
}

// startStack starts the stand-ins, then Clerk, and stops them all at the end
// of the test.
func startStack(t *testing.T, opts stackOptions) *stack {
	t.Helper()

	provider := newFakeProvider(t)
	bouncer := newFakeBouncer(t)
	bouncerURL := bouncer.URL
	if opts.BouncerDown {
		bouncer.Stop()
	}
	apiKey := opts.BouncerAPIKey
	if apiKey == "" {
		apiKey = itBouncerAPIKey
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// The listener exists before Clerk is built, so the issuer can name it.
	srv := httptest.NewUnstartedServer(nil)
	clerkURL := "http://" + srv.Listener.Addr().String()

	dir := t.TempDir()
	env := map[string]string{
		"ISSUER":               clerkURL,
		"DB_PATH":              filepath.Join(dir, "clerk.db"),
		"KEYS_PATH":            filepath.Join(dir, "signing.pem"),
		"BOUNCER_URL":          bouncerURL,
		"BOUNCER_API_KEY":      apiKey,
		"GOOGLE_CLIENT_ID":     itProviderClientID,
		"GOOGLE_CLIENT_SECRET": itProviderSecret,
		"GOOGLE_ISSUER":        provider.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	a, err := newApp(ctx, func(key string) string { return env[key] }, logger)
	if err != nil {
		cancel()
		srv.Close()
		t.Fatalf("start clerk: %v", err)
	}
	srv.Config.Handler = a.handler
	srv.Start()
	t.Cleanup(func() {
		srv.Close()
		cancel()
		_ = a.Close()
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &stack{
		URL:      clerkURL,
		App:      a,
		Provider: provider,
		Bouncer:  bouncer,
		Client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// testClient is a registered application with one test user.
type testClient struct {
	ClientID    string
	Secret      string
	RedirectURI string
	UserID      int64
	UserSub     string
}

// seedClient registers an application and a test user directly in the
// database. The admin interface is not involved, so this works whether or not
// Bouncer is reachable.
func (s *stack) seedClient(t *testing.T) testClient {
	t.Helper()
	ctx := context.Background()
	application, secret, err := s.App.db.CreateApplication(ctx, "Integration "+t.Name(), []string{itRedirectURI})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	user, err := s.App.db.CreateUser(ctx, application.ID, "Jane Tester")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return testClient{
		ClientID:    application.ClientID,
		Secret:      secret,
		RedirectURI: itRedirectURI,
		UserID:      user.ID,
		UserSub:     user.Sub,
	}
}

// get and postForm are the client's requests, failing the test on a transport
// error.
func (s *stack) get(t *testing.T, target string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

// postForm's edit, when given, adjusts the request before it is sent.
func (s *stack) postForm(t *testing.T, target string, form url.Values, edit func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if edit != nil {
		edit(req)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

// readBody returns the body and closes it.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// hiddenField finds a hidden input's value in a rendered page, in any
// attribute order, with HTML escaping undone. It reads Clerk's own pages, which
// html/template renders with double-quoted attributes; it is not a general
// HTML parser. A hidden field without a value fails the test here, where the
// cause is clear, rather than later in the flow.
func hiddenField(t *testing.T, page, name string) string {
	t.Helper()
	for _, input := range inputTag.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, m := range attribute.FindAllStringSubmatch(input, -1) {
			attrs[strings.ToLower(m[1])] = html.UnescapeString(m[2])
		}
		if attrs["type"] != "hidden" || attrs["name"] != name {
			continue
		}
		value, ok := attrs["value"]
		if !ok || value == "" {
			t.Fatalf("the hidden field %q has no value:\n%s", name, input)
		}
		return value
	}
	t.Fatalf("the page has no hidden %q field:\n%s", name, page)
	return ""
}

var (
	inputTag  = regexp.MustCompile(`(?i)<input\b[^>]*>`)
	attribute = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)="([^"]*)"`)
)

// fakeProvider is a stand-in OpenID Connect sign-in provider for the admin
// interface. Its authorization step signs the stand-in administrator in at
// once and sends the browser straight back with a code. Its token endpoint
// checks what a real provider checks: the client's credentials, the redirect
// URI the code was issued for, and the PKCE verifier against the challenge.
type fakeProvider struct {
	URL    string
	server *httptest.Server
	key    *rsa.PrivateKey

	mu     sync.Mutex
	issued map[string]issuedCode // code → the request that issued it
}

type issuedCode struct {
	nonce, challenge, redirectURI string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, issued: map[string]issuedCode{}}

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

func (p *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("client_id") != itProviderClientID ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := "code-" + q.Get("state")
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
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		// Basic credentials are form-encoded first (RFC 6749 §2.3.1).
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != itProviderClientID || secret != itProviderSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	code := r.PostFormValue("code")
	p.mu.Lock()
	issued, ok := p.issued[code]
	delete(p.issued, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || r.PostFormValue("redirect_uri") != issued.redirectURI ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != issued.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "provider-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *fakeProvider) idToken(nonce string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "integration"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(map[string]any{
		"iss":   p.URL,
		"aud":   itProviderClientID,
		"sub":   itAdminSubject,
		"name":  "Integration Admin",
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}).Serialize()
}

// fakeBouncer is a stand-in for Bouncer's access endpoint. It grants the
// admin role to the stand-in administrator, only when Clerk presents the
// expected API key, and refuses everything else the way Bouncer does.
type fakeBouncer struct {
	URL    string
	server *httptest.Server
}

func newFakeBouncer(t *testing.T) *fakeBouncer {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/access", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+itBouncerAPIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_api_key"})
			return
		}
		q := r.URL.Query()
		if q.Get("sub") != itAdminSubject || q.Get("provider") != "google" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"sub":  itAdminSubject,
			"role": map[string]string{"customId": "admin", "name": "Administrator"},
		})
	})
	b := &fakeBouncer{server: httptest.NewServer(mux)}
	b.URL = b.server.URL
	t.Cleanup(b.server.Close)
	return b
}

// Stop makes Bouncer unreachable: its address stays configured in Clerk, but
// nothing listens there any more.
func (b *fakeBouncer) Stop() { b.server.Close() }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
