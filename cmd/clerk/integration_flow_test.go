package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Ryback2501/Clerk/internal/adminauth"
)

// oidcFlow walks one Authorization Code sign-in through Clerk, the way a
// third-party application and its user's browser would. Each step checks its
// own result and leaves what the next step needs.
type oidcFlow struct {
	s      *stack
	client testClient
	state  string
	nonce  string

	discovery   map[string]any
	requestID   string
	csrfToken   string
	code        string
	accessToken string
	idToken     string
}

// newFlow registers a fresh application and test user for one sign-in.
func (s *stack) newFlow(t *testing.T) *oidcFlow {
	t.Helper()
	return &oidcFlow{
		s:      s,
		client: s.seedClient(t),
		state:  "integration-state",
		nonce:  "integration-nonce",
	}
}

// run performs every step in order, each as a sub-test named after it, and
// stops at the first one that fails. The failing sub-test already marks the
// test failed and says why, so nothing more is reported here.
func (f *oidcFlow) run(t *testing.T) {
	for _, step := range f.steps() {
		if !t.Run(step.name, step.fn) {
			return
		}
	}
}

type flowStep struct {
	name string
	fn   func(*testing.T)
}

func (f *oidcFlow) steps() []flowStep {
	return []flowStep{
		{"discovery", f.discover},
		{"authorize", f.authorize},
		{"login", f.login},
		{"token", f.token},
		{"userinfo", f.userinfo},
	}
}

// discover reads the discovery document and checks it names this server.
func (f *oidcFlow) discover(t *testing.T) {
	resp := f.s.get(t, f.s.URL+"/.well-known/openid-configuration", nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery answered %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &f.discovery); err != nil {
		t.Fatalf("discovery is not JSON: %v", err)
	}
	for key, want := range map[string]string{
		"issuer":                 f.s.URL,
		"authorization_endpoint": f.s.URL + "/authorize",
		"token_endpoint":         f.s.URL + "/token",
		"userinfo_endpoint":      f.s.URL + "/userinfo",
		"jwks_uri":               f.s.URL + "/jwks",
	} {
		if got := f.discovery[key]; got != want {
			t.Errorf("discovery %s = %v, want %s", key, got, want)
		}
	}
}

// authorize starts the sign-in and expects the page to pick a test identity.
func (f *oidcFlow) authorize(t *testing.T) {
	q := url.Values{
		"client_id":     {f.client.ClientID},
		"redirect_uri":  {f.client.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {f.state},
		"nonce":         {f.nonce},
	}
	resp := f.s.get(t, f.endpoint(t, "authorization_endpoint")+"?"+q.Encode(), nil)
	page := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize answered %d: %s", resp.StatusCode, page)
	}
	if !strings.Contains(page, "Jane Tester") {
		t.Errorf("the sign-in page does not offer the test user:\n%s", page)
	}
	f.requestID = hiddenField(t, page, "request_id")
	f.csrfToken = hiddenField(t, page, "csrf_token")
}

// login picks the test user and expects to be sent back to the application
// with a code and the original state.
func (f *oidcFlow) login(t *testing.T) {
	resp := f.s.postForm(t, f.endpoint(t, "authorization_endpoint"), url.Values{
		"request_id": {f.requestID},
		"csrf_token": {f.csrfToken},
		"user_id":    {strconv.FormatInt(f.client.UserID, 10)},
	}, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login answered %d, want a redirect: %s", resp.StatusCode, body)
	}
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("login redirect: %v", err)
	}
	if got := back.Scheme + "://" + back.Host + back.Path; got != f.client.RedirectURI {
		t.Fatalf("login sent the browser to %s, want %s", got, f.client.RedirectURI)
	}
	if got := back.Query().Get("state"); got != f.state {
		t.Errorf("state came back as %q, want %q", got, f.state)
	}
	if f.code = back.Query().Get("code"); f.code == "" {
		t.Fatalf("login redirect carries no code: %s", back)
	}
}

// token exchanges the code, then checks the ID token's signature against the
// published keys and its claims against this sign-in.
func (f *oidcFlow) token(t *testing.T) {
	resp := f.s.postForm(t, f.endpoint(t, "token_endpoint"), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {f.code},
		"redirect_uri": {f.client.RedirectURI},
	}, func(req *http.Request) {
		// client_secret_basic form-encodes each part first (RFC 6749 §2.3.1).
		req.SetBasicAuth(url.QueryEscape(f.client.ClientID), url.QueryEscape(f.client.Secret))
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token answered %d: %s", resp.StatusCode, body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(body), &tokens); err != nil {
		t.Fatalf("token response is not JSON: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" || tokens.TokenType != "Bearer" {
		t.Fatalf("token response is incomplete: %s", body)
	}
	f.accessToken, f.idToken = tokens.AccessToken, tokens.IDToken

	claims := f.verifyIDToken(t)
	for key, want := range map[string]string{
		"iss":   f.s.URL,
		"aud":   f.client.ClientID,
		"sub":   f.client.UserSub,
		"nonce": f.nonce,
	} {
		got := claims[key]
		if aud, ok := got.([]any); ok && len(aud) == 1 {
			got = aud[0]
		}
		if got != want {
			t.Errorf("ID token %s = %v, want %s", key, got, want)
		}
	}
}

// verifyIDToken checks the ID token's RS256 signature with the key published
// at the jwks_uri, and returns its claims.
func (f *oidcFlow) verifyIDToken(t *testing.T) map[string]any {
	t.Helper()
	resp := f.s.get(t, f.endpoint(t, "jwks_uri"), nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks answered %d: %s", resp.StatusCode, body)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		t.Fatalf("jwks is not a key set: %v", err)
	}

	parsed, err := jwt.ParseSigned(f.idToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("the ID token does not parse: %v", err)
	}
	if len(parsed.Headers) != 1 {
		t.Fatalf("the ID token has %d signatures, want 1", len(parsed.Headers))
	}
	keys := set.Key(parsed.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("jwks has no key %q", parsed.Headers[0].KeyID)
	}
	var claims map[string]any
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		t.Fatalf("the ID token's signature does not verify against /jwks: %v", err)
	}
	return claims
}

// userinfo presents the access token and expects the user's claims.
func (f *oidcFlow) userinfo(t *testing.T) {
	resp := f.s.get(t, f.endpoint(t, "userinfo_endpoint"), func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+f.accessToken)
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo answered %d: %s", resp.StatusCode, body)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(body), &claims); err != nil {
		t.Fatalf("userinfo is not JSON: %v", err)
	}
	if claims["sub"] != f.client.UserSub {
		t.Errorf("userinfo sub = %v, want %s", claims["sub"], f.client.UserSub)
	}
}

// endpoint is an address from the discovery document, which the client
// follows rather than guessing.
func (f *oidcFlow) endpoint(t *testing.T, key string) string {
	t.Helper()
	if f.discovery == nil {
		t.Fatal("discovery has not run")
	}
	v, _ := f.discovery[key].(string)
	if v == "" {
		t.Fatalf("discovery has no %s", key)
	}
	return v
}

// adminSignIn signs in to the admin interface through the stand-in provider,
// as a browser would, and returns Clerk's answer to the provider's callback.
func (s *stack) adminSignIn(t *testing.T) *http.Response {
	t.Helper()
	start := s.get(t, s.URL+"/admin/auth/google/start", nil)
	_ = readBody(t, start)
	toProvider := start.Header.Get("Location")
	if start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(toProvider, s.Provider.URL) {
		t.Fatalf("starting the admin sign-in answered %d → %q, want a redirect to the provider",
			start.StatusCode, toProvider)
	}

	atProvider := s.get(t, toProvider, nil)
	_ = readBody(t, atProvider)
	callback := atProvider.Header.Get("Location")
	if !strings.HasPrefix(callback, s.URL+"/admin/auth/google/callback") {
		t.Fatalf("the provider sent the browser to %q, want Clerk's callback", callback)
	}
	return s.get(t, callback, nil)
}

// hasAdminSession reports whether the client holds an admin session cookie.
func (s *stack) hasAdminSession(t *testing.T) bool {
	t.Helper()
	u, err := url.Parse(s.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Client.Jar.Cookies(u) {
		if c.Name == adminauth.SessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}
