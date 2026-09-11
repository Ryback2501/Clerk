package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// obtainCode drives a full authorization to get a fresh code.
func (f *flow) obtainCode(t *testing.T, overrides map[string]string) string {
	t.Helper()
	page := f.authorize(overrides).Body.String()
	users := userValuePattern.FindStringSubmatch(page)
	if users == nil {
		t.Fatal("no selectable user on the login page")
	}
	return mustCode(t, f.login(page, users[1]))
}

// exchange posts to the token endpoint with client_secret_post.
func (f *flow) exchange(form url.Values) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, f.basePath+TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *flow) tokenForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {f.app.ClientID},
		"client_secret": {f.secret},
	}
}

type tokenBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func decodeToken(t *testing.T, rec *httptest.ResponseRecorder) tokenBody {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %s", rec.Code, rec.Body.String())
	}
	var out tokenBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("token response is not JSON: %v", err)
	}
	return out
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("error response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return out.Error
}

// Acceptance criteria 17, 18, 19.
func TestTokenExchangeReturnsUsableTokens(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, nil)

	got := decodeToken(t, f.exchange(f.tokenForm(code)))

	if got.AccessToken == "" {
		t.Error("no access token was returned")
	}
	if got.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", got.TokenType)
	}
	if got.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive lifetime", got.ExpiresIn)
	}
	if got.Scope != "openid profile" {
		t.Errorf("scope = %q, want the granted scope reported back", got.Scope)
	}
	if got.IDToken == "" {
		t.Fatal("no ID token was returned")
	}
}

// Acceptance criteria 18, 19: a real RS256 JWT with correct claims.
func TestIDTokenIsAValidRS256JWTWithCorrectClaims(t *testing.T) {
	f := newFlow(t)
	before := time.Now()
	code := f.obtainCode(t, nil)
	got := decodeToken(t, f.exchange(f.tokenForm(code)))

	parsed, err := jwt.ParseSigned(got.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("the ID token is not a valid RS256 JWT: %v", err)
	}

	if len(parsed.Headers) != 1 {
		t.Fatalf("got %d JWT headers, want 1", len(parsed.Headers))
	}
	if alg := parsed.Headers[0].Algorithm; alg != string(jose.RS256) {
		t.Errorf("alg = %q, want RS256", alg)
	}
	if kid := parsed.Headers[0].KeyID; kid != f.signer.KeyID() {
		t.Errorf("kid = %q, want %q so clients can select the key from JWKS", kid, f.signer.KeyID())
	}

	// It must verify against the published public key, not merely parse.
	var claims jwt.Claims
	var extra struct {
		Nonce string `json:"nonce"`
		Name  string `json:"name"`
	}
	if err := parsed.Claims(f.signer.Public(), &claims, &extra); err != nil {
		t.Fatalf("the ID token does not verify against the published key: %v", err)
	}

	if claims.Issuer != "https://idp.example.com" {
		t.Errorf("iss = %q, want the configured issuer", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != f.app.ClientID {
		t.Errorf("aud = %v, want the client id", claims.Audience)
	}
	if claims.Subject != f.user.Sub {
		t.Errorf("sub = %q, want the user's subject identifier %q", claims.Subject, f.user.Sub)
	}
	if extra.Nonce != "client-nonce-value" {
		t.Errorf("nonce = %q, want the value from the authorization request", extra.Nonce)
	}
	if extra.Name != "david" {
		t.Errorf("name = %q, want the username for the profile scope", extra.Name)
	}

	if claims.IssuedAt == nil || claims.Expiry == nil {
		t.Fatal("iat and exp are required")
	}
	if claims.IssuedAt.Time().Before(before.Add(-time.Minute)) {
		t.Errorf("iat = %v, want roughly now", claims.IssuedAt.Time())
	}
	if !claims.Expiry.Time().After(claims.IssuedAt.Time()) {
		t.Error("exp is not after iat")
	}
}

// The sub must identify the user, never the username or the row id.
func TestIDTokenSubjectIsTheOpaqueIdentifier(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, nil)
	got := decodeToken(t, f.exchange(f.tokenForm(code)))

	parsed, _ := jwt.ParseSigned(got.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	var claims jwt.Claims
	if err := parsed.Claims(f.signer.Public(), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Subject == "david" {
		t.Error("sub is the username")
	}
	if claims.Subject == "1" {
		t.Error("sub is the database row id")
	}
}

// Without the profile scope there is no name claim to give.
func TestNameClaimFollowsTheGrantedScope(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, map[string]string{"scope": "openid"})
	got := decodeToken(t, f.exchange(f.tokenForm(code)))

	if got.Scope != "openid" {
		t.Errorf("scope = %q, want openid only", got.Scope)
	}

	parsed, _ := jwt.ParseSigned(got.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	var extra map[string]any
	if err := parsed.Claims(f.signer.Public(), &extra); err != nil {
		t.Fatal(err)
	}
	if _, present := extra["name"]; present {
		t.Error("the name claim was issued without the profile scope")
	}
}

// --- Negative cases §21 requires --------------------------------------------

func TestTokenEndpointRejectsBadExchanges(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(f *flow, form url.Values)
		wantError string
		wantCode  int
	}{
		{
			name:      "unsupported grant type",
			mutate:    func(_ *flow, form url.Values) { form.Set("grant_type", "password") },
			wantError: "unsupported_grant_type",
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "refresh token grant is not implemented",
			mutate:    func(_ *flow, form url.Values) { form.Set("grant_type", "refresh_token") },
			wantError: "unsupported_grant_type",
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "missing code",
			mutate:    func(_ *flow, form url.Values) { form.Del("code") },
			wantError: "invalid_request",
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "unknown code",
			mutate:    func(_ *flow, form url.Values) { form.Set("code", "not-a-real-code") },
			wantError: "invalid_grant",
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "wrong client secret",
			mutate:    func(_ *flow, form url.Values) { form.Set("client_secret", "wrong") },
			wantError: "invalid_client",
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "missing client secret",
			mutate:    func(_ *flow, form url.Values) { form.Del("client_secret") },
			wantError: "invalid_client",
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "unknown client",
			mutate:    func(_ *flow, form url.Values) { form.Set("client_id", "no-such-client") },
			wantError: "invalid_client",
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "mismatched redirect uri",
			mutate:    func(_ *flow, form url.Values) { form.Set("redirect_uri", "https://app.example.com/other") },
			wantError: "invalid_grant",
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "missing redirect uri",
			mutate:    func(_ *flow, form url.Values) { form.Del("redirect_uri") },
			wantError: "invalid_grant",
			wantCode:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFlow(t)
			form := f.tokenForm(f.obtainCode(t, nil))
			tt.mutate(f, form)

			rec := f.exchange(form)
			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if got := decodeError(t, rec); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
		})
	}
}

// Acceptance criterion 24: a code is good exactly once.
func TestReplayedCodeIsRejected(t *testing.T) {
	f := newFlow(t)
	form := f.tokenForm(f.obtainCode(t, nil))

	if rec := f.exchange(form); rec.Code != http.StatusOK {
		t.Fatalf("the first exchange failed: %d %s", rec.Code, rec.Body.String())
	}

	rec := f.exchange(form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replaying a code returned %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", got)
	}
}

// A code issued to one client must be useless to another.
func TestCodeIsBoundToTheClientItWasIssuedTo(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, nil)

	other, otherSecret, err := f.store.CreateApplication(context.Background(), "Other", []string{"https://other.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {other.ClientID},
		"client_secret": {otherSecret},
	}
	rec := f.exchange(form)
	if rec.Code == http.StatusOK {
		t.Fatal("another client exchanged a code it was not issued")
	}
	if got := decodeError(t, rec); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", got)
	}
}

// Client credentials may also arrive as HTTP Basic, which discovery advertises.
func TestClientSecretBasicIsAccepted(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirect},
	}
	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(f.app.ClientID), url.QueryEscape(f.secret))

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("client_secret_basic was rejected: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFailedClientAuthenticationChallenges(t *testing.T) {
	f := newFlow(t)
	form := f.tokenForm(f.obtainCode(t, nil))
	form.Set("client_secret", "wrong")

	rec := f.exchange(form)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// RFC 6749 §5.2 requires the challenge when the client tried to authenticate.
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

// --- PKCE -------------------------------------------------------------------

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestPKCEVerifierIsChecked(t *testing.T) {
	const verifier = "a-high-entropy-code-verifier-value-that-is-long-enough"

	t.Run("correct verifier succeeds", func(t *testing.T) {
		f := newFlow(t)
		code := f.obtainCode(t, map[string]string{
			"code_challenge": s256(verifier), "code_challenge_method": "S256",
		})
		form := f.tokenForm(code)
		form.Set("code_verifier", verifier)

		if rec := f.exchange(form); rec.Code != http.StatusOK {
			t.Fatalf("a correct verifier was rejected: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("wrong verifier fails", func(t *testing.T) {
		f := newFlow(t)
		code := f.obtainCode(t, map[string]string{
			"code_challenge": s256(verifier), "code_challenge_method": "S256",
		})
		form := f.tokenForm(code)
		form.Set("code_verifier", "the-wrong-verifier-entirely-but-long-enough")

		rec := f.exchange(form)
		if rec.Code == http.StatusOK {
			t.Fatal("an incorrect PKCE verifier was accepted")
		}
		if got := decodeError(t, rec); got != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", got)
		}
	})

	t.Run("missing verifier fails when a challenge was made", func(t *testing.T) {
		f := newFlow(t)
		code := f.obtainCode(t, map[string]string{
			"code_challenge": s256(verifier), "code_challenge_method": "S256",
		})

		rec := f.exchange(f.tokenForm(code))
		if rec.Code == http.StatusOK {
			t.Fatal("PKCE was bypassed by omitting the verifier")
		}
		if got := decodeError(t, rec); got != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", got)
		}
	})

	// A verifier for a code issued without a challenge is a confused request.
	t.Run("verifier without a challenge fails", func(t *testing.T) {
		f := newFlow(t)
		form := f.tokenForm(f.obtainCode(t, nil))
		form.Set("code_verifier", verifier)

		if rec := f.exchange(form); rec.Code == http.StatusOK {
			t.Error("a verifier was accepted for a code issued without a challenge")
		}
	})
}

// A confidential client must still authenticate even when using PKCE: PKCE
// protects the code, it does not replace the client secret.
func TestPKCEDoesNotReplaceClientAuthentication(t *testing.T) {
	const verifier = "a-high-entropy-code-verifier-value-that-is-long-enough"
	f := newFlow(t)
	code := f.obtainCode(t, map[string]string{
		"code_challenge": s256(verifier), "code_challenge_method": "S256",
	})

	form := f.tokenForm(code)
	form.Del("client_secret")
	form.Set("code_verifier", verifier)

	if rec := f.exchange(form); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: PKCE must not stand in for the client secret", rec.Code)
	}
}

// --- Response hygiene --------------------------------------------------------

func TestTokenResponseIsNotCacheable(t *testing.T) {
	f := newFlow(t)
	rec := f.exchange(f.tokenForm(f.obtainCode(t, nil)))

	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store: the response carries credentials", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestTokenEndpointRejectsGET(t *testing.T) {
	f := newFlow(t)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, TokenPath, nil))
	if rec.Code == http.StatusOK {
		t.Error("GET /token was served; credentials would land in the URL")
	}
}
