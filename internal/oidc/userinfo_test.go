package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// bearer issues a UserInfo request carrying the given token.
func (f *flow) userinfo(token string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, f.basePath+UserInfoPath, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// accessTokenFor drives a full flow and returns the resulting access token.
func (f *flow) accessTokenFor(t *testing.T, overrides map[string]string) string {
	t.Helper()
	return decodeToken(t, f.exchange(f.tokenForm(f.obtainCode(t, overrides)))).AccessToken
}

func claimsFrom(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo returned %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("userinfo response is not JSON: %v", err)
	}
	return out
}

// Acceptance criterion 20.
func TestUserInfoReturnsTheIdentity(t *testing.T) {
	f := newFlow(t)
	claims := claimsFrom(t, f.userinfo(f.accessTokenFor(t, nil)))

	if got := claims["sub"]; got != f.user.Sub {
		t.Errorf("sub = %v, want %q", got, f.user.Sub)
	}
	if got := claims["name"]; got != "david" {
		t.Errorf("name = %v, want david", got)
	}

	// §11: nothing beyond the minimal identity.
	for _, forbidden := range []string{"email", "phone_number", "address", "groups", "roles", "picture"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("userinfo returned %q, which §11 rules out", forbidden)
		}
	}
}

// The sub here must be the same value the ID token asserted, or a client
// cannot correlate the two.
func TestUserInfoSubMatchesTheIDToken(t *testing.T) {
	f := newFlow(t)
	tokens := decodeToken(t, f.exchange(f.tokenForm(f.obtainCode(t, nil))))

	claims := claimsFrom(t, f.userinfo(tokens.AccessToken))
	idSub := subjectOf(t, f, tokens.IDToken)

	if claims["sub"] != idSub {
		t.Errorf("userinfo sub = %v, id_token sub = %v; they must be the same account", claims["sub"], idSub)
	}
}

// Scope enforcement: profile is what grants the name.
func TestUserInfoHonoursTheGrantedScope(t *testing.T) {
	f := newFlow(t)
	claims := claimsFrom(t, f.userinfo(f.accessTokenFor(t, map[string]string{"scope": "openid"})))

	if _, present := claims["name"]; present {
		t.Error("name was returned without the profile scope")
	}
	// sub is always present: it is what identifies the response.
	if claims["sub"] != f.user.Sub {
		t.Errorf("sub = %v, want it present regardless of scope", claims["sub"])
	}
}

func TestUserInfoRejectsBadTokens(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no token at all", ""},
		{"a token that was never issued", "not-a-real-token"},
		{"a value that is not a credential at all", "wrong-kind-of-credential"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFlow(t)
			rec := f.userinfo(tt.token)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			// RFC 6750 §3: the challenge tells the client what went wrong.
			challenge := rec.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", challenge)
			}
			if tt.token != "" && !strings.Contains(challenge, "invalid_token") {
				t.Errorf("WWW-Authenticate = %q, want error=\"invalid_token\"", challenge)
			}
			// The body must not leak the identity it refused to serve.
			if strings.Contains(rec.Body.String(), "david") {
				t.Error("the error response leaked user information")
			}
		})
	}
}

func TestUserInfoRejectsAnExpiredToken(t *testing.T) {
	f := newFlowWith(t, "https://idp.example.com", func(o *Options) {
		o.AccessTokenTTL = time.Second
	})
	token := f.accessTokenFor(t, nil)

	// Move the store's clock past the token's lifetime.
	f.advance(2 * time.Second)

	rec := f.userinfo(token)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an expired token", rec.Code)
	}
}

// A malformed Authorization header must not be treated as a valid scheme.
func TestUserInfoRejectsNonBearerSchemes(t *testing.T) {
	f := newFlow(t)
	token := f.accessTokenFor(t, nil)

	for _, header := range []string{
		"Basic " + token,
		token,
		"Bearer",
		"Bearer  ",
	} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, f.basePath+UserInfoPath, nil)
			req.Header.Set("Authorization", header)
			rec := httptest.NewRecorder()
			f.mux.ServeHTTP(rec, req)

			// Asserting 401 specifically: "not 200" would also be satisfied by
			// a 404, so the test would keep passing if the route vanished.
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Authorization: %q returned %d, want 401", header, rec.Code)
			}
		})
	}
}

// An unredeemed authorization code is a credential, but not this kind. It must
// not be usable as a bearer token.
func TestUserInfoRejectsAnAuthorizationCode(t *testing.T) {
	f := newFlow(t)
	code := f.obtainCode(t, nil)

	rec := f.userinfo(code)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an authorization code was accepted at userinfo: %d", rec.Code)
	}

	// And it must still work where it belongs.
	if got := f.exchange(f.tokenForm(code)); got.Code != http.StatusOK {
		t.Errorf("presenting the code at userinfo consumed it: token exchange returned %d", got.Code)
	}
}

// OIDC Core §5.3.1 permits POST, and RFC 6750 §2.2 puts the credential in the
// form body. A client doing that must not be refused while holding a valid
// token.
func TestUserInfoAcceptsAFormEncodedPost(t *testing.T) {
	f := newFlow(t)
	token := f.accessTokenFor(t, nil)

	req := httptest.NewRequest(http.MethodPost, f.basePath+UserInfoPath,
		strings.NewReader(url.Values{"access_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	claims := claimsFrom(t, rec)
	if claims["sub"] != f.user.Sub {
		t.Errorf("sub = %v, want %q", claims["sub"], f.user.Sub)
	}
}

// Without credentials there is nothing to call invalid, and saying otherwise
// makes a client discard a token that may be fine.
func TestMissingCredentialsAreNotReportedAsAnInvalidToken(t *testing.T) {
	f := newFlow(t)
	rec := f.userinfo("")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "invalid_token") {
		t.Errorf("body = %s, want no error code when nothing was presented", rec.Body.String())
	}
	if strings.Contains(rec.Header().Get("WWW-Authenticate"), "error=") {
		t.Errorf("challenge = %q, want no error parameter", rec.Header().Get("WWW-Authenticate"))
	}
}

// Deleting a user must immediately stop their tokens working. In practice the
// foreign key cascade removes the tokens, so this asserts the observable
// outcome rather than any particular code path.
func TestUserInfoAfterTheUserIsDeleted(t *testing.T) {
	f := newFlow(t)
	token := f.accessTokenFor(t, nil)

	if err := f.store.DeleteUser(f.ctx(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	if rec := f.userinfo(token); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 once the identity is gone", rec.Code)
	}
}

func TestUserInfoResponseIsNotCacheable(t *testing.T) {
	f := newFlow(t)
	rec := f.userinfo(f.accessTokenFor(t, nil))

	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
