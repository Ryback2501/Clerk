package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{"an authorization code used as a bearer token", "wrong-kind-of-credential"},
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
			req := httptest.NewRequest(http.MethodGet, UserInfoPath, nil)
			req.Header.Set("Authorization", header)
			rec := httptest.NewRecorder()
			f.mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				t.Errorf("Authorization: %q was accepted", header)
			}
		})
	}
}

// Deleting a user must immediately stop their tokens working.
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
