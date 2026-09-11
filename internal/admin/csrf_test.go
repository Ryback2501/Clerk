package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueTokenSetsACookieAndReturnsAMatchingToken(t *testing.T) {
	g := newCSRF()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)

	token := g.issue(rec, req)
	if token == "" {
		t.Fatal("issue() returned an empty token")
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issue() set %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("the CSRF cookie must be HttpOnly so scripts cannot read it")
	}
	if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
		t.Error("the CSRF cookie must set SameSite")
	}
	if c.Path != "/" {
		t.Errorf("cookie path = %q, want /", c.Path)
	}
}

// An existing token must be reused, or opening two tabs would invalidate the
// form in the first one.
func TestIssueReusesAnExistingToken(t *testing.T) {
	g := newCSRF()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	first := g.issue(rec, req)

	second := httptest.NewRequest(http.MethodGet, "/admin", nil)
	second.AddCookie(&http.Cookie{Name: csrfCookieName, Value: first})
	if got := g.issue(httptest.NewRecorder(), second); got != first {
		t.Errorf("issue() minted a new token %q for a request already carrying %q", got, first)
	}
}

func TestCheckAcceptsAMatchingFormField(t *testing.T) {
	g := newCSRF()
	token := g.issue(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))

	req := httptest.NewRequest(http.MethodPost, "/admin/applications",
		strings.NewReader(csrfFieldName+"="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})

	if err := g.check(req); err != nil {
		t.Errorf("check() rejected a valid token: %v", err)
	}
}

func TestCheckRejectsForgeries(t *testing.T) {
	g := newCSRF()
	good := g.issue(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))

	tests := []struct {
		name   string
		cookie string
		field  string
	}{
		{"no cookie and no field", "", ""},
		{"cookie but no field", good, ""},
		{"field but no cookie", "", good},
		{"mismatched values", good, "forged-token"},
		{"empty values on both sides", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/applications",
				strings.NewReader(csrfFieldName+"="+tt.field))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tt.cookie})
			}

			if err := g.check(req); err == nil {
				t.Error("check() accepted a request that should have been rejected")
			}
		})
	}
}
