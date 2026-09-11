package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueTokenSetsACookieAndReturnsAMatchingToken(t *testing.T) {
	g := NewCSRF()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)

	token := g.Issue(rec, req)
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
	g := NewCSRF()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	first := g.Issue(rec, req)

	second := httptest.NewRequest(http.MethodGet, "/admin", nil)
	second.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: first})
	if got := g.Issue(httptest.NewRecorder(), second); got != first {
		t.Errorf("issue() minted a new token %q for a request already carrying %q", got, first)
	}
}

func TestCheckAcceptsAMatchingFormField(t *testing.T) {
	g := NewCSRF()
	token := g.Issue(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))

	req := httptest.NewRequest(http.MethodPost, "/admin/applications",
		strings.NewReader(CSRFFieldName+"="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})

	if err := g.Check(req); err != nil {
		t.Errorf("check() rejected a valid token: %v", err)
	}
}

func TestCheckRejectsForgeries(t *testing.T) {
	g := NewCSRF()
	good := g.Issue(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))

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
				strings.NewReader(CSRFFieldName+"="+tt.field))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: tt.cookie})
			}

			if err := g.Check(req); err == nil {
				t.Error("check() accepted a request that should have been rejected")
			}
		})
	}
}
