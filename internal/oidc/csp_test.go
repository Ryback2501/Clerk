package oidc

import (
	"net/http"
	"strings"
	"testing"
)

func TestLoginPageCSPAllowsTheClientRedirect(t *testing.T) {
	f := newFlow(t)
	rec := f.authorize(nil)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://app.example.com") {
		t.Errorf("form-action = %q, want the client's origin permitted so the final redirect is not blocked", csp)
	}
}

func TestErrorPageCSPForbidsFormSubmission(t *testing.T) {
	f := newFlow(t)
	rec := f.authorize(map[string]string{"client_id": "unknown"})

	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'none'") {
		t.Errorf("form-action = %q, want 'none' on a page with no form", csp)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSurfacesUseSeparateCSRFCookies(t *testing.T) {
	f := newFlow(t)
	f.authorize(nil)

	if _, ok := f.jar["clerk_csrf_login"]; !ok {
		t.Errorf("login page did not set its own CSRF cookie; jar = %v", f.jar)
	}
	if _, ok := f.jar["clerk_csrf_admin"]; ok {
		t.Error("the login page issued the administration CSRF cookie")
	}
}
