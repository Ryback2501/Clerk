package admin

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/adminauth"
)

// These tests drive the admin sign-in pages through real HTTP, on the site in
// signin_site_test.go.

// ---- Sign-out ----

func TestSignOutEndsTheSessionOnTheServer(t *testing.T) {
	site := newSignInSite(t)
	site.signInOK(t)
	id := site.sessionID(t)

	resp := site.postForm(t, "/admin/signout", url.Values{"csrf_token": {site.csrf(t)}})
	readAll(t, resp)

	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/signin" {
		t.Errorf("sign-out answered %d → %q, want 303 to /admin/signin", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := cookieIn(resp, adminauth.SessionCookieName); c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("sign-out did not clear the session cookie: %+v", c)
	}
	if _, err := site.sessions.GetAdminSession(context.Background(), id); err == nil {
		t.Error("the session still exists on the server after signing out")
	}
}

func TestOldSessionCookieAfterSignOutIsRefused(t *testing.T) {
	site := newSignInSite(t)
	site.signInOK(t)
	id := site.sessionID(t)
	readAll(t, site.postForm(t, "/admin/signout", url.Values{"csrf_token": {site.csrf(t)}}))

	// Present the old cookie again, as a copy kept elsewhere would.
	resp := site.getWithSession(t, "/admin", id)
	readAll(t, resp)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/signin" {
		t.Errorf("the old session cookie answered %d → %q, want 303 to /admin/signin",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSignOutWithoutCSRFTokenIsRefused(t *testing.T) {
	site := newSignInSite(t)
	site.signInOK(t)
	id := site.sessionID(t)

	resp := site.postForm(t, "/admin/signout", url.Values{})
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Request rejected") {
		t.Errorf("sign-out without a CSRF token answered %d, want 403 \"Request rejected\": %s", resp.StatusCode, body)
	}

	if _, err := site.sessions.GetAdminSession(context.Background(), id); err != nil {
		t.Errorf("the refused sign-out ended the session: %v", err)
	}
	admin := site.get(t, "/admin")
	if page := readAll(t, admin); admin.StatusCode != http.StatusOK {
		t.Errorf("/admin answered %d after a refused sign-out: %s", admin.StatusCode, page)
	}
}

// ---- The sign-in page ----

func TestSignInPageShowsTheFixedMessageForEachKnownCode(t *testing.T) {
	site := newSignInSite(t)
	for code, want := range map[string]string{
		"not_started": "The sign-in could not be started. Please try again.",
		"failed":      "The sign-in could not be completed. Please try again.",
		"refused":     "The provider did not complete the sign-in.",
	} {
		t.Run(code, func(t *testing.T) {
			resp := site.get(t, "/admin/signin?error="+code)
			page := readAll(t, resp)
			if resp.StatusCode != http.StatusOK || !strings.Contains(page, want) {
				t.Errorf("?error=%s answered %d without %q:\n%s", code, resp.StatusCode, want, page)
			}
		})
	}
}

func TestSignInPageNeverShowsTextFromTheURL(t *testing.T) {
	site := newSignInSite(t)
	for _, text := range []string{"<script>alert(1)</script>", "Your account is locked"} {
		t.Run(text, func(t *testing.T) {
			resp := site.get(t, "/admin/signin?error="+url.QueryEscape(text))
			page := readAll(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("the sign-in page answered %d", resp.StatusCode)
			}
			if strings.Contains(page, text) || strings.Contains(page, html.EscapeString(text)) {
				t.Errorf("the page shows the text from the URL:\n%s", page)
			}
			if strings.Contains(page, `role="alert"`) {
				t.Errorf("the page shows an error message for an unknown code:\n%s", page)
			}
		})
	}
}

func TestSignInPageSendsASignedInAdministratorToAdmin(t *testing.T) {
	site := newSignInSite(t)
	site.signInOK(t)

	resp := site.get(t, "/admin/signin")
	readAll(t, resp)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin" {
		t.Errorf("the sign-in page answered %d → %q for a signed-in administrator, want 303 to /admin",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSignInStartOfAnUnconfiguredProviderIsNotFound(t *testing.T) {
	site := newSignInSite(t)
	resp := site.get(t, "/admin/auth/github/start")
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Unknown provider") {
		t.Errorf("an unconfigured provider answered %d, want 404 \"Unknown provider\": %s", resp.StatusCode, body)
	}
}

// ---- How a sign-in ends ----

func TestProviderRefusalLandsOnSignInWithTheRefusedMessage(t *testing.T) {
	site := newSignInSite(t)
	// A real sign-in, refused by the provider on the way back: the callback
	// carries the real state but an error instead of a code.
	callback, err := url.Parse(site.reachCallback(t))
	if err != nil {
		t.Fatal(err)
	}
	callback.RawQuery = url.Values{
		"error": {"access_denied"},
		"state": {callback.Query().Get("state")},
	}.Encode()
	resp := site.do(t, http.MethodGet, callback.String(), nil, nil)
	readAll(t, resp)

	site.expectSignInPageWith(t, resp, "The provider did not complete the sign-in.")
	site.expectNoSession(t, resp)
}

func TestFailedSignInLandsOnSignInWithTheFailedMessage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		callback func(t *testing.T, site *signInSite) string
	}{
		{"a state Clerk never issued", func(*testing.T, *signInSite) string {
			return "/admin/auth/google/callback?code=some-code&state=not-a-real-state"
		}},
		{"a code the provider refuses", func(t *testing.T, site *signInSite) string {
			// A real sign-in with the real state, but a code the provider
			// never issued, so the exchange fails.
			callback, err := url.Parse(site.reachCallback(t))
			if err != nil {
				t.Fatal(err)
			}
			q := callback.Query()
			q.Set("code", "not-a-code-the-provider-issued")
			return callback.Path + "?" + q.Encode()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newSignInSite(t)
			resp := site.get(t, tc.callback(t, site))
			readAll(t, resp)

			site.expectSignInPageWith(t, resp, "The sign-in could not be completed. Please try again.")
			site.expectNoSession(t, resp)
		})
	}
}

func TestBouncerRefusalIsNotAuthorizedWithoutASession(t *testing.T) {
	site := newSignInSite(t)
	site.bouncer.answer(fmt.Errorf("%w: no admin role", adminauth.ErrForbidden))

	resp := site.signIn(t)
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Not authorized") {
		t.Errorf("a refusal by Bouncer answered %d, want 403 \"Not authorized\": %s", resp.StatusCode, body)
	}
	site.expectNoSession(t, resp)
}

func TestBouncerOutageIsAdministrationUnavailableWithoutASession(t *testing.T) {
	site := newSignInSite(t)
	site.bouncer.answer(fmt.Errorf("%w: connection refused", adminauth.ErrUnavailable))

	resp := site.signIn(t)
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Administration unavailable") {
		t.Errorf("an unreachable Bouncer answered %d, want 503 \"Administration unavailable\": %s", resp.StatusCode, body)
	}
	site.expectNoSession(t, resp)
}

func TestSuccessfulSignInSetsARestrictedSessionCookie(t *testing.T) {
	site := newSignInSite(t)

	resp := site.signIn(t)
	readAll(t, resp)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin" {
		t.Fatalf("a successful sign-in answered %d → %q, want 303 to /admin",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	c := cookieIn(resp, adminauth.SessionCookieName)
	if c == nil || c.Value == "" {
		t.Fatal("a successful sign-in set no session cookie")
	}
	if !c.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("the session cookie's SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/admin" {
		t.Errorf("the session cookie's Path = %q, want /admin", c.Path)
	}

	admin := site.get(t, "/admin")
	if page := readAll(t, admin); admin.StatusCode != http.StatusOK {
		t.Errorf("/admin answered %d after signing in: %s", admin.StatusCode, page)
	}
}
