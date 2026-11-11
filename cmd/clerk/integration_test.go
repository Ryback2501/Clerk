package main

import (
	"net/http"
	"strings"
	"testing"
)

// A third-party application signs a user in through the whole server, from
// discovery to userinfo, and the ID token verifies against the published keys.
// Each step is its own sub-test, so -v lists them.
func TestSignInFlowIntegration(t *testing.T) {
	skipUnlessIntegration(t)
	s := startStack(t, stackOptions{})
	flow := s.newFlow(t)

	for _, step := range flow.steps() {
		if !t.Run(step.name, step.fn) {
			t.Fatalf("stopped: the %s step failed", step.name)
		}
	}
}

// The stand-ins work: with Bouncer reachable, the stand-in administrator signs
// in to the admin interface. This is what makes the 503 below mean "Bouncer is
// down" rather than "the test setup is broken".
func TestAdminSignInIntegration(t *testing.T) {
	skipUnlessIntegration(t)
	s := startStack(t, stackOptions{})

	resp := s.adminSignIn(t)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin" {
		t.Fatalf("the admin sign-in answered %d → %q, want a redirect to /admin: %s",
			resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if !s.hasAdminSession(t) {
		t.Fatal("the admin sign-in set no session cookie")
	}

	admin := s.get(t, s.URL+"/admin", nil)
	if page := readBody(t, admin); admin.StatusCode != http.StatusOK {
		t.Fatalf("/admin answered %d after signing in: %s", admin.StatusCode, page)
	}
}

// A Bouncer outage closes administration and nothing else: signing in to the
// admin interface answers 503 without a session, while a third-party
// application still signs its users in and gets valid tokens.
func TestBouncerDownIntegration(t *testing.T) {
	skipUnlessIntegration(t)
	s := startStack(t, stackOptions{BouncerDown: true})

	t.Run("admin sign-in answers 503", func(t *testing.T) {
		resp := s.adminSignIn(t)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("the admin sign-in answered %d, want 503: %s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "Administration unavailable") {
			t.Errorf("the page does not say administration is unavailable:\n%s", body)
		}
		if s.hasAdminSession(t) {
			t.Error("a session cookie was set although Bouncer could not be asked")
		}
	})

	t.Run("the sign-in flow still works", func(t *testing.T) {
		s.newFlow(t).run(t)
	})
}
