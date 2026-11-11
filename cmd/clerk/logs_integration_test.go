package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/adminauth"
)

// Clerk must never write a secret to its logs: client secrets, authorization
// codes, access and ID tokens, the admin session cookie, the Bouncer API key,
// the sign-in providers' client secrets or the signing key. This test runs a
// whole admin session and a whole sign-in flow, refusals included, records
// everything logged at every level, and fails if any of those values appears.
func TestNoSecretInLogsIntegration(t *testing.T) {
	skipUnlessIntegration(t)
	logs := captureLogs(t)
	var secrets []namedSecret
	keep := func(name, value string) { secrets = append(secrets, namedSecret{name, value}) }

	s := startStack(t, stackOptions{Logger: logs.Logger})
	keep("Bouncer API key", itBouncerAPIKey)
	keep("sign-in provider client secret", itProviderSecret)
	for i, line := range signingKeyLines(t, s.App.cfg.KeysPath) {
		keep(fmt.Sprintf("signing private key (line %d of the key file)", i+1), line)
	}

	t.Run("admin session", func(t *testing.T) {
		if resp := s.adminSignIn(t); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("admin sign-in answered %d: %s", resp.StatusCode, readBody(t, resp))
		}
		keep("admin session cookie", s.adminSessionID(t))
		csrf := s.adminCSRF(t)

		created := s.adminPost(t, "/admin/applications", csrf, url.Values{"name": {"Log check"}})
		page := readBody(t, created)
		if created.StatusCode != http.StatusCreated {
			t.Fatalf("creating an application answered %d: %s", created.StatusCode, page)
		}
		keep("new client secret", revealedSecret(t, page))
		appID := created.Header.Get("X-Clerk-Application")

		regenerated := s.adminPost(t, "/admin/applications/"+appID+"/secret", csrf, nil)
		page = readBody(t, regenerated)
		if regenerated.StatusCode != http.StatusOK {
			t.Fatalf("regenerating the secret answered %d: %s", regenerated.StatusCode, page)
		}
		keep("regenerated client secret", revealedSecret(t, page))

		user := s.adminPost(t, "/admin/applications/"+appID+"/users", csrf, url.Values{"username": {"Log Tester"}})
		if page := readBody(t, user); user.StatusCode != http.StatusOK {
			t.Fatalf("adding a test user answered %d: %s", user.StatusCode, page)
		}

		out := s.postForm(t, s.URL+"/admin/signout", url.Values{"csrf_token": {csrf}}, nil)
		if page := readBody(t, out); out.StatusCode != http.StatusSeeOther {
			t.Fatalf("signing out answered %d: %s", out.StatusCode, page)
		}
	})

	flow := s.newFlow(t)
	t.Run("sign-in flow", func(t *testing.T) {
		flow.run(t)
		keep("client secret", flow.client.Secret)
		keep("authorization code", flow.code)
		keep("access token", flow.accessToken)
		keep("ID token", flow.idToken)
	})

	t.Run("refusals", func(t *testing.T) {
		const wrongSecret = "wrong-client-secret-for-the-log-check"
		keep("wrong client secret", wrongSecret)
		if status := flow.exchange(t, wrongSecret); status != http.StatusUnauthorized {
			t.Errorf("a wrong client secret answered %d, want 401", status)
		}
		if status := flow.exchange(t, flow.client.Secret); status != http.StatusBadRequest {
			t.Errorf("a replayed code answered %d, want 400", status)
		}

		const madeUpToken = "made-up-access-token-for-the-log-check"
		keep("made-up access token", madeUpToken)
		// The replay revoked the real token, so both are invalid now.
		for _, token := range []string{madeUpToken, flow.accessToken} {
			resp := s.get(t, s.URL+"/userinfo", func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+token)
			})
			if body := readBody(t, resp); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("userinfo with an invalid token answered %d: %s", resp.StatusCode, body)
			}
		}
	})

	t.Run("wrong Bouncer API key", func(t *testing.T) {
		const wrongKey = "bncr_wrong-key-for-the-log-check"
		keep("wrong Bouncer API key", wrongKey)
		other := startStack(t, stackOptions{Logger: logs.Logger, BouncerAPIKey: wrongKey})

		resp := other.adminSignIn(t)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Administration unavailable") {
			t.Errorf("signing in with a wrong Bouncer key answered %d, want 503 \"Administration unavailable\": %s",
				resp.StatusCode, body)
		}
	})

	recorded := logs.String()
	if !strings.Contains(recorded, "administrator signed in") {
		t.Fatalf("the log capture recorded nothing from Clerk:\n%s", recorded)
	}
	for _, leak := range findSecrets(recorded, secrets) {
		t.Errorf("the %s appears in the logs: %s", leak.name, leak.line)
	}
}

// signingKeyLines returns the base64 lines of the signing key file. Any one of
// them in a log would be part of the private key.
func signingKeyLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read the signing key: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("the signing key file is not PEM")
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "-----") {
			lines = append(lines, line)
		}
	}
	return lines
}

// revealedSecret reads the client secret from the one-time dialog in a page.
func revealedSecret(t *testing.T, page string) string {
	t.Helper()
	m := secretInDialog.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the page shows no client secret:\n%s", page)
	}
	return m[1]
}

var secretInDialog = regexp.MustCompile(`<code class="value secret">([^<]+)</code>`)

// adminSessionID is the value of the admin session cookie the client holds.
func (s *stack) adminSessionID(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(s.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Client.Jar.Cookies(u) {
		if c.Name == adminauth.SessionCookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("the client holds no admin session cookie")
	return ""
}

// adminCSRF opens the admin page and returns the CSRF token its forms carry.
func (s *stack) adminCSRF(t *testing.T) string {
	t.Helper()
	resp := s.get(t, s.URL+"/admin", nil)
	page := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin answered %d: %s", resp.StatusCode, page)
	}
	return hiddenField(t, page, "csrf_token")
}

// adminPost sends a form to an admin route the way the admin script does.
func (s *stack) adminPost(t *testing.T, path, csrf string, form url.Values) *http.Response {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", csrf)
	return s.postForm(t, s.URL+path, form, func(req *http.Request) {
		req.Header.Set("X-Clerk-Fragment", "1")
	})
}

// exchange presents the flow's code at the token endpoint with the given
// client secret, and returns the status.
func (f *oidcFlow) exchange(t *testing.T, secret string) int {
	t.Helper()
	resp := f.s.postForm(t, f.endpoint(t, "token_endpoint"), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {f.code},
		"redirect_uri": {f.client.RedirectURI},
	}, func(req *http.Request) {
		req.SetBasicAuth(url.QueryEscape(f.client.ClientID), url.QueryEscape(secret))
	})
	_ = readBody(t, resp)
	return resp.StatusCode
}
