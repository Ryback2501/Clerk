package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	keep := func(name, value string) {
		// A value a failed step never produced is not kept: that step has
		// already failed the test, and an empty value would match every line.
		if value != "" {
			secrets = append(secrets, namedSecret{name, value})
		}
	}
	// Every stack the test starts logs into the capture. Its signing key is
	// read at once, while the key file exists; its provider's secrets are
	// collected at the scan, so a sign-in made at any point is included.
	var providers []*fakeProvider
	start := func(t *testing.T, opts stackOptions) *stack {
		t.Helper()
		opts.Logger = logs.Logger
		st := startStack(t, opts)
		providers = append(providers, st.Provider)
		for _, part := range signingKeySecrets(t, st.App.cfg.KeysPath) {
			keep(part.name, part.value)
		}
		return st
	}

	// The scan runs however the test ends, after every stack has shut down: a
	// test can stop exactly because something went wrong, and that is when a
	// leak is most likely.
	t.Cleanup(func() {
		for _, p := range providers {
			for _, secret := range p.Secrets() {
				keep(secret.name, secret.value)
			}
		}
		for _, leak := range findSecrets(logs.String(), secrets) {
			t.Errorf("the %s appears in the logs: %s", leak.name, leak.line)
		}
	})
	// step stops the test at the first failing step: the later steps build
	// on it.
	step := func(name string, fn func(*testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}

	keep("Bouncer API key", itBouncerAPIKey)
	keep("sign-in provider client secret", itProviderSecret)
	s := start(t, stackOptions{})

	step("admin session", func(t *testing.T) {
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
	step("sign-in flow", func(t *testing.T) {
		// Kept even when a step fails part-way, for the scan that follows.
		defer func() {
			keep("client secret", flow.client.Secret)
			keep("client credentials as sent in a Basic header", basicCredentials(flow.client.ClientID, flow.client.Secret))
			keep("authorization code", flow.code)
			keep("access token", flow.accessToken)
			keep("ID token", flow.idToken)
		}()
		flow.run(t)
	})

	step("refusals", func(t *testing.T) {
		const wrongSecret = "wrong-client-secret-for-the-log-check"
		keep("wrong client secret", wrongSecret)
		keep("wrong client credentials as sent in a Basic header", basicCredentials(flow.client.ClientID, wrongSecret))
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

	step("wrong Bouncer API key", func(t *testing.T) {
		const wrongKey = "bncr_wrong-key-for-the-log-check"
		keep("wrong Bouncer API key", wrongKey)
		other := start(t, stackOptions{BouncerAPIKey: wrongKey})

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
	// The scan itself runs in the cleanup registered above.
}

// signingKeySecrets returns the forms the signing key could leak in: each
// base64 line of its PEM file, and each private part of the key (the private
// exponent, the primes and the CRT values) in base64url, as a JWK carries
// them, and in decimal, as printing the key with %v does.
func signingKeySecrets(t *testing.T, path string) []namedSecret {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read the signing key: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("the signing key file is not PEM")
	}

	var secrets []namedSecret
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "-----") {
			n++
			secrets = append(secrets, namedSecret{fmt.Sprintf("signing private key (line %d of the key file)", n), line})
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if err8 != nil || !ok {
			t.Fatalf("the signing key is not an RSA key: %v / %v", err, err8)
		}
		key = rsaKey
	}
	key.Precompute()
	parts := map[string]*big.Int{
		"private exponent": key.D,
		"first prime":      key.Primes[0],
		"second prime":     key.Primes[1],
		"CRT exponent dp":  key.Precomputed.Dp,
		"CRT exponent dq":  key.Precomputed.Dq,
		"CRT coefficient":  key.Precomputed.Qinv,
	}
	for name, v := range parts {
		secrets = append(secrets,
			namedSecret{"signing key " + name + " (base64url)", base64.RawURLEncoding.EncodeToString(v.Bytes())},
			namedSecret{"signing key " + name + " (decimal)", v.String()})
	}
	return secrets
}

// basicCredentials is the value of an Authorization: Basic header for these
// client credentials, each part form-encoded first (RFC 6749 §2.3.1): a
// logged header would carry the secret only in this encoded form.
func basicCredentials(id, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id) + ":" + url.QueryEscape(secret)))
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
	id := s.adminSessionValue(t)
	if id == "" {
		t.Fatal("the client holds no admin session cookie")
	}
	return id
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

// exchange presents the flow's code with the given client secret and
// returns the status.
func (f *oidcFlow) exchange(t *testing.T, secret string) int {
	t.Helper()
	resp := f.postToken(t, secret)
	_ = readBody(t, resp)
	return resp.StatusCode
}
