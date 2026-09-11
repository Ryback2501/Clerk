package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/keys"
	"github.com/Ryback2501/Clerk/internal/store"
	"github.com/Ryback2501/Clerk/internal/web"
)

type flow struct {
	t        *testing.T
	mux      *http.ServeMux
	store    *store.Store
	app      *store.Application
	user     *store.User
	jar      map[string]string
	basePath string
	secret   string
	signer   *keys.Signer
}

const testRedirect = "https://app.example.com/cb"

func newFlow(t *testing.T) *flow { return newFlowWithIssuer(t, "https://idp.example.com") }

func newFlowWithIssuer(t *testing.T, issuerURL string) *flow {
	return newFlowWith(t, issuerURL, nil)
}

// newFlowWith builds a flow, letting a test adjust the provider options.
func newFlowWith(t *testing.T, issuerURL string, configure func(*Options)) *flow {
	t.Helper()
	dir := t.TempDir()

	s, err := store.Open(filepath.Join(dir, "clerk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	signer, err := keys.LoadOrGenerate(filepath.Join(dir, "signing.pem"))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := url.Parse(issuerURL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{Issuer: issuer, Signer: signer, Store: s}
	if configure != nil {
		configure(&opts)
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	app, appSecret, err := s.CreateApplication(context.Background(), "My Test Application",
		[]string{testRedirect, "https://app.example.com/other"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.CreateUser(context.Background(), app.ID, "david")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	p.Register(mux)
	return &flow{
		t: t, mux: mux, store: s, app: app, user: user,
		jar:      map[string]string{},
		basePath: strings.TrimRight(issuer.Path, "/"),
		secret:   appSecret,
		signer:   signer,
	}
}

func (f *flow) do(req *http.Request) *httptest.ResponseRecorder {
	f.t.Helper()
	for n, v := range f.jar {
		req.AddCookie(&http.Cookie{Name: n, Value: v})
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(f.jar, c.Name)
			continue
		}
		f.jar[c.Name] = c.Value
	}
	return rec
}

// authorize issues a GET /authorize with the given parameters, filling in
// valid defaults for anything not overridden.
func (f *flow) authorize(overrides map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	q := url.Values{
		"client_id":     {f.app.ClientID},
		"redirect_uri":  {testRedirect},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"client-state-value"},
		"nonce":         {"client-nonce-value"},
	}
	for k, v := range overrides {
		if v == "" {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	return f.do(httptest.NewRequest(http.MethodGet, f.basePath+AuthorizePath+"?"+q.Encode(), nil))
}

var (
	requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	csrfPattern      = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	userValuePattern = regexp.MustCompile(`<option value="(\d+)"`)
)

// login submits the rendered login form.
func (f *flow) login(page string, userID string) *httptest.ResponseRecorder {
	f.t.Helper()

	reqID := requestIDPattern.FindStringSubmatch(page)
	token := csrfPattern.FindStringSubmatch(page)
	if reqID == nil || token == nil {
		f.t.Fatal("the login page is missing the request id or the CSRF token")
	}

	form := url.Values{
		"request_id":      {reqID[1]},
		web.CSRFFieldName: {token[1]},
		"user_id":         {userID},
	}
	req := httptest.NewRequest(http.MethodPost, formAction(f.t, page), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(req)
}

// --- Requests that must NOT redirect ---------------------------------------

// RFC 6749 §4.1.2.1: when the client or the redirect URI cannot be trusted,
// the provider must not send anything to that URI — doing so would turn the
// provider into an open redirector and leak errors to an attacker's endpoint.
func TestUntrustworthyRequestsAreNotRedirected(t *testing.T) {
	f := newFlow(t)

	tests := []struct {
		name      string
		overrides map[string]string
	}{
		{"unknown client", map[string]string{"client_id": "no-such-client"}},
		{"missing client", map[string]string{"client_id": ""}},
		{"missing redirect uri", map[string]string{"redirect_uri": ""}},
		{"unregistered redirect uri", map[string]string{"redirect_uri": "https://evil.example.com/cb"}},
		{"redirect uri differing by path", map[string]string{"redirect_uri": "https://app.example.com/cb2"}},
		{"redirect uri differing by trailing slash", map[string]string{"redirect_uri": testRedirect + "/"}},
		{"redirect uri differing by scheme", map[string]string{"redirect_uri": "http://app.example.com/cb"}},
		{"redirect uri differing by case of host", map[string]string{"redirect_uri": "https://APP.example.com/cb"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.authorize(tt.overrides)

			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("the provider redirected to %q instead of refusing", loc)
			}
			if rec.Code == http.StatusOK {
				t.Errorf("status = 200; an invalid request should not render as success")
			}
			if rec.Code < 400 || rec.Code >= 500 {
				t.Errorf("status = %d, want a 4xx", rec.Code)
			}
			// The page must explain the problem without echoing an attacker's URI.
			if strings.Contains(rec.Body.String(), "evil.example.com") {
				t.Error("the error page reflects the attacker-supplied redirect URI")
			}
		})
	}
}

// --- Requests that must redirect with an error -----------------------------

// Once the client and redirect URI are trusted, remaining errors go back to
// the client so it can react, carrying state so it can match the response.
func TestInvalidRequestsRedirectWithAnError(t *testing.T) {
	f := newFlow(t)

	tests := []struct {
		name      string
		overrides map[string]string
		wantError string
	}{
		{"missing response type", map[string]string{"response_type": ""}, "invalid_request"},
		{"implicit flow", map[string]string{"response_type": "token"}, "unsupported_response_type"},
		{"hybrid flow", map[string]string{"response_type": "code id_token"}, "unsupported_response_type"},
		{"missing scope", map[string]string{"scope": ""}, "invalid_scope"},
		{"scope without openid", map[string]string{"scope": "profile"}, "invalid_scope"},
		{"unsupported pkce method", map[string]string{"code_challenge": "abc", "code_challenge_method": "plain"}, "invalid_request"},
		{"pkce challenge without a method", map[string]string{"code_challenge": "abc"}, "invalid_request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.authorize(tt.overrides)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 back to the client: %s", rec.Code, rec.Body.String())
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testRedirect {
				t.Errorf("redirected to %q, want the registered URI", got)
			}
			q := loc.Query()
			if got := q.Get("error"); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
			if got := q.Get("state"); got != "client-state-value" {
				t.Errorf("state = %q, want it echoed back unchanged", got)
			}
			// An error response must never carry a code.
			if q.Get("code") != "" {
				t.Error("an error response carried an authorization code")
			}
		})
	}
}

// --- The happy path --------------------------------------------------------

func TestAuthorizeRendersTheLoginPage(t *testing.T) {
	f := newFlow(t)
	rec := f.authorize(nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	if !strings.Contains(body, "My Test Application") {
		t.Error("the login page does not name the requesting application")
	}
	if !strings.Contains(body, "david") {
		t.Error("the application's test user is not offered")
	}
	// §8: no consent screen, no password, no email.
	for _, forbidden := range []string{"type=\"password\"", "consent", "Consent", "email"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the login page contains %q, which §8 rules out", forbidden)
		}
	}
	if requestIDPattern.FindStringSubmatch(body) == nil {
		t.Error("the form does not carry the server-side request handle")
	}
}

// §8: only the requesting application's identities may be offered.
func TestLoginPageOffersOnlyTheApplicationsOwnUsers(t *testing.T) {
	f := newFlow(t)

	other, _, err := f.store.CreateApplication(context.Background(), "Other", []string{"https://other.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateUser(context.Background(), other.ID, "someone-else"); err != nil {
		t.Fatal(err)
	}

	body := f.authorize(nil).Body.String()
	if strings.Contains(body, "someone-else") {
		t.Error("another application's user is offered on this login page")
	}
}

// §8: an application with no identities gets a clear page, not a broken form.
func TestApplicationWithNoUsersGetsAnExplanation(t *testing.T) {
	f := newFlow(t)

	empty, _, err := f.store.CreateApplication(context.Background(), "Empty", []string{"https://empty.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}

	rec := f.authorize(map[string]string{
		"client_id":    empty.ClientID,
		"redirect_uri": "https://empty.example.com/cb",
	})
	body := rec.Body.String()
	if !strings.Contains(strings.ToLower(body), "no test users") {
		t.Errorf("the page does not explain that the application has no users: %s", body)
	}
	if requestIDPattern.FindStringSubmatch(body) != nil {
		t.Error("a login form was rendered for an application with nobody to sign in as")
	}
}

func TestCompleteAuthorizationIssuesACode(t *testing.T) {
	f := newFlow(t)
	page := f.authorize(nil).Body.String()

	users := userValuePattern.FindStringSubmatch(page)
	if users == nil {
		t.Fatal("the login form offers no selectable user")
	}

	rec := f.login(page, users[1])
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testRedirect {
		t.Errorf("redirected to %q, want the registered URI", got)
	}

	q := loc.Query()
	code := q.Get("code")
	if code == "" {
		t.Fatal("no authorization code was issued")
	}
	if len(code) < 40 {
		t.Errorf("authorization code %q carries too little entropy", code)
	}
	if got := q.Get("state"); got != "client-state-value" {
		t.Errorf("state = %q, want it echoed back unchanged", got)
	}

	// The code must resolve to the selected identity, bound to this client.
	stored, err := f.store.ConsumeAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("the issued code is not usable: %v", err)
	}
	if stored.UserID != f.user.ID {
		t.Errorf("the code resolves to user %d, want %d", stored.UserID, f.user.ID)
	}
	if stored.ApplicationID != f.app.ID {
		t.Errorf("the code is bound to application %d, want %d", stored.ApplicationID, f.app.ID)
	}
	if stored.Nonce != "client-nonce-value" {
		t.Errorf("nonce = %q, want it carried through to the code", stored.Nonce)
	}
}

func TestPKCEChallengeIsCarriedToTheCode(t *testing.T) {
	f := newFlow(t)
	page := f.authorize(map[string]string{
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
	}).Body.String()

	users := userValuePattern.FindStringSubmatch(page)
	rec := f.login(page, users[1])
	code := mustCode(t, rec)

	stored, err := f.store.ConsumeAuthCode(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("code_challenge = %q, want it preserved for the token endpoint", stored.CodeChallenge)
	}
	if stored.CodeChallengeMethod != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", stored.CodeChallengeMethod)
	}
}

// --- Login submission hardening --------------------------------------------

func TestLoginRejectsAForgedRequest(t *testing.T) {
	f := newFlow(t)
	page := f.authorize(nil).Body.String()
	users := userValuePattern.FindStringSubmatch(page)

	t.Run("without a CSRF token", func(t *testing.T) {
		reqID := requestIDPattern.FindStringSubmatch(page)
		form := url.Values{"request_id": {reqID[1]}, "user_id": {users[1]}}
		req := httptest.NewRequest(http.MethodPost, AuthorizePath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusFound {
			t.Error("a login without a CSRF token completed")
		}
	})

	t.Run("with an unknown request handle", func(t *testing.T) {
		forged := strings.Replace(page, requestIDPattern.FindStringSubmatch(page)[1], "not-a-real-request", 1)
		if rec := f.login(forged, users[1]); rec.Code == http.StatusFound {
			t.Error("a login with a fabricated request handle completed")
		}
	})
}

// The handle is consumed on use, so one rendered form cannot mint two codes.
func TestLoginFormCannotBeSubmittedTwice(t *testing.T) {
	f := newFlow(t)
	page := f.authorize(nil).Body.String()
	users := userValuePattern.FindStringSubmatch(page)

	if rec := f.login(page, users[1]); rec.Code != http.StatusFound {
		t.Fatalf("the first submission failed: %d", rec.Code)
	}
	if rec := f.login(page, users[1]); rec.Code == http.StatusFound {
		t.Error("the same login form produced a second authorization code")
	}
}

// Selecting an identity that belongs to another application must fail, or the
// form could be used to sign in as anyone in the provider.
func TestLoginRejectsAUserFromAnotherApplication(t *testing.T) {
	f := newFlow(t)

	other, _, err := f.store.CreateApplication(context.Background(), "Other", []string{"https://other.example.com/cb"})
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := f.store.CreateUser(context.Background(), other.ID, "outsider")
	if err != nil {
		t.Fatal(err)
	}

	page := f.authorize(nil).Body.String()
	rec := f.login(page, itoa(outsider.ID))
	if rec.Code == http.StatusFound {
		t.Fatal("signed in as a user belonging to a different application")
	}
}

func mustCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", rec.Header().Get("Location"))
	}
	return code
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// §2 asks for interoperability with standard clients. Many send scopes this
// provider does not implement (email, offline_access) as a matter of course.
// Rejecting the whole request would break them for no benefit; RFC 6749 §3.3
// allows granting a subset, provided the client is told what it actually got.
func TestUnsupportedScopesAreIgnoredRatherThanRejected(t *testing.T) {
	f := newFlow(t)

	rec := f.authorize(map[string]string{"scope": "openid profile email offline_access"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a request with extra scopes was rejected: %d %s", rec.Code, rec.Body.String())
	}

	page := rec.Body.String()
	users := userValuePattern.FindStringSubmatch(page)
	code := mustCode(t, f.login(page, users[1]))

	stored, err := f.store.ConsumeAuthCode(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	// Only what is actually supported may be granted.
	if stored.Scope != "openid profile" {
		t.Errorf("granted scope = %q, want only the supported subset", stored.Scope)
	}
}

// Dropping openid is different: without it this is not an OpenID Connect
// request at all, and no ID token could be issued.
func TestScopeWithoutOpenIDIsStillRejected(t *testing.T) {
	f := newFlow(t)
	rec := f.authorize(map[string]string{"scope": "profile email"})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want a redirect carrying an error", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("error"); got != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", got)
	}
}

var actionPattern = regexp.MustCompile(`<form method="post" action="([^"]+)"`)

// formAction returns where the rendered login page actually posts to. Tests
// must follow the page rather than assume a path, or a form pointing at an
// unregistered route would go unnoticed.
func formAction(t *testing.T, page string) string {
	t.Helper()
	m := actionPattern.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the login page has no form action")
	}
	return m[1]
}

// The provider mounts its endpoints under the issuer's path, so a login form
// that posts to a hardcoded /authorize is unreachable in exactly the
// deployment the discovery document advertises — nobody could ever sign in.
func TestLoginWorksWhenTheIssuerHasAPathPrefix(t *testing.T) {
	f := newFlowWithIssuer(t, "https://example.com/oidc")

	rec := f.authorize(nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /oidc/authorize = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()

	if got := formAction(t, page); got != "/oidc"+AuthorizePath {
		t.Errorf("form posts to %q, want it under the issuer path", got)
	}

	users := userValuePattern.FindStringSubmatch(page)
	if users == nil {
		t.Fatal("no selectable user")
	}
	login := f.login(page, users[1])
	if login.Code != http.StatusFound {
		t.Fatalf("login under a path-prefixed issuer returned %d, want 302: %s", login.Code, login.Body.String())
	}
	if code := mustCode(t, login); code == "" {
		t.Error("no authorization code was issued")
	}
}

// The stylesheet must be reachable from the login page under the same prefix,
// or a proxy forwarding only the issuer path serves an unstyled page.
func TestLoginPageStylesheetIsUnderTheIssuerPath(t *testing.T) {
	f := newFlowWithIssuer(t, "https://example.com/oidc")
	page := f.authorize(nil).Body.String()

	m := regexp.MustCompile(`<link rel="stylesheet" href="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the login page links no stylesheet")
	}
	if !strings.HasPrefix(m[1], "/oidc/") {
		t.Errorf("stylesheet href = %q, want it under the issuer path", m[1])
	}

	rec := f.do(httptest.NewRequest(http.MethodGet, m[1], nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want the stylesheet to be served", m[1], rec.Code)
	}
}

// A database failure is not the same as someone tampering with the form: one
// is a server fault, the other a security event. Conflating them logs a false
// security warning and tells the user something untrue.
func TestStoreFailureDuringLoginIsNotReportedAsTampering(t *testing.T) {
	f := newFlow(t)
	page := f.authorize(nil).Body.String()
	users := userValuePattern.FindStringSubmatch(page)

	// Closing the database makes the user lookup fail for infrastructure
	// reasons rather than because the selection was wrong.
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}

	rec := f.login(page, users[1])
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a store failure", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "does not belong to the application") {
		t.Error("a database failure was reported to the user as an invalid selection")
	}
}

// The method is part of each registered pattern; losing it would let the
// wrong handler serve a route.
func TestAuthorizeRoutesAreMethodScoped(t *testing.T) {
	f := newFlow(t)

	// POST to /authorize without a form must not reach the GET handler.
	req := httptest.NewRequest(http.MethodPost, AuthorizePath, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(req); rec.Code == http.StatusOK {
		t.Error("a bare POST rendered a page; it should have failed CSRF validation")
	}

	for _, method := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		if rec := f.do(httptest.NewRequest(method, AuthorizePath, nil)); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /authorize = %d, want 405", method, rec.Code)
		}
	}
}
