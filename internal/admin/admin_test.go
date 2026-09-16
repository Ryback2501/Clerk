package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
	"github.com/Ryback2501/Clerk/internal/web"
)

// fakeAdmin authenticates every request as one fixed administrator. It exists
// only in tests, so the handlers can be exercised without an OAuth round trip;
// the shipped handler is always built with real sign-in.
type fakeAdmin struct{}

func (fakeAdmin) Authenticate(*http.Request) (*adminauth.Admin, error) {
	return &adminauth.Admin{Subject: "test-admin", Provider: "test", Name: "Test administrator"}, nil
}

// refusingAdmin fails every authentication with a fixed error.
type refusingAdmin struct{ err error }

func (a refusingAdmin) Authenticate(*http.Request) (*adminauth.Admin, error) { return nil, a.err }

type harness struct {
	t     *testing.T
	mux   *http.ServeMux
	store *store.Store

	// jar emulates browser cookie semantics: setting a name replaces any
	// previous value, and a negative MaxAge deletes it. Appending blindly
	// instead would let a stale cookie shadow a newer one of the same name.
	jar map[string]string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, fakeAdmin{})
}

func newHarnessWith(t *testing.T, auth adminauth.Authenticator) *harness {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "clerk.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := newHandler(s, auth, nil)
	if err != nil {
		t.Fatalf("newHandler(): %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return &harness{t: t, mux: mux, store: s, jar: map[string]string{}}
}

func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	h.t.Helper()
	for name, value := range h.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(h.jar, c.Name)
			continue
		}
		h.jar[c.Name] = c.Value
	}
	return rec
}

// page requests a full page, the way a browser navigation does.
func (h *harness) page(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(httptest.NewRequest(http.MethodGet, path, nil))
}

// get requests a fragment, the way the admin script does.
func (h *harness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(fragmentHeader, "1")
	return h.do(req)
}

// post submits a form as the admin script does, first fetching the shell to
// pick up a valid CSRF token.
func (h *harness) post(path string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	form.Set(web.CSRFFieldName, h.csrfToken())
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(fragmentHeader, "1")
	return h.do(req)
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (h *harness) csrfToken() string {
	h.t.Helper()
	body := h.page("/admin").Body.String()
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("no CSRF token found in the shell")
	}
	return m[1]
}

// createApp registers an application and optionally adds redirect URIs to it,
// returning its id and the secret shown in the creation response.
func (h *harness) createApp(name string, uris ...string) int64 {
	h.t.Helper()
	id, _ := h.createAppWithSecret(name, uris...)
	return id
}

func (h *harness) createAppWithSecret(name string, uris ...string) (int64, string) {
	h.t.Helper()
	rec := h.post("/admin/applications", url.Values{"name": {name}})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	id, err := strconv.ParseInt(rec.Header().Get(createdHeader), 10, 64)
	if err != nil {
		h.t.Fatalf("create response carries no usable %s header: %v", createdHeader, err)
	}
	for _, uri := range uris {
		if got := h.post(appPath(id)+"/redirect-uris", url.Values{"uri": {uri}}); got.Code != http.StatusOK {
			h.t.Fatalf("add redirect uri returned %d: %s", got.Code, got.Body.String())
		}
	}
	return id, extractSecret(h.t, rec.Body.String())
}

var secretPattern = regexp.MustCompile(`<code class="value secret">([A-Za-z0-9_-]{40,})</code>`)

// extractSecret returns the secret shown in a response, which may only ever be
// inside the one-time dialog.
func extractSecret(t *testing.T, body string) string {
	t.Helper()
	dialog := secretDialog(body)
	if dialog == "" {
		return ""
	}
	m := secretPattern.FindStringSubmatch(dialog)
	if m == nil {
		return ""
	}
	if outside := secretPattern.FindStringSubmatch(strings.Replace(body, dialog, "", 1)); outside != nil {
		t.Errorf("a secret is rendered outside the one-time dialog: %s", outside[1])
	}
	return m[1]
}

// secretDialog returns the one-time secret dialog's markup, or "" if the
// response carries none.
func secretDialog(body string) string {
	start := strings.Index(body, "<dialog data-secret")
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], "</dialog>")
	if end < 0 {
		return ""
	}
	return body[start : start+end+len("</dialog>")]
}

func appPath(id int64) string { return "/admin/applications/" + itoa(id) }

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func seedUsers(t *testing.T, h *harness, appID int64, n int) {
	t.Helper()
	for i := range n {
		if _, err := h.store.DB().Exec(
			`INSERT INTO users (application_id, username, sub) VALUES (?, ?, ?)`,
			appID, "user"+itoa(int64(i)), "sub-"+itoa(appID)+"-"+itoa(int64(i))); err != nil {
			t.Fatal(err)
		}
	}
}

// The shell is the only page. Everything about applications arrives later, on
// demand, so the page itself must carry none of it.
func TestShellCarriesNoApplicationData(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Shell Test Application", "https://shell.example.com/cb")

	rec := h.page("/admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`id="applications"`, `<dialog id="register"`, "/static/admin.js", "/static/admin.css", "Register application"} {
		if !strings.Contains(body, want) {
			t.Errorf("the shell does not contain %q", want)
		}
	}
	for _, leak := range []string{"Shell Test Application", "https://shell.example.com/cb", `data-app="` + itoa(id) + `"`} {
		if strings.Contains(body, leak) {
			t.Errorf("the shell already contains application data %q", leak)
		}
	}
}

// The register button sits below the list, not above it.
func TestRegisterButtonFollowsTheList(t *testing.T) {
	h := newHarness(t)
	body := h.page("/admin").Body.String()

	list := strings.Index(body, `id="applications"`)
	button := strings.Index(body, `commandfor="register"`)
	if list < 0 || button < 0 {
		t.Fatalf("list at %d, register button at %d; both must be present", list, button)
	}
	if button < list {
		t.Error("the Register application button is placed above the list")
	}
}

func TestShellSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	rec := h.page("/admin")

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "style-src 'self'", "font-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP %q allows inline code", csp)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// Pico guarded its dark palette with :root:not([data-theme]), and the admin
// stylesheet follows the same convention, so emitting any data-theme value at
// all would pin the UI to light mode regardless of the reader's preference.
func TestPageDoesNotPinTheColourTheme(t *testing.T) {
	h := newHarness(t)
	if strings.Contains(h.page("/admin").Body.String(), "data-theme") {
		t.Error("the page sets data-theme, which disables automatic dark mode")
	}
}

func TestAdminTrailingSlashReachesTheInterface(t *testing.T) {
	h := newHarness(t)
	rec := h.page("/admin/")
	if rec.Code != http.StatusOK && rec.Code != http.StatusMovedPermanently {
		t.Errorf("GET /admin/ = %d, want the interface or a redirect to it", rec.Code)
	}
}

func TestListRendersEmptyState(t *testing.T) {
	h := newHarness(t)

	rec := h.get("/admin/applications")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/applications = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No applications yet") {
		t.Error("the empty state is not shown")
	}
}

// The list carries only what a folded application shows. An application's
// inner data is requested when it is unfolded, never in advance.
func TestListCarriesSummariesButNoInnerData(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Listed Application", "https://listed.example.com/cb")
	seedUsers(t, h, id, 2)
	app, _ := h.store.GetApplication(context.Background(), id)

	body := h.get("/admin/applications").Body.String()
	for _, want := range []string{"Listed Application", `data-app="` + itoa(id) + `"`, `data-user-count="2"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the list does not contain %q", want)
		}
	}
	// A folded row is the name and how many test users it has. The client id
	// belongs in Credentials, and the registration date is of no use there.
	for _, inner := range []string{app.ClientID, app.CreatedAt, "https://listed.example.com/cb", "user0", "sub-" + itoa(id) + "-0", "Danger zone"} {
		if strings.Contains(body, inner) {
			t.Errorf("the list already contains inner data %q", inner)
		}
	}
	if strings.Contains(body, "<details open") || strings.Contains(body, " open>") {
		t.Error("an application is rendered unfolded in the list")
	}
}

func TestPanelCarriesTheApplicationsInnerData(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Panel Application", "https://panel.example.com/cb")
	seedUsers(t, h, id, 1)
	app, _ := h.store.GetApplication(context.Background(), id)

	rec := h.get(appPath(id))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", appPath(id), rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Credentials", "Redirect URIs", "Test users", "Danger zone",
		app.ClientID, "https://panel.example.com/cb", "user0", "sub-" + itoa(id) + "-0",
		`data-user-count="1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the panel does not contain %q", want)
		}
	}
	if strings.Contains(body, "<html") {
		t.Error("a fragment was wrapped in the page layout")
	}
}

// A fragment is meaningless as a page. Someone who opens its URL directly is
// sent to the interface, and a form posted without the script changes nothing.
func TestFragmentRoutesAnswerOnlyTheAdminScript(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App")

	for _, path := range []string{"/admin/applications", appPath(id)} {
		rec := h.page(path)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin" {
			t.Errorf("a browser visit to %s = %d → %q, want 303 → /admin", path, rec.Code, rec.Header().Get("Location"))
		}
	}

	form := url.Values{"name": {"Posted without the script"}, web.CSRFFieldName: {h.csrfToken()}}
	req := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := h.do(req); rec.Code != http.StatusSeeOther {
		t.Errorf("a plain form post = %d, want 303", rec.Code)
	}
	apps, _ := h.store.ListApplications(context.Background())
	if len(apps) != 1 {
		t.Errorf("a plain form post created an application: %d exist, want 1", len(apps))
	}
}

// The script cannot follow a redirect to a sign-in page and render it as a
// fragment, so fragment requests learn about authorization as status codes.
func TestFragmentAuthorizationFailuresAreStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
		text string
	}{
		{adminauth.ErrUnauthenticated, http.StatusUnauthorized, "sign in"},
		{adminauth.ErrForbidden, http.StatusForbidden, "role"},
		{fmt.Errorf("%w: bouncer down", adminauth.ErrUnavailable), http.StatusServiceUnavailable, "OpenID Connect endpoints are unaffected"},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			h := newHarnessWith(t, refusingAdmin{err: tc.err})
			rec := h.get("/admin/applications")
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
			body := rec.Body.String()
			if strings.Contains(body, "<html") {
				t.Error("the failure was rendered as a whole page instead of a fragment")
			}
			if !strings.Contains(body, tc.text) {
				t.Errorf("the failure does not mention %q: %s", tc.text, body)
			}
		})
	}
}

// Acceptance criteria 1, 2, 3, 5: the secret is shown once, in the response
// to the request that generated it, and no request can ever fetch it again.
func TestCreateApplicationShowsTheSecretExactlyOnce(t *testing.T) {
	h := newHarness(t)

	rec := h.post("/admin/applications", url.Values{"name": {"My Test Application"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("create sets Location %q; the admin never leaves /admin", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the response carrying the secret has Cache-Control %q, want no-store", got)
	}

	id, err := strconv.ParseInt(rec.Header().Get(createdHeader), 10, 64)
	if err != nil {
		t.Fatalf("no usable %s header: %v", createdHeader, err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Danger zone") {
		t.Error("the create response is not the new application's panel")
	}
	shown := extractSecret(t, body)
	if shown == "" {
		t.Fatal("the freshly created secret was not displayed")
	}
	dialog := secretDialog(body)
	for _, want := range []string{"will not be able", "Copy", "OK"} {
		if !strings.Contains(dialog, want) {
			t.Errorf("the secret dialog does not mention %q", want)
		}
	}
	ok, err := h.store.VerifyClientSecret(context.Background(), id, shown)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("the displayed secret does not match the stored hash")
	}

	for _, path := range []string{"/admin", "/admin/applications", appPath(id)} {
		again := h.get(path).Body.String()
		if strings.Contains(again, shown) || strings.Contains(again, "data-secret") {
			t.Errorf("GET %s shows the client secret again", path)
		}
	}
}

func TestCreateApplicationRequiresAName(t *testing.T) {
	h := newHarness(t)

	rec := h.post("/admin/applications", url.Values{"name": {"   "}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "must not be empty") {
		t.Error("the error does not say the name is required")
	}
	if !strings.Contains(body, `name="name"`) || !strings.Contains(body, "required") {
		t.Error("the response is not the register form, or the input is not required")
	}

	apps, _ := h.store.ListApplications(context.Background())
	if len(apps) != 0 {
		t.Errorf("an invalid submission created %d application(s)", len(apps))
	}
}

// Acceptance criterion 6.
func TestRegenerateSecretShowsANewSecretOnce(t *testing.T) {
	h := newHarness(t)
	id, first := h.createAppWithSecret("App")

	rec := h.post(appPath(id)+"/secret", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("regenerate returned %d, want 200", rec.Code)
	}
	shown := extractSecret(t, rec.Body.String())
	if shown == "" {
		t.Fatal("the regenerated secret was not displayed")
	}
	if shown == first {
		t.Error("regenerating returned the previous secret")
	}
	ok, err := h.store.VerifyClientSecret(context.Background(), id, shown)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("the displayed regenerated secret does not match the stored hash")
	}

	if strings.Contains(h.get(appPath(id)).Body.String(), shown) {
		t.Error("the regenerated secret is shown again by a later request")
	}
}

// Only the response to a secret-generating request may carry a secret. Every
// other panel response must not, or a later edit would re-display it.
func TestOtherPanelResponsesCarryNoSecret(t *testing.T) {
	h := newHarness(t)
	id, shown := h.createAppWithSecret("App")

	for _, change := range []struct {
		path string
		form url.Values
	}{
		{appPath(id) + "/redirect-uris", url.Values{"uri": {"https://x.example.com/cb"}}},
		{appPath(id) + "/users", url.Values{"username": {"david"}}},
		{appPath(id) + "/name", url.Values{"name": {"Renamed"}}},
	} {
		body := h.post(change.path, change.form).Body.String()
		if strings.Contains(body, shown) || strings.Contains(body, "data-secret") {
			t.Errorf("POST %s re-displayed the client secret", change.path)
		}
	}
}

// Acceptance criterion 7.
func TestAddAndRemoveRedirectURIs(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App", "https://a.example.com/cb")
	base := appPath(id)

	rec := h.post(base+"/redirect-uris", url.Values{"uri": {"https://b.example.com/cb"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("add returned %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "https://b.example.com/cb") {
		t.Error("the refreshed panel does not list the added redirect URI")
	}

	rec = h.post(base+"/redirect-uris/remove", url.Values{"uri": {"https://a.example.com/cb"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove returned %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "https://a.example.com/cb") {
		t.Error("the refreshed panel still lists the removed redirect URI")
	}

	rec = h.post(base+"/redirect-uris", url.Values{"uri": {"javascript:alert(1)"}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a non-http redirect URI returned %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "redirect uri") {
		t.Error("the panel does not explain the rejected redirect URI")
	}
	if !strings.Contains(body, `value="javascript:alert(1)"`) {
		t.Error("the rejected redirect URI was not kept in the form")
	}
	app, _ := h.store.GetApplication(context.Background(), id)
	if len(app.RedirectURIs) != 1 {
		t.Errorf("redirect URIs = %v, want only the one added", app.RedirectURIs)
	}
}

// Acceptance criterion 27: the confirmation must say what else will be destroyed.
func TestDeleteConfirmationWarnsAboutUsers(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Doomed")
	seedUsers(t, h, id, 3)

	body := h.get(appPath(id)).Body.String()
	dialog := body[max(strings.Index(body, `<dialog id="delete-`+itoa(id)+`"`), 0):]
	if !strings.HasPrefix(dialog, "<dialog") {
		t.Fatal("the panel has no delete confirmation dialog")
	}
	for _, want := range []string{"permanently delete", "test users", "cannot be undone", "3"} {
		if !strings.Contains(dialog, want) {
			t.Errorf("the confirmation does not mention %q", want)
		}
	}
}

func TestDeleteApplicationRemovesItAndItsUsers(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Doomed")
	seedUsers(t, h, id, 2)

	rec := h.post(appPath(id)+"/delete", url.Values{})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d, want 204", rec.Code)
	}

	if _, err := h.store.GetApplication(context.Background(), id); err == nil {
		t.Error("the application still exists after deletion")
	}
	var users int
	if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE application_id = ?`, id).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Errorf("%d users survived the application deletion", users)
	}
}

// Every state-changing route must reject a request without a CSRF token.
func TestStateChangingRoutesRequireCSRF(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App", "https://a.example.com/cb")
	base := appPath(id)

	for _, path := range []string{
		"/admin/applications",
		base + "/secret",
		base + "/redirect-uris",
		base + "/redirect-uris/remove",
		base + "/delete",
	} {
		t.Run(path, func(t *testing.T) {
			req := newForm(http.MethodPost, path, "name=x&uri=https://x.example.com/cb")
			// Deliberately no cookies and no token.
			rec := httptest.NewRecorder()
			h.mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s without a CSRF token = %d, want 403", path, rec.Code)
			}
		})
	}
}

func TestUnknownApplicationIsNotFound(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/admin/applications/4242", "/admin/applications/not-a-number", "/admin/applications/new"} {
		if rec := h.get(path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := h.post("/admin/applications/4242/secret", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("POST to an unknown application = %d, want 404", rec.Code)
	}
}

// The confirmation is a dialog now; the page it used to be is gone.
func TestDeleteConfirmationPageIsGone(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App")
	if rec := h.get(appPath(id) + "/delete"); rec.Code == http.StatusOK {
		t.Errorf("GET %s/delete = 200; the confirmation page should no longer exist", appPath(id))
	}
}

// The admin UI renders user-supplied names, so escaping must be active.
func TestApplicationNameIsEscaped(t *testing.T) {
	h := newHarness(t)
	id := h.createApp(`<script>alert("xss")</script>`)

	for _, path := range []string{"/admin/applications", appPath(id)} {
		body := h.get(path).Body.String()
		if strings.Contains(body, "<script>alert") {
			t.Errorf("GET %s rendered the application name unescaped", path)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("GET %s does not contain the escaped name", path)
		}
	}
}

// Infrastructure failures must not be shown to the administrator as if they
// were their own input mistake.
func TestInternalFailureIsNotReportedAsValidation(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App")

	// Closing the database makes every subsequent query fail.
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}

	rec := h.get(appPath(id))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a database failure returned %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sql:") || strings.Contains(rec.Body.String(), "database is closed") {
		t.Error("the raw database error was shown in the browser")
	}
}

func TestSignInOffersOnlyConfiguredProviders(t *testing.T) {
	h, err := newHandler(nil, refusingAdmin{err: adminauth.ErrUnauthenticated}, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, signInPath, nil)
	rec := httptest.NewRecorder()
	data := h.newPageData(rec, req, nil, "Sign in")
	data.Providers = providerButtonsFor([]string{"github"})
	h.render(rec, req, "signin", http.StatusOK, data)

	body := rec.Body.String()
	if !strings.Contains(body, "Continue with GitHub") || !strings.Contains(body, `href="/admin/auth/github/start"`) {
		t.Error("the configured provider has no sign-in button")
	}
	for _, absent := range []string{"Google", "Microsoft", "LinkedIn"} {
		if strings.Contains(body, absent) {
			t.Errorf("an unconfigured provider, %s, is offered", absent)
		}
	}
}

func TestProviderButtons(t *testing.T) {
	got := providerButtonsFor([]string{"google", "microsoft", "linkedin", "github", "acme"})
	want := []struct{ id, label string }{
		{"google", "Continue with Google"},
		{"microsoft", "Continue with Microsoft"},
		{"linkedin", "Continue with LinkedIn"},
		{"github", "Continue with GitHub"},
		{"acme", "Continue with acme"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d buttons, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].ID != w.id || got[i].Label != w.label {
			t.Errorf("button %d = {%q, %q}, want {%q, %q}", i, got[i].ID, got[i].Label, w.id, w.label)
		}
	}
	if got[4].Icon != "" {
		t.Error("an unknown provider was given another provider's icon")
	}
}

func newForm(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(fragmentHeader, "1")
	return req
}

// The panel opens with the application's name and the control that changes it,
// and closes with a danger zone that is folded away until it is wanted.
func TestPanelOpensWithTheNameAndFoldsTheDangerZone(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Panel Shape")

	body := h.get(appPath(id)).Body.String()
	for _, want := range []string{
		`data-app-name="Panel Shape"`,
		`commandfor="rename-` + itoa(id) + `"`,
		`<dialog id="rename-` + itoa(id) + `"`,
		"Rename application",
		`<dialog id="regenerate-` + itoa(id) + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the panel does not contain %q", want)
		}
	}

	danger := body[strings.Index(body, "danger-zone"):]
	if !strings.Contains(body, `<details class="panel-section danger-zone"`) {
		t.Error("the danger zone is not foldable")
	}
	if strings.Contains(danger[:strings.Index(danger, ">")+1], "open") {
		t.Error("the danger zone is unfolded by default")
	}

	// The rename dialog is the register dialog with another title, so both must
	// carry the same field.
	rename := body[strings.Index(body, `<dialog id="rename-`):]
	rename = rename[:strings.Index(rename, "</dialog>")]
	if !strings.Contains(rename, `name="name"`) || !strings.Contains(rename, `value="Panel Shape"`) {
		t.Error("the rename dialog does not offer the current name")
	}
}

func TestCreateApplicationRejectsANameAlreadyInUse(t *testing.T) {
	h := newHarness(t)
	h.createApp("Only One")

	rec := h.post("/admin/applications", url.Values{"name": {"  only   one  "}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a duplicate name returned %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "already exists") {
		t.Error("the error does not say the name is taken")
	}
	if !strings.Contains(body, `name="name"`) {
		t.Error("the response is not the name form")
	}

	// The rejected name is offered back for correction, but what Cancel
	// restores is still "no name at all".
	if !strings.Contains(body, `data-original=""`) {
		t.Error("the rejected name became the value the dialog reverts to")
	}

	apps, _ := h.store.ListApplications(context.Background())
	if len(apps) != 1 {
		t.Errorf("%d applications exist, want 1", len(apps))
	}
}

func TestRenameApplication(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Before")

	rec := h.post(appPath(id)+"/name", url.Values{"name": {"After"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("rename returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `data-app-name="After"`) {
		t.Error("the refreshed panel does not carry the new name")
	}
	if !strings.Contains(h.get("/admin/applications").Body.String(), "After") {
		t.Error("the list does not show the new name")
	}

	apps, _ := h.store.ListApplications(context.Background())
	if len(apps) != 1 {
		t.Errorf("renaming left %d applications, want 1", len(apps))
	}
}

func TestRenameApplicationRejectsANameInUse(t *testing.T) {
	h := newHarness(t)
	first := h.createApp("First")
	h.createApp("Second")

	rec := h.post(appPath(first)+"/name", url.Values{"name": {"Second"}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "already exists") {
		t.Error("the error does not explain the conflict")
	}
	if !strings.Contains(body, `value="Second"`) {
		t.Error("the rejected name was not kept in the form")
	}
	// Cancelling goes back to the name the application actually has.
	if !strings.Contains(body, `data-original="First"`) {
		t.Error("the rejected name became the value the dialog reverts to")
	}

	app, _ := h.store.GetApplication(context.Background(), first)
	if app.Name != "First" {
		t.Errorf("name = %q, want it unchanged", app.Name)
	}
}

func TestRenameUnknownApplicationIsNotFound(t *testing.T) {
	h := newHarness(t)
	if rec := h.post("/admin/applications/4242/name", url.Values{"name": {"Whatever"}}); rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", rec.Code)
	}
}

// The register dialog checks the name while it is typed, so the administrator
// learns it is taken before pressing anything.
func TestNameCheck(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Taken")

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"name=Free", http.StatusNoContent},
		{"name=Taken", http.StatusConflict},
		{"name=++taken++", http.StatusConflict},
		{"name=Taken&exclude=" + itoa(id), http.StatusNoContent},
		{"name=Taken&exclude=not-a-number", http.StatusConflict},
		{"name=", http.StatusNoContent},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := h.get("/admin/applications/name-check?" + tc.query)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusConflict && !strings.Contains(rec.Body.String(), "already in use") {
				t.Errorf("the reply does not say the name is in use: %s", rec.Body.String())
			}
			// A cached "that name is free" would keep offering a name someone
			// else has since registered.
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}

	// It is part of the interface, not an endpoint of its own.
	if rec := h.page("/admin/applications/name-check?name=Free"); rec.Code != http.StatusSeeOther {
		t.Errorf("a browser visit returned %d, want a 303 to /admin", rec.Code)
	}
}
