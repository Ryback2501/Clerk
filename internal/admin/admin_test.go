package admin

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

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
)

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
	s, err := store.Open(filepath.Join(t.TempDir(), "clerk.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := New(s, adminauth.AllowAll{}, true)
	if err != nil {
		t.Fatalf("New(): %v", err)
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

func (h *harness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(httptest.NewRequest(http.MethodGet, path, nil))
}

// post submits a form, first fetching a page to pick up a valid CSRF token.
func (h *harness) post(path string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	form.Set(csrfFieldName, h.csrfToken())
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(req)
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (h *harness) csrfToken() string {
	h.t.Helper()
	body := h.get("/admin/applications/new").Body.String()
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("no CSRF token found in the form")
	}
	return m[1]
}

func (h *harness) createApp(name string, uris string) int64 {
	h.t.Helper()
	rec := h.post("/admin/applications", url.Values{"name": {name}, "redirect_uris": {uris}})
	if rec.Code != http.StatusSeeOther {
		h.t.Fatalf("create returned %d, want 303: %s", rec.Code, rec.Body.String())
	}
	apps, err := h.store.ListApplications(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, a := range apps {
		if a.Name == name {
			return a.ID
		}
	}
	h.t.Fatalf("application %q was not created", name)
	return 0
}

func TestListApplicationsRendersEmptyState(t *testing.T) {
	h := newHarness(t)

	rec := h.get("/admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No applications yet") {
		t.Error("the empty state is not shown")
	}
	// The stub authenticator must be visible in the UI, not silent.
	if !strings.Contains(rec.Body.String(), "Admin authentication is disabled") {
		t.Error("the insecure-mode banner is missing")
	}
}

// Acceptance criteria 1, 2, 3, 5.
func TestCreateApplicationShowsTheSecretExactlyOnce(t *testing.T) {
	h := newHarness(t)

	rec := h.post("/admin/applications", url.Values{
		"name":          {"My Test Application"},
		"redirect_uris": {"https://app.example.com/cb"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create returned %d, want a 303 redirect: %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")

	// The secret must not travel in the URL, where it would reach access logs
	// and referrer headers.
	if strings.Contains(location, "secret") || len(location) > 60 {
		t.Errorf("Location %q looks like it carries the secret", location)
	}

	page := h.get(location)
	if page.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", location, page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, "Client secret") || !strings.Contains(body, "Copy it now") {
		t.Fatal("the freshly created secret was not displayed")
	}

	shown := extractSecret(t, body)
	if shown == "" {
		t.Fatal("could not find the displayed secret")
	}

	// It verifies against what was stored...
	apps, _ := h.store.ListApplications(context.Background())
	ok, err := h.store.VerifyClientSecret(context.Background(), apps[0].ID, shown)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("the displayed secret does not match the stored hash")
	}

	// ...and a refresh must never show it again.
	again := h.get(location).Body.String()
	if strings.Contains(again, shown) {
		t.Error("the client secret was shown a second time on reload")
	}
	if strings.Contains(again, "Copy it now") {
		t.Error("the one-time secret panel is still rendered on reload")
	}
}

var secretPattern = regexp.MustCompile(`<code class="value">([A-Za-z0-9_-]{40,})</code>`)

func extractSecret(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "Copy it now")
	if i < 0 {
		return ""
	}
	m := secretPattern.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestCreateApplicationRejectsInvalidInputWithoutLosingIt(t *testing.T) {
	h := newHarness(t)

	rec := h.post("/admin/applications", url.Values{
		"name":          {"My App"},
		"redirect_uris": {"not-a-url"},
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	// The form must come back populated, not blank.
	if !strings.Contains(body, "My App") {
		t.Error("the submitted name was discarded on validation failure")
	}
	if !strings.Contains(body, "not-a-url") {
		t.Error("the submitted redirect URIs were discarded on validation failure")
	}

	apps, _ := h.store.ListApplications(context.Background())
	if len(apps) != 0 {
		t.Errorf("an invalid submission created %d application(s)", len(apps))
	}
}

// Acceptance criterion 6.
func TestRegenerateSecretShowsANewSecretOnce(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App", "https://a.example.com/cb")

	rec := h.post("/admin/applications/"+itoa(id)+"/secret", url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("regenerate returned %d, want 303", rec.Code)
	}

	body := h.get(rec.Header().Get("Location")).Body.String()
	shown := extractSecret(t, body)
	if shown == "" {
		t.Fatal("the regenerated secret was not displayed")
	}

	ok, err := h.store.VerifyClientSecret(context.Background(), id, shown)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("the displayed regenerated secret does not match the stored hash")
	}
}

// Acceptance criterion 7.
func TestAddAndRemoveRedirectURIs(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("App", "https://a.example.com/cb")
	base := "/admin/applications/" + itoa(id)

	if rec := h.post(base+"/redirect-uris", url.Values{"uri": {"https://b.example.com/cb"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("add returned %d, want 303", rec.Code)
	}
	if body := h.get(base).Body.String(); !strings.Contains(body, "https://b.example.com/cb") {
		t.Error("the added redirect URI is not listed")
	}

	if rec := h.post(base+"/redirect-uris/remove", url.Values{"uri": {"https://a.example.com/cb"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove returned %d, want 303", rec.Code)
	}
	if body := h.get(base).Body.String(); strings.Contains(body, "https://a.example.com/cb") {
		t.Error("the removed redirect URI is still listed")
	}

	if rec := h.post(base+"/redirect-uris", url.Values{"uri": {"javascript:alert(1)"}}); rec.Code == http.StatusSeeOther {
		t.Error("a non-http redirect URI was accepted")
	}
}

// Acceptance criterion 27: the confirmation must say what else will be destroyed.
func TestDeleteConfirmationWarnsAboutUsers(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Doomed", "https://a.example.com/cb")
	seedUsers(t, h, id, 3)

	body := h.get("/admin/applications/" + itoa(id) + "/delete").Body.String()
	for _, want := range []string{"permanently delete", "test users", "cannot be undone", "3"} {
		if !strings.Contains(body, want) {
			t.Errorf("the confirmation page does not mention %q", want)
		}
	}
}

func TestDeleteApplicationRemovesItAndItsUsers(t *testing.T) {
	h := newHarness(t)
	id := h.createApp("Doomed", "https://a.example.com/cb")
	seedUsers(t, h, id, 2)

	rec := h.post("/admin/applications/"+itoa(id)+"/delete", url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete returned %d, want 303", rec.Code)
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
	base := "/admin/applications/" + itoa(id)

	for _, path := range []string{
		"/admin/applications",
		base + "/secret",
		base + "/redirect-uris",
		base + "/redirect-uris/remove",
		base + "/delete",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("name=x&uri=https://x.example.com/cb"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	for _, path := range []string{"/admin/applications/4242", "/admin/applications/4242/delete"} {
		if rec := h.get(path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := h.get("/admin/applications/not-a-number"); rec.Code != http.StatusNotFound {
		t.Errorf("a non-numeric id returned %d, want 404", rec.Code)
	}
}

// The admin UI renders user-supplied names, so escaping must be active.
func TestApplicationNameIsEscaped(t *testing.T) {
	h := newHarness(t)
	h.createApp(`<script>alert("xss")</script>`, "https://a.example.com/cb")

	body := h.get("/admin").Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Error("the application name was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the escaped name is not present")
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/admin/static/pico.min.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the stylesheet = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("Content-Type = %q, want a CSS type", ct)
	}
}

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

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// The one-time secret must appear only on the application it belongs to.
func TestRevealedSecretDoesNotLeakOntoAnotherApplication(t *testing.T) {
	h := newHarness(t)
	first := h.createApp("First", "https://a.example.com/cb")
	second := h.createApp("Second", "https://b.example.com/cb")

	// Creating "Second" left a pending reveal. Viewing "First" must not show it.
	body := h.get("/admin/applications/" + itoa(first)).Body.String()
	if strings.Contains(body, "Copy it now") {
		t.Error("another application's secret was displayed on this page")
	}

	// It is still available where it belongs.
	if !strings.Contains(h.get("/admin/applications/"+itoa(second)).Body.String(), "Copy it now") {
		t.Error("the secret was not shown on the application it was generated for")
	}
}

// Pico guards its dark palette with :root:not([data-theme]), so emitting any
// data-theme value at all pins the UI to light mode regardless of the reader's
// system preference.
func TestPageDoesNotPinTheColourTheme(t *testing.T) {
	h := newHarness(t)
	body := h.get("/admin").Body.String()

	if strings.Contains(body, "data-theme") {
		t.Error("the page sets data-theme, which disables Pico's automatic dark mode")
	}
}
