package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/standin"
	"github.com/Ryback2501/Clerk/internal/store"
)

// The admin interface with real sign-in, served over HTTP for the sign-in
// tests: the real handlers, the real session store on a temporary database,
// and the real OAuth client talking to a stand-in Google. Only Bouncer's
// answer is faked, and each test sets it.

// signInSite is the admin interface with real sign-in, served over HTTP.
type signInSite struct {
	URL      string
	client   *http.Client
	sessions *SessionStore
	bouncer  *fakeBouncer
}

// fakeBouncer answers every role check with whatever the test set: nil
// grants access.
type fakeBouncer struct {
	mu  sync.Mutex
	err error
}

func (b *fakeBouncer) Authorize(context.Context, adminauth.Identity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *fakeBouncer) answer(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err = err
}

func newSignInSite(t *testing.T) *signInSite {
	t.Helper()
	provider := standin.NewProvider(t)

	db, err := store.Open(filepath.Join(t.TempDir(), "clerk.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The listener exists first, so the callback URL can name it.
	srv := httptest.NewUnstartedServer(nil)
	public, err := url.Parse("http://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	sessions := NewSessionStore(db)
	bouncer := &fakeBouncer{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oauth, err := adminauth.NewOAuth(ctx, adminauth.OAuthConfig{
		PublicURL: public,
		Providers: map[string]adminauth.ClientCredentials{"google": {
			ClientID:     standin.ProviderClientID,
			ClientSecret: standin.ProviderClientSecret,
			Issuer:       provider.URL,
		}},
		Store:      sessions,
		Authorizer: bouncer,
	})
	if err != nil {
		srv.Close()
		t.Fatalf("admin sign-in: %v", err)
	}
	h, err := NewWithOAuth(db, oauth)
	if err != nil {
		srv.Close()
		t.Fatalf("admin handler: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &signInSite{
		URL: public.String(),
		client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		sessions: sessions,
		bouncer:  bouncer,
	}
}

// signIn goes through the stand-in Google as a browser would, and returns
// Clerk's answer to the provider's callback.
func (s *signInSite) signIn(t *testing.T) *http.Response {
	t.Helper()
	start := s.get(t, "/admin/auth/google/start")
	readAll(t, start)
	toProvider := start.Header.Get("Location")
	if start.StatusCode != http.StatusSeeOther || toProvider == "" {
		t.Fatalf("starting the sign-in answered %d → %q", start.StatusCode, toProvider)
	}
	atProvider := s.do(t, http.MethodGet, toProvider, nil, nil)
	readAll(t, atProvider)
	callback := atProvider.Header.Get("Location")
	if !strings.HasPrefix(callback, s.URL+"/admin/auth/google/callback") {
		t.Fatalf("the provider sent the browser to %q, want the callback", callback)
	}
	return s.do(t, http.MethodGet, callback, nil, nil)
}

// signInOK signs in and expects it to succeed.
func (s *signInSite) signInOK(t *testing.T) {
	t.Helper()
	resp := s.signIn(t)
	if body := readAll(t, resp); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signing in answered %d: %s", resp.StatusCode, body)
	}
}

// sessionID is the session cookie the browser holds.
func (s *signInSite) sessionID(t *testing.T) string {
	t.Helper()
	if v := s.sessionCookie(t); v != "" {
		return v
	}
	t.Fatal("the browser holds no session cookie")
	return ""
}

func (s *signInSite) sessionCookie(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(s.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.client.Jar.Cookies(u) {
		if c.Name == adminauth.SessionCookieName {
			return c.Value
		}
	}
	return ""
}

// csrf reads the token the admin page's forms carry.
func (s *signInSite) csrf(t *testing.T) string {
	t.Helper()
	resp := s.get(t, "/admin")
	page := readAll(t, resp)
	m := csrfField.FindStringSubmatch(page)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("/admin answered %d without a CSRF token:\n%s", resp.StatusCode, page)
	}
	return m[1]
}

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// expectSignInPageWith checks the answer sends the browser to the sign-in
// page, and that the page shows the message.
func (s *signInSite) expectSignInPageWith(t *testing.T, resp *http.Response, message string) {
	t.Helper()
	to := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(to, "/admin/signin") {
		t.Fatalf("answered %d → %q, want 303 to the sign-in page", resp.StatusCode, to)
	}
	page := s.get(t, to)
	if body := readAll(t, page); !strings.Contains(body, message) {
		t.Errorf("the sign-in page does not say %q:\n%s", message, body)
	}
}

// expectNoSession checks the answer set no session cookie and the browser
// holds none.
func (s *signInSite) expectNoSession(t *testing.T, resp *http.Response) {
	t.Helper()
	if c := cookieIn(resp, adminauth.SessionCookieName); c != nil && c.Value != "" {
		t.Errorf("a session cookie was set: %+v", c)
	}
	if s.sessionCookie(t) != "" {
		t.Error("the browser holds a session cookie")
	}
}

func (s *signInSite) get(t *testing.T, path string) *http.Response {
	t.Helper()
	return s.do(t, http.MethodGet, s.URL+path, nil, nil)
}

// getWithSession sends a request carrying only the given session cookie,
// bypassing the browser's cookie jar.
func (s *signInSite) getWithSession(t *testing.T, path, sessionID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionID})
	client := *s.client
	client.Jar = nil
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (s *signInSite) postForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	return s.do(t, http.MethodPost, s.URL+path, strings.NewReader(form.Encode()), func(req *http.Request) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
}

func (s *signInSite) do(t *testing.T, method, target string, body io.Reader, edit func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(req)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

// cookieIn is the named cookie a response sets, or nil.
func cookieIn(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// readAll returns the body and closes it.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
