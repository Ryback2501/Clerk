package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIDP is a minimal OIDC provider: discovery, JWKS, and a token endpoint
// that returns an ID token carrying whatever claims a test asks for.
type fakeIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any
	nonce  string
}

func newFakeIDP(t *testing.T, claims map[string]any) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key, claims: claims}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/auth",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// The client must prove possession of the PKCE verifier.
		if r.PostFormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "provider-access-token",
			"token_type":   "Bearer",
			"id_token":     idp.mintIDToken(t, "test-client"),
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (f *fakeIDP) mintIDToken(t *testing.T, audience string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{
		"iss":   f.server.URL,
		"aud":   audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": f.nonce,
	}
	for k, v := range f.claims {
		claims[k] = v
	}

	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// memoryStore is the session persistence, in memory.
type memoryStore struct {
	logins   map[string]*StoredLogin
	sessions map[string]*StoredSession
	seq      int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{logins: map[string]*StoredLogin{}, sessions: map[string]*StoredSession{}}
}

func (m *memoryStore) CreateAdminLogin(_ context.Context, provider, verifier, nonce, returnTo string, _ time.Duration) (*StoredLogin, error) {
	m.seq++
	l := &StoredLogin{
		State: "state-" + itoa(m.seq), Provider: provider,
		CodeVerifier: verifier, Nonce: nonce, ReturnTo: returnTo,
	}
	m.logins[l.State] = l
	return l, nil
}

func (m *memoryStore) ConsumeAdminLogin(_ context.Context, state string) (*StoredLogin, error) {
	l, ok := m.logins[state]
	if !ok {
		return nil, errors.New("not found")
	}
	delete(m.logins, state)
	return l, nil
}

func (m *memoryStore) CreateAdminSession(_ context.Context, subject, provider, name string, _ time.Duration) (*StoredSession, error) {
	m.seq++
	s := &StoredSession{ID: "session-" + itoa(m.seq), Subject: subject, Provider: provider, Name: name}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *memoryStore) GetAdminSession(_ context.Context, id string) (*StoredSession, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}

func (m *memoryStore) DeleteAdminSession(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// recordingAuthorizer captures what the Bouncer client would be asked.
type recordingAuthorizer struct {
	got Identity
	err error
}

func (r *recordingAuthorizer) Authorize(_ context.Context, identity Identity) error {
	r.got = identity
	return r.err
}

func newOAuthUnderTest(t *testing.T, idp *fakeIDP, provider string, auth Authorizer, store SessionStore) *OAuth {
	t.Helper()
	public, _ := url.Parse("https://clerk.example.com")

	// The issuer override points this provider at the fake, so the shared
	// provider table is never mutated and the tests stay independent.
	a, err := NewOAuth(context.Background(), OAuthConfig{
		PublicURL: public,
		Providers: map[string]ClientCredentials{provider: {
			ClientID: "test-client", ClientSecret: "test-secret", Issuer: idp.server.URL,
		}},
		Store:      store,
		Authorizer: auth,
		HTTPClient: idp.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The whole integration in one test: a Microsoft sign-in must present the oid
// claim to the role service, not the pairwise sub.
func TestMicrosoftSignInSendsTheObjectIDToTheAuthorizer(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{
		"sub":  "pairwise-sub-for-this-client",
		"oid":  "00000000-1111-2222-3333-444444444444",
		"name": "Grace Hopper",
	})
	recorder := &recordingAuthorizer{}
	store := newMemoryStore()
	a := newOAuthUnderTest(t, idp, "microsoft", recorder, store)

	authURL, err := a.Start(context.Background(), "microsoft", "/admin")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	parsed, _ := url.Parse(authURL)
	q := parsed.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("no PKCE challenge was sent upstream")
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("no state parameter was sent")
	}
	idp.nonce = q.Get("nonce")
	if idp.nonce == "" {
		t.Error("no nonce was sent to an OIDC provider")
	}

	session, returnTo, err := a.Complete(context.Background(), "microsoft", state, "provider-code")
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}

	if recorder.got.Subject != "00000000-1111-2222-3333-444444444444" {
		t.Errorf("the authorizer was asked about %q, want the oid claim", recorder.got.Subject)
	}
	if recorder.got.Subject == "pairwise-sub-for-this-client" {
		t.Fatal("the pairwise sub was sent; no Microsoft administrator would ever match")
	}
	if recorder.got.Provider != "microsoft" {
		t.Errorf("provider = %q, want microsoft", recorder.got.Provider)
	}
	if session.Name != "Grace Hopper" {
		t.Errorf("session name = %q", session.Name)
	}
	if returnTo != "/admin" {
		t.Errorf("returnTo = %q, want /admin", returnTo)
	}
}

func TestGoogleSignInSendsTheSubject(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "109876543210", "name": "Ada"})
	recorder := &recordingAuthorizer{}
	a := newOAuthUnderTest(t, idp, "google", recorder, newMemoryStore())

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	idp.nonce = q.Query().Get("nonce")

	if _, _, err := a.Complete(context.Background(), "google", q.Query().Get("state"), "code"); err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if recorder.got.Subject != "109876543210" {
		t.Errorf("subject = %q, want the sub claim", recorder.got.Subject)
	}
}

// A refusal from the role service must not create a session.
func TestRefusalByTheAuthorizerCreatesNoSession(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s", "name": "Nobody"})
	store := newMemoryStore()
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{err: ErrForbidden}, store)

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	idp.nonce = q.Query().Get("nonce")

	_, _, err := a.Complete(context.Background(), "google", q.Query().Get("state"), "code")
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("Complete() = %v, want ErrForbidden", err)
	}
	if len(store.sessions) != 0 {
		t.Errorf("%d sessions were created despite the refusal", len(store.sessions))
	}
}

// An outage of the role service must be distinguishable from a refusal, so the
// admin UI can say which happened.
func TestRoleServiceOutagePropagatesAsUnavailable(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s", "name": "Ada"})
	store := newMemoryStore()
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{err: ErrUnavailable}, store)

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	idp.nonce = q.Query().Get("nonce")

	_, _, err := a.Complete(context.Background(), "google", q.Query().Get("state"), "code")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Complete() = %v, want ErrUnavailable", err)
	}
	if len(store.sessions) != 0 {
		t.Error("a session was created despite the role service being unavailable")
	}
}

// The callback's state is single-use: replaying it must fail.
func TestCallbackCannotBeReplayed(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s", "name": "Ada"})
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, newMemoryStore())

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	state := q.Query().Get("state")
	idp.nonce = q.Query().Get("nonce")

	if _, _, err := a.Complete(context.Background(), "google", state, "code"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Complete(context.Background(), "google", state, "code"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("replaying the callback returned %v, want ErrUnauthenticated", err)
	}
}

func TestForgedCallbackStateIsRejected(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s"})
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, newMemoryStore())

	if _, _, err := a.Complete(context.Background(), "google", "never-issued", "code"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a forged state returned %v, want ErrUnauthenticated", err)
	}
}

// An ID token whose nonce does not match the sign-in it claims to answer must
// be refused: that binding is what stops a token being replayed from elsewhere.
func TestMismatchedNonceIsRejected(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s", "name": "Ada"})
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, newMemoryStore())

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	idp.nonce = "a-different-nonce-entirely"

	_, _, err := a.Complete(context.Background(), "google", q.Query().Get("state"), "code")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Complete() = %v, want the mismatched nonce rejected", err)
	}
}

// Starting with one provider and returning on another's callback must fail.
func TestCallbackOnTheWrongProviderIsRejected(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s"})
	store := newMemoryStore()
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, store)

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)

	if _, _, err := a.Complete(context.Background(), "github", q.Query().Get("state"), "code"); err == nil {
		t.Error("a callback on a different provider was accepted")
	}
}

func TestCallbackURLMatchesWhatMustBeRegistered(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s"})
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, newMemoryStore())

	if got, want := a.CallbackURL("google"), "https://clerk.example.com/admin/auth/google/callback"; got != want {
		t.Errorf("CallbackURL() = %q, want %q", got, want)
	}
}

func TestNewOAuthRejectsAnUnusableConfiguration(t *testing.T) {
	public, _ := url.Parse("https://clerk.example.com")
	store := newMemoryStore()

	for _, tt := range []struct {
		name string
		cfg  OAuthConfig
	}{
		{"no providers at all", OAuthConfig{PublicURL: public, Store: store, Authorizer: &recordingAuthorizer{}}},
		{"no store", OAuthConfig{PublicURL: public, Authorizer: &recordingAuthorizer{},
			Providers: map[string]ClientCredentials{"google": {ClientID: "a", ClientSecret: "b"}}}},
		{"unknown provider", OAuthConfig{PublicURL: public, Store: store, Authorizer: &recordingAuthorizer{},
			Providers: map[string]ClientCredentials{"myspace": {ClientID: "a", ClientSecret: "b"}}}},
		{"provider with no secret", OAuthConfig{PublicURL: public, Store: store, Authorizer: &recordingAuthorizer{},
			Providers: map[string]ClientCredentials{"google": {ClientID: "a"}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewOAuth(context.Background(), tt.cfg); err == nil {
				t.Error("NewOAuth accepted an unusable configuration")
			}
		})
	}
}

func TestAuthenticateResolvesTheSessionCookie(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s", "name": "Ada"})
	store := newMemoryStore()
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, store)

	authURL, _ := a.Start(context.Background(), "google", "/admin")
	q, _ := url.Parse(authURL)
	idp.nonce = q.Query().Get("nonce")
	session, _, err := a.Complete(context.Background(), "google", q.Query().Get("state"), "code")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	admin, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if admin.Name != "Ada" || admin.Provider != "google" {
		t.Errorf("admin = %+v, want the session's identity", admin)
	}

	// No cookie, an unknown cookie, and a signed-out session must all fail.
	if _, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/admin", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("a request with no cookie was authenticated")
	}
	if err := a.SignOut(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(req); !errors.Is(err, ErrUnauthenticated) {
		t.Error("a signed-out session still authenticates")
	}
}

func TestEnabledProvidersIsStable(t *testing.T) {
	idp := newFakeIDP(t, map[string]any{"sub": "s"})
	a := newOAuthUnderTest(t, idp, "google", &recordingAuthorizer{}, newMemoryStore())

	first := strings.Join(a.EnabledProviders(), ",")
	for range 5 {
		if got := strings.Join(a.EnabledProviders(), ","); got != first {
			t.Fatalf("EnabledProviders() reordered: %q then %q", first, got)
		}
	}
}

// Overriding the issuer of a provider that has none is a configuration
// mistake, not something to ignore.
func TestIssuerOverrideOnANonOIDCProviderIsRejected(t *testing.T) {
	public, _ := url.Parse("https://clerk.example.com")

	_, err := NewOAuth(context.Background(), OAuthConfig{
		PublicURL: public,
		Providers: map[string]ClientCredentials{"github": {
			ClientID: "a", ClientSecret: "b", Issuer: "https://example.com",
		}},
		Store:      newMemoryStore(),
		Authorizer: &recordingAuthorizer{},
	})
	if err == nil {
		t.Error("an issuer override was accepted for a provider with no OIDC issuer")
	}
}
