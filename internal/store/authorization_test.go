package store

import (
	"errors"
	"testing"
	"time"
)

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func newAuthRequest(t *testing.T, s *Store, appID int64) *AuthRequest {
	t.Helper()
	req, err := s.CreateAuthRequest(ctx(), AuthRequest{
		ApplicationID: appID,
		RedirectURI:   "https://app.example.com/cb",
		State:         "client-state",
		Nonce:         "client-nonce",
		Scope:         "openid profile",
	}, time.Minute)
	if err != nil {
		t.Fatalf("CreateAuthRequest() error: %v", err)
	}
	return req
}

func TestAuthRequestRoundTrip(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")

	created := newAuthRequest(t, s, app.ID)
	if created.ID == "" {
		t.Fatal("no request id was generated")
	}
	if len(created.ID) < 22 {
		t.Errorf("request id %q is too short to be unguessable", created.ID)
	}

	got, err := s.GetAuthRequest(ctx(), created.ID)
	if err != nil {
		t.Fatalf("GetAuthRequest() error: %v", err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"redirect_uri", got.RedirectURI, "https://app.example.com/cb"},
		{"state", got.State, "client-state"},
		{"nonce", got.Nonce, "client-nonce"},
		{"scope", got.Scope, "openid profile"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestAuthRequestIdsAreUnpredictable(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")

	seen := map[string]bool{}
	for range 50 {
		id := newAuthRequest(t, s, app.ID).ID
		if seen[id] {
			t.Fatalf("request id %q was issued twice", id)
		}
		seen[id] = true
	}
}

func TestExpiredAuthRequestIsRejected(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")

	start := time.Unix(1_000_000, 0)
	s.now = fixedClock(start)
	req := newAuthRequest(t, s, app.ID)

	s.now = fixedClock(start.Add(time.Minute + time.Second))
	if _, err := s.GetAuthRequest(ctx(), req.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired authorization request was returned: %v", err)
	}
}

func TestConsumeAuthRequestIsSingleUse(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	req := newAuthRequest(t, s, app.ID)

	if _, err := s.ConsumeAuthRequest(ctx(), req.ID); err != nil {
		t.Fatalf("ConsumeAuthRequest() error: %v", err)
	}
	if _, err := s.ConsumeAuthRequest(ctx(), req.ID); !errors.Is(err, ErrNotFound) {
		t.Error("an authorization request was consumed twice")
	}
}

// Deleting an application must not strand its parked requests.
func TestAuthRequestsCascadeWithTheirApplication(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	newAuthRequest(t, s, app.ID)

	if err := s.DeleteApplication(ctx(), app.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM auth_requests`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d authorization requests survived the application", n)
	}
}

func issueCode(t *testing.T, s *Store, appID, userID int64) (string, *AuthCode) {
	t.Helper()
	plain, code, err := s.IssueAuthCode(ctx(), AuthCode{
		ApplicationID: appID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/cb",
		Nonce:         "client-nonce",
		Scope:         "openid profile",
	}, time.Minute)
	if err != nil {
		t.Fatalf("IssueAuthCode() error: %v", err)
	}
	return plain, code
}

// §3: codes must be cryptographically unpredictable and stored so that reading
// the database does not yield a usable code.
func TestAuthCodeIsUnpredictableAndStoredHashed(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	user := mustCreateUser(t, s, app.ID, "david")

	plain, _ := issueCode(t, s, app.ID, user.ID)
	if len(plain) < 40 {
		t.Errorf("authorization code %q carries too little entropy", plain)
	}

	var stored string
	if err := s.DB().QueryRow(`SELECT code_hash FROM auth_codes`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == plain {
		t.Fatal("the authorization code is stored in plaintext")
	}

	var raw int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE code_hash = ?`, plain).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != 0 {
		t.Error("the plaintext code matches a stored row")
	}
}

// §3 and acceptance criterion 24.
func TestAuthCodeIsSingleUse(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	user := mustCreateUser(t, s, app.ID, "david")
	plain, _ := issueCode(t, s, app.ID, user.ID)

	first, err := s.ConsumeAuthCode(ctx(), plain)
	if err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}
	if first.UserID != user.ID {
		t.Errorf("code resolved to user %d, want %d", first.UserID, user.ID)
	}

	second, err := s.ConsumeAuthCode(ctx(), plain)
	if !errors.Is(err, ErrCodeReplayed) {
		t.Errorf("replaying a code returned (%v, %v), want ErrCodeReplayed", second, err)
	}
}

func TestExpiredAuthCodeIsRejected(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	user := mustCreateUser(t, s, app.ID, "david")

	start := time.Unix(1_000_000, 0)
	s.now = fixedClock(start)
	plain, _ := issueCode(t, s, app.ID, user.ID)

	s.now = fixedClock(start.Add(time.Minute + time.Second))
	if _, err := s.ConsumeAuthCode(ctx(), plain); !errors.Is(err, ErrCodeExpired) {
		t.Error("an expired authorization code was accepted")
	}
}

func TestUnknownAuthCodeIsRejected(t *testing.T) {
	s := openTemp(t)
	if _, err := s.ConsumeAuthCode(ctx(), "never-issued"); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestAuthCodeCarriesItsBindings(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	user := mustCreateUser(t, s, app.ID, "david")

	plain, _, err := s.IssueAuthCode(ctx(), AuthCode{
		ApplicationID:       app.ID,
		UserID:              user.ID,
		RedirectURI:         "https://app.example.com/cb",
		Nonce:               "client-nonce",
		Scope:               "openid profile",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeAuthCode(ctx(), plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"redirect_uri", got.RedirectURI, "https://app.example.com/cb"},
		{"nonce", got.Nonce, "client-nonce"},
		{"scope", got.Scope, "openid profile"},
		{"code_challenge", got.CodeChallenge, "challenge-value"},
		{"code_challenge_method", got.CodeChallengeMethod, "S256"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if got.ApplicationID != app.ID {
		t.Errorf("application = %d, want %d", got.ApplicationID, app.ID)
	}
}

// Housekeeping must not remove a consumed code while it could still be
// replayed within its own lifetime.
func TestPurgeExpiredRemovesOnlyWhatIsPastItsLifetime(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://app.example.com/cb")
	user := mustCreateUser(t, s, app.ID, "david")

	start := time.Unix(1_000_000, 0)
	s.now = fixedClock(start)
	plain, _ := issueCode(t, s, app.ID, user.ID)
	newAuthRequest(t, s, app.ID)
	if _, err := s.ConsumeAuthCode(ctx(), plain); err != nil {
		t.Fatal(err)
	}

	// Still inside the code's lifetime: the replay record must survive.
	s.now = fixedClock(start.Add(30 * time.Second))
	if err := s.PurgeExpired(ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthCode(ctx(), plain); !errors.Is(err, ErrCodeReplayed) {
		t.Error("a consumed code was purged while it could still be replayed")
	}

	// Past it: everything goes.
	s.now = fixedClock(start.Add(time.Hour))
	if err := s.PurgeExpired(ctx()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"auth_codes", "auth_requests"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still holds %d expired rows", table, n)
		}
	}
}
