package store

import (
	"errors"
	"testing"
	"time"
)

func TestAdminSessionRoundTripAndExpiry(t *testing.T) {
	s := openTemp(t)
	start := time.Unix(2_000_000, 0)
	s.now = fixedClock(start)

	sess, err := s.CreateAdminSession(ctx(), "sub-1", "google", "Ada", time.Hour)
	if err != nil {
		t.Fatalf("CreateAdminSession() error: %v", err)
	}
	if len(sess.ID) < 22 {
		t.Errorf("session id %q is too short to be unguessable", sess.ID)
	}

	got, err := s.GetAdminSession(ctx(), sess.ID)
	if err != nil {
		t.Fatalf("GetAdminSession() error: %v", err)
	}
	if got.Subject != "sub-1" || got.Provider != "google" || got.Name != "Ada" {
		t.Errorf("session = %+v, want the stored identity", got)
	}

	s.now = fixedClock(start.Add(time.Hour + time.Second))
	if _, err := s.GetAdminSession(ctx(), sess.ID); !errors.Is(err, ErrNotFound) {
		t.Error("an expired admin session was returned")
	}
}

// Signing out must take effect immediately, not when the cookie expires.
func TestDeleteAdminSession(t *testing.T) {
	s := openTemp(t)
	sess, err := s.CreateAdminSession(ctx(), "sub-1", "google", "Ada", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteAdminSession(ctx(), sess.ID); err != nil {
		t.Fatalf("DeleteAdminSession() error: %v", err)
	}
	if _, err := s.GetAdminSession(ctx(), sess.ID); !errors.Is(err, ErrNotFound) {
		t.Error("the session survived being deleted")
	}
	// Deleting an unknown session is not an error: signing out twice is fine.
	if err := s.DeleteAdminSession(ctx(), "never-existed"); err != nil {
		t.Errorf("deleting an unknown session returned %v, want nil", err)
	}
}

func TestAdminSessionIDsAreUnpredictable(t *testing.T) {
	s := openTemp(t)
	seen := map[string]bool{}
	for range 50 {
		sess, err := s.CreateAdminSession(ctx(), "sub", "google", "Ada", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if seen[sess.ID] {
			t.Fatalf("session id %q was issued twice", sess.ID)
		}
		seen[sess.ID] = true
	}
}

func TestAdminLoginIsSingleUse(t *testing.T) {
	s := openTemp(t)

	login, err := s.CreateAdminLogin(ctx(), "google", "verifier-value", "nonce-value", "/admin", time.Minute)
	if err != nil {
		t.Fatalf("CreateAdminLogin() error: %v", err)
	}
	if len(login.State) < 22 {
		t.Errorf("state %q is too short to protect against CSRF on the callback", login.State)
	}

	got, err := s.ConsumeAdminLogin(ctx(), login.State)
	if err != nil {
		t.Fatalf("ConsumeAdminLogin() error: %v", err)
	}
	if got.CodeVerifier != "verifier-value" || got.Nonce != "nonce-value" || got.Provider != "google" {
		t.Errorf("login = %+v, want the stored values", got)
	}

	// Replaying the callback must not work.
	if _, err := s.ConsumeAdminLogin(ctx(), login.State); !errors.Is(err, ErrNotFound) {
		t.Error("an OAuth callback state was consumed twice")
	}
}

func TestExpiredAdminLoginIsRejected(t *testing.T) {
	s := openTemp(t)
	start := time.Unix(2_000_000, 0)
	s.now = fixedClock(start)

	login, err := s.CreateAdminLogin(ctx(), "google", "v", "n", "/admin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	s.now = fixedClock(start.Add(2 * time.Minute))
	if _, err := s.ConsumeAdminLogin(ctx(), login.State); !errors.Is(err, ErrNotFound) {
		t.Error("an expired OAuth login was accepted")
	}
}

func TestPurgeExpiredClearsAdminState(t *testing.T) {
	s := openTemp(t)
	start := time.Unix(2_000_000, 0)
	s.now = fixedClock(start)

	if _, err := s.CreateAdminSession(ctx(), "sub", "google", "Ada", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdminLogin(ctx(), "google", "v", "n", "/admin", time.Minute); err != nil {
		t.Fatal(err)
	}

	s.now = fixedClock(start.Add(time.Hour))
	if err := s.PurgeExpired(ctx()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"admin_sessions", "admin_logins"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still holds %d expired rows", table, n)
		}
	}
}
