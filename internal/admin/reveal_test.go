package admin

import (
	"testing"
	"time"
)

// A client secret is shown exactly once. Holding it briefly in memory keeps it
// out of the URL, the database and the logs, and consuming it on read means a
// refresh cannot show it again.
func TestRevealStoreReturnsASecretExactlyOnce(t *testing.T) {
	s := newRevealStore()

	token := s.put(7, "super-secret")
	if token == "" {
		t.Fatal("put() returned an empty token")
	}

	got, ok := s.take(token, 7)
	if !ok || got != "super-secret" {
		t.Fatalf("take() = (%q, %v), want the stored secret", got, ok)
	}
	if _, ok := s.take(token, 7); ok {
		t.Error("take() returned the secret a second time; it must be single-use")
	}
}

func TestRevealStoreRejectsUnknownTokens(t *testing.T) {
	s := newRevealStore()
	if _, ok := s.take("never-issued", 1); ok {
		t.Error("take() accepted a token that was never issued")
	}
	if _, ok := s.take("", 1); ok {
		t.Error("take() accepted an empty token")
	}
}

// A secret left unread must not linger in memory indefinitely.
func TestRevealStoreExpiresSecrets(t *testing.T) {
	s := newRevealStore()
	s.now = func() time.Time { return time.Unix(1000, 0) }

	token := s.put(1, "super-secret")

	s.now = func() time.Time { return time.Unix(1000, 0).Add(revealTTL + time.Second) }
	if _, ok := s.take(token, 1); ok {
		t.Error("take() returned an expired secret")
	}
}

func TestRevealStoreIssuesDistinctTokens(t *testing.T) {
	s := newRevealStore()
	seen := map[string]bool{}
	for range 100 {
		tok := s.put(1, "x")
		if seen[tok] {
			t.Fatalf("put() reused token %q", tok)
		}
		seen[tok] = true
	}
}

// A secret belongs to the application it was generated for. Without this,
// creating application A and then navigating to application B would display
// A's secret under B's heading — and consume it, so it could never be shown
// where it belonged.
func TestRevealStoreBindsTheSecretToItsApplication(t *testing.T) {
	s := newRevealStore()
	token := s.put(1, "secret-for-app-1")

	if _, ok := s.take(token, 2); ok {
		t.Error("take() released a secret to a different application")
	}
	// A mismatch must not consume it either.
	got, ok := s.take(token, 1)
	if !ok || got != "secret-for-app-1" {
		t.Error("a mismatched lookup destroyed the secret for its real application")
	}
}
