package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "nested", "clerk.db"))
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Helpers that insert directly, so the schema is exercised before any repository
// code exists.
func insertApp(t *testing.T, s *Store, name, clientID string) int64 {
	t.Helper()
	res, err := s.DB().ExecContext(context.Background(),
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES (?, ?, 'x')`, name, clientID)
	if err != nil {
		t.Fatalf("insert application %q: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func insertUser(t *testing.T, s *Store, appID int64, username, sub string) error {
	t.Helper()
	_, err := s.DB().ExecContext(context.Background(),
		`INSERT INTO users (application_id, username, sub) VALUES (?, ?, ?)`, appID, username, sub)
	return err
}

func TestOpenCreatesDatabaseAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "clerk.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open() error: %v", err)
	}
	appID := insertApp(t, first, "App A", "cid-a")
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Re-opening must re-run migrations harmlessly and preserve existing data.
	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open() error: %v", err)
	}
	defer second.Close()

	var name string
	if err := second.DB().QueryRow(`SELECT name FROM applications WHERE id = ?`, appID).Scan(&name); err != nil {
		t.Fatalf("data did not survive reopen: %v", err)
	}
	if name != "App A" {
		t.Errorf("name = %q, want %q", name, "App A")
	}
}

// SQLite disables foreign keys by default, and the whole cascade-delete
// requirement depends on them being on for every pooled connection.
func TestForeignKeysAreEnforced(t *testing.T) {
	s := openTemp(t)

	if err := insertUser(t, s, 99999, "ghost", "sub-ghost"); err == nil {
		t.Fatal("inserted a user referencing a non-existent application; foreign keys are OFF")
	}
}

func TestForeignKeysEnforcedOnEveryPooledConnection(t *testing.T) {
	s := openTemp(t)

	// Force the pool to hand out several distinct connections; a pragma applied
	// to only the first would let later writes slip through unchecked.
	for i := 0; i < 5; i++ {
		var on int
		if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
			t.Fatalf("read pragma: %v", err)
		}
		if on != 1 {
			t.Fatalf("foreign_keys = %d on pooled connection %d, want 1", on, i)
		}
	}
}

// Acceptance criteria 27 and 28.
func TestDeletingApplicationCascadesToUsersAndRedirectURIs(t *testing.T) {
	s := openTemp(t)
	appID := insertApp(t, s, "App A", "cid-a")
	keepID := insertApp(t, s, "App B", "cid-b")

	if err := insertUser(t, s, appID, "david", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(t, s, keepID, "david", "sub-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO redirect_uris (application_id, uri) VALUES (?, ?)`,
		appID, "https://a.example.com/cb"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB().Exec(`DELETE FROM applications WHERE id = ?`, appID); err != nil {
		t.Fatalf("delete application: %v", err)
	}

	for _, c := range []struct {
		name  string
		query string
	}{
		{"users of the deleted application", `SELECT COUNT(*) FROM users WHERE application_id = ?`},
		{"redirect URIs of the deleted application", `SELECT COUNT(*) FROM redirect_uris WHERE application_id = ?`},
	} {
		var n int
		if err := s.DB().QueryRow(c.query, appID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows remain, want 0", c.name, n)
		}
	}

	// Deleting one application must not touch another's users.
	var survivors int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE application_id = ?`, keepID).Scan(&survivors); err != nil {
		t.Fatal(err)
	}
	if survivors != 1 {
		t.Errorf("other application has %d users, want 1", survivors)
	}
}

// Acceptance criterion 9.
func TestDuplicateUsernameWithinAnApplicationIsRejected(t *testing.T) {
	s := openTemp(t)
	appID := insertApp(t, s, "App A", "cid-a")

	if err := insertUser(t, s, appID, "david", "sub-1"); err != nil {
		t.Fatal(err)
	}
	err := insertUser(t, s, appID, "david", "sub-2")
	if err == nil {
		t.Fatal("duplicate username within one application was accepted")
	}
	if !strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
		t.Errorf("error = %v, want a uniqueness violation", err)
	}
}

// Acceptance criterion 10.
func TestSameUsernameInDifferentApplicationsIsAllowed(t *testing.T) {
	s := openTemp(t)
	a := insertApp(t, s, "App A", "cid-a")
	b := insertApp(t, s, "App B", "cid-b")

	if err := insertUser(t, s, a, "david", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(t, s, b, "david", "sub-2"); err != nil {
		t.Fatalf("same username in a different application was rejected: %v", err)
	}
}

// Acceptance criterion 11: sub must be globally unique across the whole IdP.
func TestSubIsGloballyUnique(t *testing.T) {
	s := openTemp(t)
	a := insertApp(t, s, "App A", "cid-a")
	b := insertApp(t, s, "App B", "cid-b")

	if err := insertUser(t, s, a, "david", "shared-sub"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(t, s, b, "alice", "shared-sub"); err == nil {
		t.Fatal("the same sub was accepted for two different users")
	}
}

func TestClientIDIsUnique(t *testing.T) {
	s := openTemp(t)
	insertApp(t, s, "App A", "cid-shared")

	_, err := s.DB().Exec(
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES (?, ?, 'x')`,
		"App B", "cid-shared")
	if err == nil {
		t.Fatal("duplicate client_id was accepted")
	}
}

func TestRedirectURIIsUniquePerApplication(t *testing.T) {
	s := openTemp(t)
	appID := insertApp(t, s, "App A", "cid-a")

	const uri = "https://a.example.com/cb"
	if _, err := s.DB().Exec(`INSERT INTO redirect_uris (application_id, uri) VALUES (?, ?)`, appID, uri); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO redirect_uris (application_id, uri) VALUES (?, ?)`, appID, uri); err == nil {
		t.Fatal("the same redirect URI was registered twice for one application")
	}
}
