package store

import (
	"context"
	"errors"
	"os"
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

// The pragma is set in the DSN rather than with a one-off Exec precisely so it
// applies to every connection. Opening the same file twice yields two
// independent pools, which is what makes this a real test: a pragma applied
// only to the first connection of the first pool would not reach the second.
func TestForeignKeysEnforcedOnEveryNewConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clerk.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open() error: %v", err)
	}
	defer first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open() error: %v", err)
	}
	defer second.Close()

	appID := insertApp(t, first, "App A", "cid-a")

	for name, s := range map[string]*Store{"first": first, "second": second} {
		var on int
		if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
			t.Fatalf("%s connection: read pragma: %v", name, err)
		}
		if on != 1 {
			t.Errorf("%s connection: foreign_keys = %d, want 1", name, on)
		}
		if err := insertUser(t, s, 99999, "ghost-"+name, "sub-ghost-"+name); err == nil {
			t.Errorf("%s connection: accepted a user with a dangling application_id", name)
		}
	}

	// A valid insert must still work on the second handle.
	if err := insertUser(t, second, appID, "david", "sub-ok"); err != nil {
		t.Errorf("second connection rejected a valid insert: %v", err)
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

// SQLite opens the DSN with SQLITE_OPEN_URI, so it percent-decodes the path and
// treats "?" and "#" as delimiters. An unescaped path containing any of them
// would open a different file than asked for and silently drop the pragma list.
func TestOpenHandlesPathsNeedingEscaping(t *testing.T) {
	for _, name := range []string{
		"plain.db",
		"with space.db",
		"100%-full.db",
		"query?.db",
		"fragment#.db",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)

			s, err := Open(path)
			if err != nil {
				t.Fatalf("Open(%q) error: %v", path, err)
			}
			defer s.Close()

			// The database must land at exactly the requested path...
			if _, err := os.Stat(path); err != nil {
				t.Errorf("database was not created at the requested path: %v", err)
			}
			// ...and the pragmas must have survived the round trip. Open already
			// verifies these, so reaching here proves the query string arrived.
			insertApp(t, s, "App A", "cid-"+name)
			if err := insertUser(t, s, 99999, "ghost", "sub-ghost-"+name); err == nil {
				t.Error("foreign keys are off; the pragma list was lost in the DSN")
			}
		})
	}
}

// An upgrade must not strand a database that predates unique names: two
// applications could legitimately be called the same thing until then, and a
// failed migration stops Clerk from starting at all.
func TestUniqueNameMigrationReconcilesExistingDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clerk.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Put the database back the way it looked before the unique-name migration,
	// then fill it with rows that migration has to cope with.
	for _, stmt := range []string{
		`DROP INDEX idx_applications_name_unique`,
		`DELETE FROM schema_migrations WHERE name = '0006_unique_application_name.sql'`,
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES ('My App', 'c1', 'h')`,
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES ('my app', 'c2', 'h')`,
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES ('My  App ', 'c3', 'h')`,
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES ('Untouched', 'c4', 'h')`,
	} {
		if _, err := s.DB().Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening a database with duplicate names failed: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	apps, err := reopened.ListApplications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 4 {
		t.Fatalf("%d applications survived, want all 4", len(apps))
	}

	seen := make(map[string]string, len(apps))
	for _, app := range apps {
		key := strings.ToLower(app.Name)
		if other, clash := seen[key]; clash {
			t.Errorf("%q and %q are still indistinguishable", other, app.Name)
		}
		seen[key] = app.Name
		if app.Name != strings.Join(strings.Fields(app.Name), " ") {
			t.Errorf("name %q was not normalised", app.Name)
		}
	}

	// The name that was never a duplicate is left exactly as it was.
	if _, ok := seen["untouched"]; !ok {
		t.Error("an unaffected application was renamed")
	}

	// And the rule is in force from here on.
	if _, _, err := reopened.CreateApplication(context.Background(), "Untouched", nil); !errors.Is(err, ErrValidation) {
		t.Errorf("after the migration a duplicate name returned %v, want a validation error", err)
	}
}
