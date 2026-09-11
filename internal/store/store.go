// Package store owns Clerk's SQLite database: connection setup, schema
// migrations, and the invariants the schema enforces.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	// Registers the pure-Go "sqlite" driver, so the binary needs no cgo and can
	// run on a distroless base image.
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store is a handle to the database and the migrations applied to it.
type Store struct {
	db *sql.DB
}

// Open connects to the SQLite database at path, creating the file and any
// missing parent directories, then applies outstanding migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite permits a single writer. Serialising access here trades a little
	// concurrency for the absence of SQLITE_BUSY under load, which is the right
	// call for a tool whose whole database is a handful of small tables.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.verifyPragmas(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return s, nil
}

// dsn builds the connection string. The pragmas are set per connection via the
// DSN rather than with a one-off Exec, because database/sql pools connections
// and a pragma applied to one of them would not protect the others.
func dsn(path string) string {
	q := url.Values{}
	// Foreign keys are OFF by default in SQLite; the cascade from applications
	// to users and redirect URIs depends entirely on this.
	q.Add("_pragma", "foreign_keys(1)")
	// WAL gives readers concurrency with the single writer.
	q.Add("_pragma", "journal_mode(WAL)")
	// Wait rather than failing immediately if the writer is briefly busy.
	q.Add("_pragma", "busy_timeout(5000)")
	return "file:" + path + "?" + q.Encode()
}

// verifyPragmas confirms the DSN actually took effect, so a driver change can
// never silently disable the guarantees the schema relies on.
func (s *Store) verifyPragmas() error {
	var foreignKeys int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return fmt.Errorf("read foreign_keys pragma: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("foreign_keys pragma is %d, want 1: cascade deletion would silently not happen", foreignKeys)
	}
	return nil
}

// DB exposes the underlying handle for queries.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// migrate applies every embedded migration that has not run yet, in filename
// order, each inside its own transaction.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		var applied int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}
		if err := s.applyMigration(name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(name string) error {
	body, err := migrationFS.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(string(body)); err != nil {
		return fmt.Errorf("run migration %s: %w", name, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}

func migrationNames() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	// Filenames are zero-padded, so lexical order is application order.
	sort.Strings(names)
	return names, nil
}
