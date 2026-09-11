package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Ryback2501/Clerk/internal/secret"
)

const (
	// adminSessionIDBytes is the entropy behind a session cookie value.
	// Holding it is equivalent to being signed in.
	adminSessionIDBytes = 32

	// adminLoginStateBytes is the entropy behind the OAuth state parameter.
	adminLoginStateBytes = 32
)

// AdminSession is a signed-in administrator.
type AdminSession struct {
	ID        string
	Subject   string
	Provider  string
	Name      string
	ExpiresAt time.Time
}

// AdminLogin is an OAuth sign-in that has been started but not yet completed.
type AdminLogin struct {
	State        string
	Provider     string
	CodeVerifier string
	Nonce        string
	ReturnTo     string
	ExpiresAt    time.Time
}

// CreateAdminSession records a signed-in administrator.
func (s *Store) CreateAdminSession(ctx context.Context, subject, provider, name string, ttl time.Duration) (*AdminSession, error) {
	id, err := secret.Token(adminSessionIDBytes)
	if err != nil {
		return nil, err
	}

	now := s.now()
	sess := &AdminSession{
		ID: id, Subject: subject, Provider: provider, Name: name,
		ExpiresAt: now.Add(ttl),
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (id, subject, provider, name, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, subject, provider, name, sess.ExpiresAt.Unix(), now.Unix()); err != nil {
		return nil, fmt.Errorf("insert admin session: %w", err)
	}
	return sess, nil
}

// GetAdminSession loads a session, treating an expired one as absent.
func (s *Store) GetAdminSession(ctx context.Context, id string) (*AdminSession, error) {
	var sess AdminSession
	var expires int64

	err := s.db.QueryRowContext(ctx,
		`SELECT id, subject, provider, name, expires_at FROM admin_sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.Subject, &sess.Provider, &sess.Name, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load admin session: %w", err)
	}

	sess.ExpiresAt = time.Unix(expires, 0)
	if s.now().After(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &sess, nil
}

// DeleteAdminSession signs an administrator out. Deleting a session that is
// already gone is not an error.
func (s *Store) DeleteAdminSession(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

// CreateAdminLogin parks the state of an OAuth sign-in that is about to start.
func (s *Store) CreateAdminLogin(ctx context.Context, provider, verifier, nonce, returnTo string, ttl time.Duration) (*AdminLogin, error) {
	state, err := secret.Token(adminLoginStateBytes)
	if err != nil {
		return nil, err
	}

	now := s.now()
	login := &AdminLogin{
		State: state, Provider: provider, CodeVerifier: verifier,
		Nonce: nonce, ReturnTo: returnTo, ExpiresAt: now.Add(ttl),
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_logins (state, provider, code_verifier, nonce, return_to, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		login.State, provider, verifier, nonce, returnTo,
		login.ExpiresAt.Unix(), now.Unix()); err != nil {
		return nil, fmt.Errorf("insert admin login: %w", err)
	}
	return login, nil
}

// ConsumeAdminLogin resolves a callback's state exactly once, so the callback
// cannot be replayed.
func (s *Store) ConsumeAdminLogin(ctx context.Context, state string) (*AdminLogin, error) {
	var login AdminLogin
	var expires int64

	err := s.db.QueryRowContext(ctx,
		`SELECT state, provider, code_verifier, nonce, return_to, expires_at
		   FROM admin_logins WHERE state = ?`, state).
		Scan(&login.State, &login.Provider, &login.CodeVerifier, &login.Nonce,
			&login.ReturnTo, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load admin login: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_logins WHERE state = ?`, state)
	if err != nil {
		return nil, fmt.Errorf("consume admin login: %w", err)
	}
	if err := expectOneRow(res, "admin login"); err != nil {
		return nil, err
	}

	login.ExpiresAt = time.Unix(expires, 0)
	if s.now().After(login.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &login, nil
}
