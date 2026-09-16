package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Ryback2501/Clerk/internal/secret"
)

const (
	// subBytes is the entropy behind a subject identifier: 128 bits, which
	// makes a collision across the lifetime of any test instance negligible.
	subBytes = 16

	// maxUsernameLength bounds what an administrator can type. It is generous
	// for a display name and keeps a single row from growing unreasonably.
	maxUsernameLength = 200
)

// User is a test identity belonging to exactly one application.
//
// The model is deliberately minimal: no password, no email, no groups. Signing
// in as this user means selecting it from a list.
type User struct {
	ID            int64
	ApplicationID int64

	// Username is the user-visible name, unique only within its application.
	Username string

	// Sub is the OIDC subject identifier: opaque, globally unique, and stable
	// for the lifetime of this user. It is generated randomly, so it reveals
	// neither the username nor the internal row id.
	Sub string

	CreatedAt string
}

// CreateUser adds a test identity to an application, assigning it a fresh
// subject identifier.
func (s *Store) CreateUser(ctx context.Context, appID int64, username string) (*User, error) {
	username = strings.TrimSpace(username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}

	// The application must exist. Checking explicitly turns a foreign-key
	// violation into a message that says what is actually wrong.
	if _, err := s.GetApplication(ctx, appID); err != nil {
		return nil, err
	}

	sub, err := secret.Token(subBytes)
	if err != nil {
		return nil, err
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (application_id, username, sub) VALUES (?, ?, ?)`,
		appID, username, sub)
	if err != nil {
		// Only a duplicate name is the administrator's to fix. A sub collision
		// would be a 128-bit coincidence and is a fault, not a validation
		// failure — reporting it as "that name is taken" would send them
		// chasing a problem that does not exist.
		if isDuplicateUsername(err) {
			return nil, invalidf("a user named %q already exists in this application", username)
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read new user id: %w", err)
	}
	return s.GetUser(ctx, id)
}

// ListUsers returns an application's test identities, ordered by name.
func (s *Store) ListUsers(ctx context.Context, appID int64) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, application_id, username, sub, created_at
		   FROM users
		  WHERE application_id = ?
		  ORDER BY username COLLATE NOCASE, id`, appID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.ApplicationID, &u.Username, &u.Sub, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// GetUser loads one test identity by internal id.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return s.getUser(ctx,
		`SELECT id, application_id, username, sub, created_at FROM users WHERE id = ?`, id)
}

// GetUserBySub loads one test identity by subject identifier. This is the
// lookup the UserInfo endpoint uses.
func (s *Store) GetUserBySub(ctx context.Context, sub string) (*User, error) {
	return s.getUser(ctx,
		`SELECT id, application_id, username, sub, created_at FROM users WHERE sub = ?`, sub)
}

func (s *Store) getUser(ctx context.Context, query string, arg any) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, query, arg).
		Scan(&u.ID, &u.ApplicationID, &u.Username, &u.Sub, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return &u, nil
}

// RenameUser changes a test identity's display name. Its sub is deliberately
// left alone: that is the identifier already issued in ID tokens and stored by
// the client, so renaming must not be the same thing as deleting the user and
// creating a replacement.
func (s *Store) RenameUser(ctx context.Context, id int64, username string) error {
	// Checking first turns an unknown id into ErrNotFound rather than a silent
	// no-op, and reports it before any validation message.
	if _, err := s.GetUser(ctx, id); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	if err := validateUsername(username); err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET username = ? WHERE id = ?`, username, id)
	if err != nil {
		if isDuplicateUsername(err) {
			return invalidf("a user named %q already exists in this application", username)
		}
		return fmt.Errorf("rename user: %w", err)
	}
	return expectOneRow(res, "user")
}

// DeleteUser removes one test identity. It affects nothing else: not the
// application, not any other user.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return expectOneRow(res, "user")
}

// validateUsername keeps the name displayable and loggable. Control characters
// are rejected rather than escaped: they have no legitimate use in a test
// identity and would corrupt log lines and the login dropdown.
func validateUsername(username string) error {
	switch {
	case username == "":
		return invalidf("user name must not be empty")
	case utf8.RuneCountInString(username) > maxUsernameLength:
		return invalidf("user name must be at most %d characters", maxUsernameLength)
	case !utf8.ValidString(username):
		return invalidf("user name must be valid UTF-8")
	}

	for _, r := range username {
		if unicode.IsControl(r) {
			return invalidf("user name must not contain control characters")
		}
	}
	return nil
}

// isDuplicateUsername reports whether err is the uniqueness failure caused by
// reusing a name within one application, as opposed to any other constraint.
//
// The driver exports no typed error, so the message is the only signal
// available; it names the columns, which is what makes the two cases
// separable.
func isDuplicateUsername(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") &&
		strings.Contains(msg, "users.username")
}
