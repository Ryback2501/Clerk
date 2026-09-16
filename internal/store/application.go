package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Ryback2501/Clerk/internal/secret"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when a row would violate a uniqueness rule.
var ErrDuplicate = errors.New("already exists")

// ErrValidation marks an error caused by what the caller supplied, as opposed
// to a failure of the database or the runtime. Callers use it to decide between
// showing the message to the administrator and logging it as an internal fault.
var ErrValidation = errors.New("invalid input")

// invalidf builds a validation error carrying ErrValidation.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrValidation}, args...)...)
}

// Application is an OIDC client registered with this provider.
//
// It deliberately carries no secret material: the client secret exists in
// plaintext only in the response to its own creation or regeneration, and only
// its hash is ever stored.
type Application struct {
	ID           int64
	Name         string
	ClientID     string
	CreatedAt    string
	RedirectURIs []string
}

// CreateApplication registers a new client, generating its credentials. The
// returned string is the plaintext client secret, which the caller must show to
// the administrator once and then discard: it cannot be recovered afterwards.
func (s *Store) CreateApplication(ctx context.Context, name string, redirectURIs []string) (*Application, string, error) {
	name, err := s.claimName(ctx, name, 0)
	if err != nil {
		return nil, "", err
	}
	for _, uri := range redirectURIs {
		if err := ValidateRedirectURI(uri); err != nil {
			return nil, "", err
		}
	}
	// The same URI listed twice is a typo, not a reason to reject the whole
	// registration on a uniqueness constraint.
	redirectURIs = dedupe(redirectURIs)

	clientID, err := secret.NewClientID()
	if err != nil {
		return nil, "", err
	}
	plainSecret, err := secret.NewClientSecret()
	if err != nil {
		return nil, "", err
	}
	hash, err := secret.HashSecret(plainSecret)
	if err != nil {
		return nil, "", err
	}

	// One transaction, so a rejected redirect URI cannot leave a half-built
	// application behind.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO applications (name, client_id, client_secret_hash) VALUES (?, ?, ?)`,
		name, clientID, hash)
	if err != nil {
		// Two administrators registering the same name at once both pass the
		// check above; the index is what actually decides, so its refusal is
		// reported as the same validation failure rather than as a fault.
		if isDuplicateApplicationName(err) {
			return nil, "", duplicateNameError(name)
		}
		return nil, "", fmt.Errorf("insert application: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, "", fmt.Errorf("read new application id: %w", err)
	}

	for _, uri := range redirectURIs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO redirect_uris (application_id, uri) VALUES (?, ?)`, id, uri); err != nil {
			return nil, "", fmt.Errorf("insert redirect uri %q: %w", uri, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit: %w", err)
	}

	app, err := s.GetApplication(ctx, id)
	if err != nil {
		return nil, "", err
	}
	return app, plainSecret, nil
}

// normalizeName trims an application name and collapses inner runs of
// whitespace, so names that read identically are stored identically.
func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }

func duplicateNameError(name string) error {
	return invalidf("an application named %q already exists", name)
}

// NameIsAvailable reports whether an application may be given this name.
// excludeID is the application being renamed, which never collides with itself;
// pass 0 when registering a new one.
func (s *Store) NameIsAvailable(ctx context.Context, name string, excludeID int64) (bool, error) {
	name = normalizeName(name)
	if name == "" {
		return false, nil
	}

	var taken bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM applications WHERE lower(name) = lower(?) AND id <> ?)`,
		name, excludeID).Scan(&taken)
	if err != nil {
		return false, fmt.Errorf("check application name: %w", err)
	}
	return !taken, nil
}

// claimName validates a name for the application identified by excludeID (0
// when it does not exist yet) and returns it normalised.
func (s *Store) claimName(ctx context.Context, name string, excludeID int64) (string, error) {
	name = normalizeName(name)
	if name == "" {
		return "", invalidf("application name must not be empty")
	}

	free, err := s.NameIsAvailable(ctx, name, excludeID)
	if err != nil {
		return "", err
	}
	if !free {
		return "", duplicateNameError(name)
	}
	return name, nil
}

// RenameApplication changes only the label an administrator sees. The client
// id, secret, redirect URIs and users are untouched, so a client configured
// against this application keeps working.
func (s *Store) RenameApplication(ctx context.Context, appID int64, name string) error {
	if _, err := s.GetApplication(ctx, appID); err != nil {
		return err
	}

	name, err := s.claimName(ctx, name, appID)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `UPDATE applications SET name = ? WHERE id = ?`, name, appID)
	if err != nil {
		if isDuplicateApplicationName(err) {
			return duplicateNameError(name)
		}
		return fmt.Errorf("rename application: %w", err)
	}
	return expectOneRow(res, "application")
}

// isDuplicateApplicationName reports whether err is the unique-name index
// refusing a row, as opposed to any other constraint. The driver exports no
// typed error, so the message naming the index is the only signal available.
func isDuplicateApplicationName(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") &&
		strings.Contains(msg, "idx_applications_name_unique")
}

// ListApplications returns every registered client, ordered by name.
func (s *Store) ListApplications(ctx context.Context) ([]*Application, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, client_id, created_at FROM applications ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var apps []*Application
	for rows.Next() {
		var a Application
		if err := rows.Scan(&a.ID, &a.Name, &a.ClientID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		apps = append(apps, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	return apps, nil
}

// GetApplication loads one client and its redirect URIs by internal id.
func (s *Store) GetApplication(ctx context.Context, id int64) (*Application, error) {
	return s.getApplication(ctx,
		`SELECT id, name, client_id, created_at FROM applications WHERE id = ?`, id)
}

// GetApplicationByClientID loads one client by the identifier it authenticates
// with. This is the lookup the authorization and token endpoints use.
func (s *Store) GetApplicationByClientID(ctx context.Context, clientID string) (*Application, error) {
	return s.getApplication(ctx,
		`SELECT id, name, client_id, created_at FROM applications WHERE client_id = ?`, clientID)
}

func (s *Store) getApplication(ctx context.Context, query string, arg any) (*Application, error) {
	var a Application
	err := s.db.QueryRowContext(ctx, query, arg).Scan(&a.ID, &a.Name, &a.ClientID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load application: %w", err)
	}

	uris, err := s.redirectURIs(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	a.RedirectURIs = uris
	return &a, nil
}

func (s *Store) redirectURIs(ctx context.Context, appID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uri FROM redirect_uris WHERE application_id = ? ORDER BY id`, appID)
	if err != nil {
		return nil, fmt.Errorf("load redirect uris: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, fmt.Errorf("scan redirect uri: %w", err)
		}
		uris = append(uris, uri)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load redirect uris: %w", err)
	}
	return uris, nil
}

// VerifyClientSecret reports whether plain is the current secret of the client.
func (s *Store) VerifyClientSecret(ctx context.Context, appID int64, plain string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT client_secret_hash FROM applications WHERE id = ?`, appID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("load client secret hash: %w", err)
	}
	return secret.VerifySecret(hash, plain), nil
}

// RegenerateClientSecret issues a new secret and invalidates the previous one.
// The client id is left untouched, so existing client configuration keeps
// working once the new secret is deployed.
func (s *Store) RegenerateClientSecret(ctx context.Context, appID int64) (string, error) {
	plain, err := secret.NewClientSecret()
	if err != nil {
		return "", err
	}
	hash, err := secret.HashSecret(plain)
	if err != nil {
		return "", err
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE applications SET client_secret_hash = ? WHERE id = ?`, hash, appID)
	if err != nil {
		return "", fmt.Errorf("update client secret: %w", err)
	}
	if err := expectOneRow(res, "application"); err != nil {
		return "", err
	}
	return plain, nil
}

// AddRedirectURI registers an additional redirect URI for a client.
func (s *Store) AddRedirectURI(ctx context.Context, appID int64, uri string) error {
	if err := ValidateRedirectURI(uri); err != nil {
		return err
	}
	if _, err := s.GetApplication(ctx, appID); err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO redirect_uris (application_id, uri) VALUES (?, ?)`, appID, uri)
	if err != nil {
		return fmt.Errorf("insert redirect uri: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert redirect uri: %w", err)
	}
	if n == 0 {
		return invalidf("redirect uri %q is already registered", uri)
	}
	return nil
}

// CountUsers reports how many test users belong to an application. It lives
// here so that knowledge of the users table stays in one package.
func (s *Store) CountUsers(ctx context.Context, appID int64) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE application_id = ?`, appID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// dedupe removes repeated entries while preserving the order given.
func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0:0]
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// RemoveRedirectURI unregisters a redirect URI from a client.
func (s *Store) RemoveRedirectURI(ctx context.Context, appID int64, uri string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM redirect_uris WHERE application_id = ? AND uri = ?`, appID, uri)
	if err != nil {
		return fmt.Errorf("delete redirect uri: %w", err)
	}
	return expectOneRow(res, "redirect uri")
}

// DeleteApplication removes a client and, by cascade, every user and redirect
// URI belonging to it.
func (s *Store) DeleteApplication(ctx context.Context, appID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM applications WHERE id = ?`, appID)
	if err != nil {
		return fmt.Errorf("delete application: %w", err)
	}
	return expectOneRow(res, "application")
}

func expectOneRow(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	return nil
}

// ValidateRedirectURI enforces the shape a redirect target must have. OIDC
// requires an absolute URI, and the fragment component is reserved for the
// response itself, so a registered value may not carry one. Validation happens
// at registration so that authorization-time matching can stay exact and
// simple.
func ValidateRedirectURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return invalidf("redirect uri must not be empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return invalidf("redirect uri %q is not a valid URL: %s", raw, err)
	}
	switch {
	case !u.IsAbs():
		return invalidf("redirect uri %q must be absolute", raw)
	case u.Scheme != "http" && u.Scheme != "https":
		return invalidf("redirect uri %q must use http or https, got %q", raw, u.Scheme)
	case u.Host == "":
		return invalidf("redirect uri %q must include a host", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return invalidf("redirect uri %q must not contain a fragment", raw)
	}
	return nil
}
