package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Ryback2501/Clerk/internal/secret"
)

// Outcomes of presenting an authorization code, kept distinct because the
// token endpoint reacts differently to each.
var (
	// ErrCodeExpired means the code was valid but is past its lifetime.
	ErrCodeExpired = errors.New("authorization code expired")

	// ErrCodeReplayed means the code was already exchanged. This is a signal
	// worth acting on: it may mean the code was intercepted.
	ErrCodeReplayed = errors.New("authorization code already used")
)

const (
	// authRequestIDBytes is the entropy behind the handle the login form
	// carries. It must be unguessable: holding it is what lets a browser
	// complete someone's pending sign-in.
	authRequestIDBytes = 32

	// authCodeBytes is the entropy behind an authorization code.
	authCodeBytes = 32

	// accessTokenBytes is the entropy behind an access token.
	accessTokenBytes = 32
)

// AuthRequest is a validated authorization request parked while the user picks
// an identity.
type AuthRequest struct {
	ID                  string
	ApplicationID       int64
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// AuthCode is an issued authorization code, bound to the client, the user and
// the redirect URI it was issued for.
type AuthCode struct {
	ApplicationID       int64
	UserID              int64
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// CreateAuthRequest parks a validated request and returns it with its handle.
func (s *Store) CreateAuthRequest(ctx context.Context, req AuthRequest, ttl time.Duration) (*AuthRequest, error) {
	id, err := secret.Token(authRequestIDBytes)
	if err != nil {
		return nil, err
	}

	now := s.now()
	req.ID = id
	req.ExpiresAt = now.Add(ttl)

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests
		   (id, application_id, redirect_uri, state, nonce, scope,
		    code_challenge, code_challenge_method, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.ApplicationID, req.RedirectURI, req.State, req.Nonce, req.Scope,
		req.CodeChallenge, req.CodeChallengeMethod, req.ExpiresAt.Unix(), now.Unix()); err != nil {
		return nil, fmt.Errorf("insert authorization request: %w", err)
	}
	return &req, nil
}

// GetAuthRequest loads a parked request. An expired one is reported as absent:
// to every caller the two cases are the same.
func (s *Store) GetAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	var req AuthRequest
	var expires int64
	var state, nonce, challenge, method sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT id, application_id, redirect_uri, state, nonce, scope,
		        code_challenge, code_challenge_method, expires_at
		   FROM auth_requests WHERE id = ?`, id).
		Scan(&req.ID, &req.ApplicationID, &req.RedirectURI, &state, &nonce, &req.Scope,
			&challenge, &method, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load authorization request: %w", err)
	}

	req.State = state.String
	req.Nonce = nonce.String
	req.CodeChallenge = challenge.String
	req.CodeChallengeMethod = method.String
	req.ExpiresAt = time.Unix(expires, 0)

	if s.now().After(req.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &req, nil
}

// ConsumeAuthRequest loads a parked request and removes it, so one rendered
// login form can produce at most one authorization code.
func (s *Store) ConsumeAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	req, err := s.GetAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("consume authorization request: %w", err)
	}
	// Losing the delete race means another submission got there first.
	if err := expectOneRow(res, "authorization request"); err != nil {
		return nil, err
	}
	return req, nil
}

// IssueAuthCode mints an authorization code, returning the plaintext to send to
// the client. Only its hash is stored.
func (s *Store) IssueAuthCode(ctx context.Context, code AuthCode, ttl time.Duration) (string, *AuthCode, error) {
	plain, err := secret.Token(authCodeBytes)
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	code.ExpiresAt = now.Add(ttl)

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes
		   (code_hash, application_id, user_id, redirect_uri, nonce, scope,
		    code_challenge, code_challenge_method, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		secret.HashToken(plain), code.ApplicationID, code.UserID, code.RedirectURI,
		code.Nonce, code.Scope, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt.Unix(), now.Unix()); err != nil {
		return "", nil, fmt.Errorf("insert authorization code: %w", err)
	}
	return plain, &code, nil
}

// ConsumeAuthCode exchanges a code exactly once.
//
// A code that was already used returns ErrCodeReplayed rather than "not
// found": the row is kept until it expires precisely so a replay is
// recognisable, which deleting on first use would make impossible.
func (s *Store) ConsumeAuthCode(ctx context.Context, plain string) (*AuthCode, error) {
	hash := secret.HashToken(plain)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var code AuthCode
	var expires int64
	var consumed sql.NullInt64
	var nonce, challenge, method sql.NullString

	err = tx.QueryRowContext(ctx,
		`SELECT application_id, user_id, redirect_uri, nonce, scope,
		        code_challenge, code_challenge_method, expires_at, consumed_at
		   FROM auth_codes WHERE code_hash = ?`, hash).
		Scan(&code.ApplicationID, &code.UserID, &code.RedirectURI, &nonce, &code.Scope,
			&challenge, &method, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load authorization code: %w", err)
	}

	if consumed.Valid {
		return nil, ErrCodeReplayed
	}

	code.Nonce = nonce.String
	code.CodeChallenge = challenge.String
	code.CodeChallengeMethod = method.String
	code.ExpiresAt = time.Unix(expires, 0)

	now := s.now()
	if now.After(code.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	// Marking and reading share the transaction, so two simultaneous exchanges
	// cannot both succeed.
	res, err := tx.ExecContext(ctx,
		`UPDATE auth_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL`,
		now.Unix(), hash)
	if err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	if n == 0 {
		return nil, ErrCodeReplayed
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &code, nil
}

// AccessToken is an issued bearer token, resolved back to the client and user
// it was minted for.
type AccessToken struct {
	ApplicationID int64
	UserID        int64
	Scope         string
	ExpiresAt     time.Time
}

// IssueAccessToken mints a token and returns the plaintext. Only its hash is
// stored.
//
// authCode is the plaintext authorization code this token was issued for, so a
// later replay of that code can revoke it. It may be empty for tokens that did
// not come from a code exchange.
func (s *Store) IssueAccessToken(ctx context.Context, appID, userID int64, scope, authCode string, ttl time.Duration) (string, error) {
	plain, err := secret.Token(accessTokenBytes)
	if err != nil {
		return "", err
	}

	var codeHash any
	if authCode != "" {
		codeHash = secret.HashToken(authCode)
	}

	now := s.now()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO access_tokens
		   (token_hash, application_id, user_id, scope, auth_code_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		secret.HashToken(plain), appID, userID, scope, codeHash,
		now.Add(ttl).Unix(), now.Unix()); err != nil {
		return "", fmt.Errorf("insert access token: %w", err)
	}
	return plain, nil
}

// RevokeTokensIssuedForCode deletes every access token minted from the given
// authorization code, and reports how many were removed.
//
// This is the response to a detected replay: the first redemption may have
// been the attacker's, so what it produced must not stay valid.
func (s *Store) RevokeTokensIssuedForCode(ctx context.Context, authCode string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM access_tokens WHERE auth_code_hash = ?`, secret.HashToken(authCode))
	if err != nil {
		return 0, fmt.Errorf("revoke tokens for authorization code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke tokens for authorization code: %w", err)
	}
	return n, nil
}

// LookupAccessToken resolves a bearer token. An expired one is reported as
// absent: to a caller presenting it, the two are the same.
func (s *Store) LookupAccessToken(ctx context.Context, plain string) (*AccessToken, error) {
	var tok AccessToken
	var expires int64

	err := s.db.QueryRowContext(ctx,
		`SELECT application_id, user_id, scope, expires_at
		   FROM access_tokens WHERE token_hash = ?`, secret.HashToken(plain)).
		Scan(&tok.ApplicationID, &tok.UserID, &tok.Scope, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load access token: %w", err)
	}

	tok.ExpiresAt = time.Unix(expires, 0)
	if s.now().After(tok.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &tok, nil
}

// PurgeExpired drops authorization state that is past its lifetime. Consumed
// codes are kept until they expire so that a replay is still detectable.
func (s *Store) PurgeExpired(ctx context.Context) error {
	cutoff := s.now().Unix()
	for _, stmt := range []string{
		`DELETE FROM auth_requests WHERE expires_at < ?`,
		`DELETE FROM auth_codes WHERE expires_at < ?`,
		`DELETE FROM access_tokens WHERE expires_at < ?`,
		`DELETE FROM admin_sessions WHERE expires_at < ?`,
		`DELETE FROM admin_logins WHERE expires_at < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt, cutoff); err != nil {
			return fmt.Errorf("purge expired authorization state: %w", err)
		}
	}
	return nil
}
