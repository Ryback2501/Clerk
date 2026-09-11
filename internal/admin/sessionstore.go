package admin

import (
	"context"
	"time"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
)

// SessionStore adapts the database to the persistence adminauth needs.
//
// The adapter exists so internal/adminauth does not import internal/store: it
// is the boundary that keeps the authorization machinery independent of how
// this provider happens to persist things.
type SessionStore struct{ db *store.Store }

// NewSessionStore wraps a database for use by the OAuth authenticator.
func NewSessionStore(db *store.Store) *SessionStore { return &SessionStore{db: db} }

func (s *SessionStore) CreateAdminLogin(ctx context.Context, provider, verifier, nonce, returnTo string, ttl time.Duration) (*adminauth.StoredLogin, error) {
	login, err := s.db.CreateAdminLogin(ctx, provider, verifier, nonce, returnTo, ttl)
	if err != nil {
		return nil, err
	}
	return &adminauth.StoredLogin{
		State:        login.State,
		Provider:     login.Provider,
		CodeVerifier: login.CodeVerifier,
		Nonce:        login.Nonce,
		ReturnTo:     login.ReturnTo,
	}, nil
}

func (s *SessionStore) ConsumeAdminLogin(ctx context.Context, state string) (*adminauth.StoredLogin, error) {
	login, err := s.db.ConsumeAdminLogin(ctx, state)
	if err != nil {
		return nil, err
	}
	return &adminauth.StoredLogin{
		State:        login.State,
		Provider:     login.Provider,
		CodeVerifier: login.CodeVerifier,
		Nonce:        login.Nonce,
		ReturnTo:     login.ReturnTo,
	}, nil
}

func (s *SessionStore) CreateAdminSession(ctx context.Context, subject, provider, name string, ttl time.Duration) (*adminauth.StoredSession, error) {
	sess, err := s.db.CreateAdminSession(ctx, subject, provider, name, ttl)
	if err != nil {
		return nil, err
	}
	return &adminauth.StoredSession{ID: sess.ID, Subject: sess.Subject, Provider: sess.Provider, Name: sess.Name}, nil
}

func (s *SessionStore) GetAdminSession(ctx context.Context, id string) (*adminauth.StoredSession, error) {
	sess, err := s.db.GetAdminSession(ctx, id)
	if err != nil {
		return nil, err
	}
	return &adminauth.StoredSession{ID: sess.ID, Subject: sess.Subject, Provider: sess.Provider, Name: sess.Name}, nil
}

func (s *SessionStore) DeleteAdminSession(ctx context.Context, id string) error {
	return s.db.DeleteAdminSession(ctx, id)
}
