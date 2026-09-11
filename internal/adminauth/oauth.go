package adminauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Ryback2501/Clerk/internal/secret"
)

const (
	// SessionCookieName holds the admin session id.
	SessionCookieName = "clerk_admin_session"

	// DefaultSessionTTL is how long a sign-in lasts.
	DefaultSessionTTL = 12 * time.Hour

	// loginTTL bounds how long a started sign-in may take to come back.
	loginTTL = 10 * time.Minute

	// verifierBytes is the entropy behind the PKCE verifier Clerk sends
	// upstream. Clerk is a confidential client there, but PKCE also binds the
	// callback to the request that started it.
	verifierBytes = 32
)

// SessionStore is the persistence the OAuth authenticator needs. It is an
// interface so this package does not depend on the whole store.
type SessionStore interface {
	CreateAdminLogin(ctx context.Context, provider, verifier, nonce, returnTo string, ttl time.Duration) (*StoredLogin, error)
	ConsumeAdminLogin(ctx context.Context, state string) (*StoredLogin, error)
	CreateAdminSession(ctx context.Context, subject, provider, name string, ttl time.Duration) (*StoredSession, error)
	GetAdminSession(ctx context.Context, id string) (*StoredSession, error)
	DeleteAdminSession(ctx context.Context, id string) error
}

// StoredLogin and StoredSession mirror the store's rows.
type StoredLogin struct {
	State        string
	Provider     string
	CodeVerifier string
	Nonce        string
	ReturnTo     string
}

// StoredSession is a persisted sign-in.
type StoredSession struct {
	ID       string
	Subject  string
	Provider string
	Name     string
}

// Authorizer decides whether an identity may administer this provider.
type Authorizer interface {
	Authorize(ctx context.Context, identity Identity) error
}

// OAuthConfig configures the real authenticator.
type OAuthConfig struct {
	// PublicURL is the origin browsers reach Clerk at, used to build callbacks.
	PublicURL *url.URL

	// Providers maps a provider name to its client credentials. Only the ones
	// present here are offered.
	Providers map[string]ClientCredentials

	// Store persists sessions and in-flight sign-ins.
	Store SessionStore

	// Authorizer is consulted after a successful sign-in.
	Authorizer Authorizer

	// SessionTTL defaults to DefaultSessionTTL.
	SessionTTL time.Duration

	// HTTPClient is for tests and for reaching providers through a proxy.
	HTTPClient *http.Client
}

// ClientCredentials are one provider's OAuth application credentials.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

// OAuth signs administrators in with an external provider and then asks the
// Authorizer whether they may proceed.
type OAuth struct {
	publicURL  *url.URL
	store      SessionStore
	authorizer Authorizer
	sessionTTL time.Duration
	httpClient *http.Client

	// configured holds one ready provider per enabled name.
	configured map[string]*configuredProvider
}

// configuredProvider is a provider with its credentials and, where it has one,
// its discovered OIDC endpoints resolved.
type configuredProvider struct {
	kind     ProviderKind
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOAuth builds the authenticator, discovering each OIDC provider's
// endpoints up front so a misconfiguration surfaces at startup.
func NewOAuth(ctx context.Context, cfg OAuthConfig) (*OAuth, error) {
	switch {
	case cfg.PublicURL == nil:
		return nil, errors.New("adminauth: a public URL is required to build OAuth callbacks")
	case cfg.Store == nil:
		return nil, errors.New("adminauth: a session store is required")
	case cfg.Authorizer == nil:
		return nil, errors.New("adminauth: an authorizer is required")
	case len(cfg.Providers) == 0:
		return nil, errors.New("adminauth: at least one OAuth provider must be configured, or nobody can sign in")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, client)

	a := &OAuth{
		publicURL:  cfg.PublicURL,
		store:      cfg.Store,
		authorizer: cfg.Authorizer,
		sessionTTL: cfg.SessionTTL,
		httpClient: client,
		configured: make(map[string]*configuredProvider, len(cfg.Providers)),
	}
	if a.sessionTTL == 0 {
		a.sessionTTL = DefaultSessionTTL
	}

	for name, creds := range cfg.Providers {
		kind, ok := SupportedProviders[name]
		if !ok {
			return nil, fmt.Errorf("adminauth: unknown provider %q; supported: %s",
				name, strings.Join(ProviderNames(), ", "))
		}
		if creds.ClientID == "" || creds.ClientSecret == "" {
			return nil, fmt.Errorf("adminauth: provider %q needs both a client id and a client secret", name)
		}

		built, err := a.configure(ctx, kind, creds)
		if err != nil {
			return nil, err
		}
		a.configured[name] = built
	}
	return a, nil
}

func (a *OAuth) configure(ctx context.Context, kind ProviderKind, creds ClientCredentials) (*configuredProvider, error) {
	built := &configuredProvider{
		kind: kind,
		oauth: &oauth2.Config{
			ClientID:     creds.ClientID,
			ClientSecret: creds.ClientSecret,
			RedirectURL:  a.CallbackURL(kind.Name),
			Scopes:       kind.Scopes,
			Endpoint:     kind.Endpoint,
		},
	}

	// GitHub has no OIDC; its endpoints are fixed and its identity comes from
	// the REST API instead of an ID token.
	if kind.Issuer == "" {
		return built, nil
	}

	provider, err := oidc.NewProvider(ctx, kind.Issuer)
	if err != nil {
		return nil, fmt.Errorf("adminauth: could not discover %s (%s): %w", kind.Name, kind.Issuer, err)
	}
	built.oauth.Endpoint = provider.Endpoint()
	built.verifier = provider.Verifier(&oidc.Config{ClientID: creds.ClientID})
	return built, nil
}

// CallbackURL is where a provider returns the browser. It must be registered
// with that provider exactly.
func (a *OAuth) CallbackURL(provider string) string {
	u := *a.publicURL
	u.Path = strings.TrimSuffix(u.Path, "/") + "/admin/auth/" + provider + "/callback"
	return u.String()
}

// ProviderNames lists every provider this build knows how to speak to.
func ProviderNames() []string {
	names := make([]string, 0, len(SupportedProviders))
	for name := range SupportedProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// EnabledProviders lists the providers actually configured, in a stable order
// so the sign-in page does not reshuffle between renders.
func (a *OAuth) EnabledProviders() []string {
	names := make([]string, 0, len(a.configured))
	for name := range a.configured {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Start begins a sign-in, returning the URL to send the browser to.
func (a *OAuth) Start(ctx context.Context, provider, returnTo string) (string, error) {
	built, ok := a.configured[provider]
	if !ok {
		return "", fmt.Errorf("%w: provider %q is not enabled", ErrForbidden, provider)
	}

	verifier, err := secret.Token(verifierBytes)
	if err != nil {
		return "", err
	}
	nonce, err := secret.Token(verifierBytes)
	if err != nil {
		return "", err
	}

	login, err := a.store.CreateAdminLogin(ctx, provider, verifier, nonce, returnTo, loginTTL)
	if err != nil {
		return "", fmt.Errorf("start sign-in: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	// GitHub is not OIDC and rejects a nonce it does not understand.
	if built.kind.Issuer != "" {
		opts = append(opts, oidc.Nonce(login.Nonce))
	}
	return built.oauth.AuthCodeURL(login.State, opts...), nil
}

// Complete finishes a sign-in: it validates the callback, resolves the
// identity, asks the Authorizer, and on success creates a session.
func (a *OAuth) Complete(ctx context.Context, provider, state, code string) (*StoredSession, string, error) {
	login, err := a.store.ConsumeAdminLogin(ctx, state)
	if err != nil {
		// An unknown or already-used state is the signature of a replayed or
		// forged callback.
		return nil, "", fmt.Errorf("%w: this sign-in is no longer valid", ErrUnauthenticated)
	}
	if login.Provider != provider {
		return nil, "", fmt.Errorf("%w: the sign-in did not start with this provider", ErrUnauthenticated)
	}

	built, ok := a.configured[provider]
	if !ok {
		return nil, "", fmt.Errorf("%w: provider %q is not enabled", ErrForbidden, provider)
	}

	ctx = oidc.ClientContext(ctx, a.httpClient)
	token, err := built.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", login.CodeVerifier))
	if err != nil {
		return nil, "", fmt.Errorf("%w: the provider rejected the sign-in: %v", ErrUnauthenticated, err)
	}

	identity, err := a.identify(ctx, built, token, login.Nonce)
	if err != nil {
		return nil, "", err
	}

	// The authorization decision is entirely the Authorizer's; its error
	// sentinels pass straight through so the caller can tell a refusal from an
	// outage.
	if err := a.authorizer.Authorize(ctx, identity); err != nil {
		return nil, "", err
	}

	session, err := a.store.CreateAdminSession(ctx, identity.Subject, identity.Provider, identity.Name, a.sessionTTL)
	if err != nil {
		return nil, "", fmt.Errorf("create session: %w", err)
	}
	return session, login.ReturnTo, nil
}

// identify turns a provider's token response into an Identity.
func (a *OAuth) identify(ctx context.Context, built *configuredProvider, token *oauth2.Token, nonce string) (Identity, error) {
	if built.kind.Issuer == "" {
		// GitHub: no ID token exists, so the REST API is the identity source.
		identity, err := gitHubIdentity(ctx, a.httpClient, gitHubAPIUser, token.AccessToken)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
		}
		return identity, nil
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("%w: the provider returned no ID token", ErrUnauthenticated)
	}

	verified, err := built.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: the provider's ID token did not verify: %v", ErrUnauthenticated, err)
	}
	// The nonce binds this token to the request that started the sign-in.
	if verified.Nonce != nonce {
		return Identity{}, fmt.Errorf("%w: the ID token's nonce does not match this sign-in", ErrUnauthenticated)
	}

	var raw []byte
	if err := verified.Claims(&raw); err != nil {
		// Claims into a []byte is not supported by every version; fall back to
		// a map and re-encode below.
		raw = nil
	}
	if raw == nil {
		var claims map[string]any
		if err := verified.Claims(&claims); err != nil {
			return Identity{}, fmt.Errorf("%w: the ID token's claims could not be read: %v", ErrUnauthenticated, err)
		}
		raw = mustJSON(claims)
	}

	identity, err := built.kind.identityFromClaims(raw, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	return identity, nil
}

// Authenticate resolves the session cookie on an incoming request.
func (a *OAuth) Authenticate(r *http.Request) (*Admin, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrUnauthenticated
	}

	session, err := a.store.GetAdminSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return &Admin{
		Subject:  session.Subject,
		Provider: session.Provider,
		Name:     session.Name,
	}, nil
}

// SignOut ends a session immediately.
func (a *OAuth) SignOut(ctx context.Context, sessionID string) error {
	return a.store.DeleteAdminSession(ctx, sessionID)
}

// Supports reports whether a provider name is enabled.
func (a *OAuth) Supports(provider string) bool {
	return slices.Contains(a.EnabledProviders(), provider)
}

// pkceChallenge derives the S256 challenge from a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
