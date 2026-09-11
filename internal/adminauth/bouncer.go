package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBouncerTimeout bounds how long an authorization decision may take.
// The admin UI blocks on it, so an unresponsive role service must fail rather
// than hang.
const DefaultBouncerTimeout = 5 * time.Second

// accessPath is the endpoint Bouncer exposes for checking access.
const accessPath = "/api/v1/access"

// BouncerConfig configures the role-service client.
type BouncerConfig struct {
	// BaseURL is the origin Bouncer is reachable at.
	BaseURL string

	// APIKey is the application key Bouncer issued for Clerk. It is a
	// credential: it must not appear in logs or error messages.
	APIKey string

	// RequiredRole is the role customId an administrator must hold. Empty
	// accepts any active role, delegating the decision entirely to Bouncer.
	RequiredRole string

	// Timeout defaults to DefaultBouncerTimeout.
	Timeout time.Duration

	// Client is for tests; production uses one built from Timeout.
	Client *http.Client
}

// Bouncer decides whether an identity may administer this provider, by asking
// the external role service.
//
// Every failure mode that is not an explicit refusal maps to ErrUnavailable,
// so the admin UI fails closed with a cause the operator can act on. None of
// this is reachable from internal/oidc: a Bouncer outage must not affect token
// issuance.
type Bouncer struct {
	baseURL      *url.URL
	apiKey       string
	requiredRole string
	client       *http.Client
}

// NewBouncer builds the client, rejecting an incomplete configuration at
// startup rather than on the first sign-in attempt.
func NewBouncer(cfg BouncerConfig) (*Bouncer, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("adminauth: a Bouncer base URL is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("adminauth: a Bouncer API key is required")
	}

	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("adminauth: Bouncer base URL is not valid: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("adminauth: Bouncer base URL %q must be absolute", cfg.BaseURL)
	}

	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = DefaultBouncerTimeout
		}
		client = &http.Client{Timeout: timeout}
	}

	return &Bouncer{
		baseURL:      base,
		apiKey:       cfg.APIKey,
		requiredRole: strings.TrimSpace(cfg.RequiredRole),
		client:       client,
	}, nil
}

// accessResponse is the granted body Bouncer returns.
type accessResponse struct {
	Sub  string `json:"sub"`
	Role struct {
		CustomID string `json:"customId"`
		Name     string `json:"name"`
	} `json:"role"`
}

// Authorize reports whether the identity may administer this provider.
//
// It returns nil when access is granted, ErrForbidden when the person is known
// but lacks the role, and ErrUnavailable when no decision could be reached.
// The distinction matters: the first is the administrator's problem, the
// second the operator's.
func (b *Bouncer) Authorize(ctx context.Context, identity Identity) error {
	endpoint := *b.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + accessPath
	endpoint.RawQuery = url.Values{
		"sub": {identity.Subject},
		// Sent so the same subject across two providers is not confused.
		"provider": {identity.Provider},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: building the request failed: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		// Deliberately not wrapping err's text with the request URL, which
		// would be fine, but never the key.
		return fmt.Errorf("%w: the role service could not be reached: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: the role service response could not be read: %v", ErrUnavailable, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return b.checkRole(body)

	case http.StatusForbidden, http.StatusNotFound:
		// role_inactive or user_not_found: a real decision, and a refusal.
		return fmt.Errorf("%w: %s", ErrForbidden, bouncerErrorCode(body))

	case http.StatusUnauthorized:
		// Clerk's own API key was rejected. That is a deployment fault, not
		// the administrator's, and must not be reported as a missing role.
		return fmt.Errorf("%w: the role service rejected this provider's API key (%s)",
			ErrUnavailable, bouncerErrorCode(body))

	default:
		return fmt.Errorf("%w: the role service returned %s", ErrUnavailable, resp.Status)
	}
}

// checkRole applies the configured role requirement to a granted response.
func (b *Bouncer) checkRole(body []byte) error {
	var granted accessResponse
	if err := json.Unmarshal(body, &granted); err != nil {
		return fmt.Errorf("%w: the role service response could not be decoded: %v", ErrUnavailable, err)
	}

	if b.requiredRole == "" {
		// Any active role is enough; Bouncer already decided.
		return nil
	}
	if granted.Role.CustomID != b.requiredRole {
		return fmt.Errorf("%w: role %q does not meet the required role %q",
			ErrForbidden, granted.Role.CustomID, b.requiredRole)
	}
	return nil
}

// bouncerErrorCode extracts the machine-readable code from an error body, for
// diagnostics. The body is external input and is only ever used as a label.
func bouncerErrorCode(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
		return "no error code"
	}
	return e.Error
}
