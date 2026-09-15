// Package adminauth gates access to the administration interface.
//
// It is deliberately the only place that knows how an administrator is
// identified. Nothing under internal/oidc may import this package: a failure
// here — including an outage of the external role service — must never affect
// token issuance for the applications under test.
package adminauth

import (
	"errors"
	"net/http"
)

// Reasons an administrator may be refused. Callers map these to a redirect to
// the sign-in page, a 403, and a 503 respectively.
var (
	// ErrUnauthenticated means nobody is signed in yet.
	ErrUnauthenticated = errors.New("adminauth: not signed in")

	// ErrForbidden means the caller is signed in but lacks the required role.
	ErrForbidden = errors.New("adminauth: not authorized")

	// ErrUnavailable means the authorization decision could not be reached,
	// for example because the role service is unreachable. The admin UI fails
	// closed on this; the OIDC endpoints are unaffected.
	ErrUnavailable = errors.New("adminauth: authorization service unavailable")
)

// Admin is an authenticated administrator.
type Admin struct {
	// Subject is the identifier the upstream provider issued. It is the value
	// the role service is queried with, so it must be carried through verbatim.
	Subject string

	// Provider names the upstream identity provider (for example "google").
	Provider string

	// Name is for display only.
	Name string
}

// Authenticator decides whether a request may use the admin interface.
//
// Implementations return an Admin, or one of the sentinel errors above. OAuth
// signs the user in with an external provider and checks their role against
// the external role service.
type Authenticator interface {
	Authenticate(r *http.Request) (*Admin, error)
}
