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
// Implementations return an Admin, or one of the sentinel errors above. The
// real implementation signs the user in with an external OAuth provider and
// checks their role against the external role service; AllowAll stands in
// until then.
type Authenticator interface {
	Authenticate(r *http.Request) (*Admin, error)
}

// AllowAll authorises every request as a fixed local administrator.
//
// It is a development stand-in only: it performs no authentication whatsoever,
// so anything it protects is open to anyone who can reach the port. Callers are
// expected to announce it loudly at startup.
type AllowAll struct{}

// Authenticate implements Authenticator by authorising everyone.
func (AllowAll) Authenticate(*http.Request) (*Admin, error) {
	return &Admin{
		Subject:  "local-development",
		Provider: "none",
		Name:     "Local administrator",
	}, nil
}

// Warning is the message a caller should log when wiring AllowAll, so an
// unprotected admin interface is never a silent condition.
const Warning = "ADMIN AUTHENTICATION IS DISABLED: every request is authorised as a local administrator. " +
	"This build must not be exposed to an untrusted network."
