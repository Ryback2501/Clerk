package admin

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/Ryback2501/Clerk/internal/secret"
)

const (
	csrfCookieName = "clerk_csrf"
	csrfFieldName  = "csrf_token"
	csrfTokenBytes = 32
)

// errCSRF reports a state-changing request that did not prove it came from the
// admin interface.
var errCSRF = errors.New("csrf token missing or invalid")

// csrf implements double-submit CSRF protection: a random token is stored in an
// HttpOnly cookie and echoed in a hidden form field. A cross-site form can be
// made to send the cookie, but the same-origin policy stops the attacker from
// reading it to populate the field.
type csrf struct{}

func newCSRF() *csrf { return &csrf{} }

// issue returns the token to embed in a form, reusing the request's existing
// token when it has one. Reuse matters: minting a fresh token per page would
// invalidate the form in any other open tab.
func (c *csrf) issue(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	token, err := secret.Token(csrfTokenBytes)
	if err != nil {
		// Without randomness no safe token can be produced. Returning empty
		// makes check() fail closed on the subsequent POST.
		return ""
	}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure is not set: Clerk terminates no TLS itself and is routinely
		// run over plain http on localhost, where a Secure cookie would never
		// be sent. TLS is the reverse proxy's job.
	})
	return token
}

// check verifies a state-changing request. It fails closed: any missing or
// mismatched value is a rejection.
func (c *csrf) check(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return errCSRF
	}
	if err := r.ParseForm(); err != nil {
		return errCSRF
	}

	submitted := r.PostFormValue(csrfFieldName)
	if submitted == "" {
		return errCSRF
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 {
		return errCSRF
	}
	return nil
}
