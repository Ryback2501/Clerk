package web

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/Ryback2501/Clerk/internal/secret"
)

const (
	// AdminCSRFCookie and LoginCSRFCookie keep the two surfaces separate.
	//
	// The administration interface and the public login page share this
	// implementation but must not share a token: any registered client can
	// drive a browser to the login page, so a single cookie would mean a token
	// valid for admin state-changing routes is embedded in a page that clients
	// control the entry to.
	AdminCSRFCookie = "clerk_csrf_admin"
	LoginCSRFCookie = "clerk_csrf_login"

	// CSRFFieldName is the hidden form field echoing the token back.
	CSRFFieldName = "csrf_token"

	csrfTokenBytes = 32
)

// ErrCSRF reports a state-changing request that did not prove it came from a
// page this provider rendered.
var ErrCSRF = errors.New("csrf token missing or invalid")

// CSRF implements double-submit CSRF protection: a random token is stored in an
// HttpOnly cookie and echoed in a hidden form field. A cross-site form can be
// made to send the cookie, but the same-origin policy stops the attacker from
// reading it to populate the field.
//
// Both the administration interface and the login form use it. The login form
// is reached by a redirect from a third-party application, so the cookie is
// SameSite=Lax rather than Strict: Strict would withhold it on that navigation
// and every sign-in would fail.
type CSRF struct {
	cookieName string
}

// NewCSRF returns a guard storing its token in the named cookie.
func NewCSRF(cookieName string) *CSRF { return &CSRF{cookieName: cookieName} }

// Reuse matters: minting a fresh token per page would invalidate the form in
// any other open tab.
//
// Issue returns the token to embed in a form, reusing the request's existing
// token when it has one.
func (c *CSRF) Issue(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(c.cookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	token, err := secret.Token(csrfTokenBytes)
	if err != nil {
		// Without randomness no safe token can be produced. Returning empty
		// makes check() fail closed on the subsequent POST.
		return ""
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
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

// Check verifies a state-changing request. It fails closed: any missing or
// mismatched value is a rejection.
func (c *CSRF) Check(r *http.Request) error {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil || cookie.Value == "" {
		return ErrCSRF
	}
	if err := r.ParseForm(); err != nil {
		return ErrCSRF
	}

	submitted := r.PostFormValue(CSRFFieldName)
	if submitted == "" {
		return ErrCSRF
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 {
		return ErrCSRF
	}
	return nil
}
