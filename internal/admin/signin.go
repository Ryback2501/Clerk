package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Ryback2501/Clerk/internal/adminauth"
)

// signInPath is where an unauthenticated administrator is sent.
const signInPath = "/admin/signin"

// registerSignIn wires the sign-in routes, which exist only when a real
// authenticator is configured.
func (h *Handler) registerSignIn(mux *http.ServeMux) {
	if h.oauth == nil {
		return
	}
	mux.HandleFunc("GET "+signInPath, h.showSignIn)
	mux.HandleFunc("GET /admin/auth/{provider}/start", h.startSignIn)
	mux.HandleFunc("GET /admin/auth/{provider}/callback", h.completeSignIn)
	mux.HandleFunc("POST /admin/signout", h.signOut)
}

func (h *Handler) showSignIn(w http.ResponseWriter, r *http.Request) {
	// Already signed in: no reason to show the page again.
	if _, err := h.auth.Authenticate(r); err == nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	data := h.newPageData(w, r, nil, "Sign in")
	data.Providers = h.oauth.EnabledProviders()
	data.Error = signInMessage(r.URL.Query().Get("error"))
	h.render(w, r, "signin", http.StatusOK, data)
}

func (h *Handler) startSignIn(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !h.oauth.Supports(provider) {
		h.renderError(w, r, nil, http.StatusNotFound, "Unknown provider",
			"That sign-in provider is not configured on this instance.")
		return
	}

	authURL, err := h.oauth.Start(r.Context(), provider, "/admin")
	if err != nil {
		h.logger.ErrorContext(r.Context(), "start admin sign-in", "err", err, "provider", provider)
		h.redirectToSignIn(w, r, problemNotStarted)
		return
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (h *Handler) completeSignIn(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")

	// A provider that refuses reports it here rather than by omitting code.
	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		h.logger.WarnContext(r.Context(), "provider refused the admin sign-in",
			"provider", provider, "error", providerErr)
		h.redirectToSignIn(w, r, problemRefused)
		return
	}

	session, returnTo, err := h.oauth.Complete(r.Context(),
		provider, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	switch {
	case err == nil:
		// fall through

	case errors.Is(err, adminauth.ErrForbidden):
		// Signed in successfully, but without the role this provider requires.
		h.logger.WarnContext(r.Context(), "admin sign-in refused by the role service",
			"provider", provider, "err", err)
		h.renderError(w, r, nil, http.StatusForbidden, "Not authorized",
			"You signed in successfully, but your account does not hold the role required to administer this provider.")
		return

	case errors.Is(err, adminauth.ErrUnavailable):
		// The OIDC endpoints are deliberately unaffected by this.
		h.logger.ErrorContext(r.Context(), "role service unavailable during admin sign-in",
			"provider", provider, "err", err)
		h.renderError(w, r, nil, http.StatusServiceUnavailable, "Administration unavailable",
			"The authorization service could not be reached, so administration is closed. "+
				"OpenID Connect endpoints are unaffected and continue to serve normally.")
		return

	default:
		h.logger.WarnContext(r.Context(), "admin sign-in failed", "provider", provider, "err", err)
		h.redirectToSignIn(w, r, problemFailed)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminauth.SessionCookieName,
		Value:    session.ID,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	h.logger.InfoContext(r.Context(), "administrator signed in",
		"provider", session.Provider, "subject", session.Subject)

	if returnTo == "" || !strings.HasPrefix(returnTo, "/admin") {
		// Only ever return to somewhere inside this interface.
		returnTo = "/admin"
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (h *Handler) signOut(w http.ResponseWriter, r *http.Request) {
	if err := h.csrf.Check(r); err != nil {
		h.renderError(w, r, nil, http.StatusForbidden, "Request rejected",
			"This sign-out could not be verified. Reload the page and try again.")
		return
	}

	if cookie, err := r.Cookie(adminauth.SessionCookieName); err == nil && cookie.Value != "" {
		if err := h.oauth.SignOut(r.Context(), cookie.Value); err != nil {
			h.logger.ErrorContext(r.Context(), "sign out", "err", err)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminauth.SessionCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, signInPath, http.StatusSeeOther)
}

// signInProblem identifies why a sign-in did not complete.
type signInProblem string

const (
	problemNotStarted signInProblem = "not_started"
	problemFailed     signInProblem = "failed"
	problemRefused    signInProblem = "refused"
)

// signInMessages maps a problem to the text shown.
//
// The code travels in the URL, never the message. Reflecting arbitrary text
// into the page would let anyone hand a victim a sign-in link displaying
// whatever they liked — escaped, so not script injection, but a convincing
// place to put a phone number to call.
var signInMessages = map[signInProblem]string{
	problemNotStarted: "The sign-in could not be started. Please try again.",
	problemFailed:     "The sign-in could not be completed. Please try again.",
	problemRefused:    "The provider did not complete the sign-in.",
}

func (h *Handler) redirectToSignIn(w http.ResponseWriter, r *http.Request, problem signInProblem) {
	target := signInPath
	if problem != "" {
		target += "?error=" + url.QueryEscape(string(problem))
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// signInMessage resolves a query parameter to one of the fixed messages,
// ignoring anything unrecognised.
func signInMessage(code string) string {
	return signInMessages[signInProblem(code)]
}
