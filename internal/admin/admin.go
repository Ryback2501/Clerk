// Package admin serves Clerk's administration interface: registering OIDC
// client applications and managing their credentials, redirect URIs and test
// users.
//
// The interface is one page, /admin. Everything about applications is loaded
// into it on demand by a small script, as HTML fragments rendered here — so all
// escaping stays in html/template and there is no separate data API.
//
// Nothing here may be imported by internal/oidc. The provider endpoints must
// keep serving even when administration — or the external service that
// authorises it — is broken.
package admin

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
	"github.com/Ryback2501/Clerk/internal/web"
)

//go:embed all:templates
var templateFS embed.FS

const (
	// fragmentHeader marks a request made by the admin script. Fragment routes
	// answer nothing else: a fragment opened as a page would be bare markup.
	// A custom header also cannot be sent cross-site without a CORS preflight
	// this server never grants, which adds to the CSRF token rather than
	// replacing it.
	fragmentHeader = "X-Clerk-Fragment"

	// createdHeader tells the script which application a create request made,
	// so it can unfold that application once the list is reloaded.
	createdHeader = "X-Clerk-Application"
)

// Handler serves the admin interface.
type Handler struct {
	store  *store.Store
	auth   adminauth.Authenticator
	logger *slog.Logger

	// oauth is set only when administration is really authenticated. It drives
	// the sign-in routes, which do not exist otherwise.
	oauth *adminauth.OAuth

	csrf      *web.CSRF
	pages     map[string]*template.Template
	fragments *template.Template
}

// NewWithOAuth builds the admin handler backed by real sign-in.
func NewWithOAuth(s *store.Store, oauth *adminauth.OAuth) (*Handler, error) {
	return newHandler(s, oauth, oauth)
}

func newHandler(s *store.Store, auth adminauth.Authenticator, oauth *adminauth.OAuth) (*Handler, error) {
	pages, fragments, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:     s,
		auth:      auth,
		oauth:     oauth,
		logger:    slog.Default(),
		csrf:      web.NewCSRF(web.AdminCSRFCookie),
		pages:     pages,
		fragments: fragments,
	}, nil
}

// WithLogger returns a copy of h that logs to the given logger.
func (h *Handler) WithLogger(l *slog.Logger) *Handler {
	clone := *h
	clone.logger = l
	return &clone
}

const fragmentGlob = "templates/fragments/*.html"

// parseTemplates pairs each page with the shared layouts, so a page can only
// ever be rendered inside one, and parses the fragments on their own. Pages
// also see the fragments, so the shell can embed the register form.
func parseTemplates() (map[string]*template.Template, *template.Template, error) {
	fragments, err := template.ParseFS(templateFS, fragmentGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("parse fragments: %w", err)
	}

	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, nil, fmt.Errorf("list templates: %w", err)
	}

	pages := make(map[string]*template.Template)
	for _, name := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(name, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.ParseFS(templateFS, "templates/layout.html", name, fragmentGlob)
		if err != nil {
			return nil, nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[base] = t
	}
	if len(pages) == 0 {
		return nil, nil, errors.New("no admin templates were embedded")
	}
	return pages, fragments, nil
}

// Register wires the admin routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	h.registerSignIn(mux)

	mux.HandleFunc("GET /admin", h.guard(h.showShell))
	// ServeMux only synthesises /x -> /x/, never the reverse, so the
	// trailing-slash form has to be registered explicitly.
	mux.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
	})

	mux.HandleFunc("GET /admin/applications", h.guardFragment(h.listApplications))
	mux.HandleFunc("GET /admin/applications/name-check", h.guardFragment(h.checkName))
	mux.HandleFunc("POST /admin/applications", h.guardWrite(h.createApplication))
	mux.HandleFunc("GET /admin/applications/{id}", h.guardFragment(h.showApplication))
	mux.HandleFunc("POST /admin/applications/{id}/name", h.guardWrite(h.renameApplication))
	mux.HandleFunc("POST /admin/applications/{id}/secret", h.guardWrite(h.regenerateSecret))
	mux.HandleFunc("POST /admin/applications/{id}/redirect-uris", h.guardWrite(h.addRedirectURI))
	mux.HandleFunc("POST /admin/applications/{id}/redirect-uris/edit", h.guardWrite(h.editRedirectURI))
	mux.HandleFunc("POST /admin/applications/{id}/redirect-uris/remove", h.guardWrite(h.removeRedirectURI))
	mux.HandleFunc("POST /admin/applications/{id}/delete", h.guardWrite(h.deleteApplication))
	mux.HandleFunc("POST /admin/applications/{id}/users", h.guardWrite(h.createUser))
	mux.HandleFunc("POST /admin/applications/{id}/users/{userID}/name", h.guardWrite(h.renameUser))
	mux.HandleFunc("POST /admin/applications/{id}/users/{userID}/delete", h.guardWrite(h.deleteUser))
}

// handlerFunc is a route that has already been authorised.
type handlerFunc func(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin)

// guard authenticates the request before running the route.
func (h *Handler) guard(next handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin, err := h.auth.Authenticate(r)
		if err != nil {
			h.denied(w, r, err)
			return
		}
		next(w, r, admin)
	}
}

// guardFragment additionally restricts the route to the admin script. Anything
// else is sent to the interface before it can read or change anything.
func (h *Handler) guardFragment(next handlerFunc) http.HandlerFunc {
	guarded := h.guard(next)
	return func(w http.ResponseWriter, r *http.Request) {
		if !isFragment(r) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		guarded(w, r)
	}
}

// guardWrite additionally enforces CSRF on state-changing routes.
func (h *Handler) guardWrite(next handlerFunc) http.HandlerFunc {
	return h.guardFragment(func(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
		if err := h.csrf.Check(r); err != nil {
			h.logger.WarnContext(r.Context(), "rejected a request failing CSRF validation",
				"path", r.URL.Path, "method", r.Method)
			h.renderError(w, r, admin, http.StatusForbidden, "Request rejected",
				"This request could not be verified as coming from the admin interface. Reload the page and try again.")
			return
		}
		next(w, r, admin)
	})
}

func isFragment(r *http.Request) bool { return r.Header.Get(fragmentHeader) == "1" }

// denied maps an authorization failure onto a response. It fails closed, and
// says which of the three reasons applied so the cause is diagnosable.
func (h *Handler) denied(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrUnauthenticated):
		// The script cannot follow a redirect into a sign-in page, so it is told
		// with a status and navigates there itself.
		if h.oauth != nil && !isFragment(r) {
			http.Redirect(w, r, signInPath, http.StatusSeeOther)
			return
		}
		h.renderError(w, r, nil, http.StatusUnauthorized, "Sign in required",
			"You must sign in to use the administration interface.")
	case errors.Is(err, adminauth.ErrForbidden):
		h.renderError(w, r, nil, http.StatusForbidden, "Not authorized",
			"Your account does not have the role required to administer this provider.")
	case errors.Is(err, adminauth.ErrUnavailable):
		// The OIDC endpoints are deliberately unaffected by this.
		h.logger.ErrorContext(r.Context(), "admin authorization unavailable", "err", err)
		h.renderError(w, r, nil, http.StatusServiceUnavailable, "Administration unavailable",
			"The authorization service could not be reached, so administration is closed. "+
				"OpenID Connect endpoints are unaffected and continue to serve normally.")
	default:
		h.logger.ErrorContext(r.Context(), "admin authorization failed", "err", err)
		h.renderError(w, r, nil, http.StatusInternalServerError, "Something went wrong",
			"The request could not be completed.")
	}
}
