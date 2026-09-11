// Package admin serves Clerk's administration interface: registering OIDC
// client applications and managing their credentials and redirect URIs.
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
)

//go:embed all:templates
var templateFS embed.FS

//go:embed all:static
var staticFS embed.FS

// revealCookiePrefix begins the name of the cookie carrying the single-use
// token that reveals a freshly generated client secret. The application id is
// appended, so each application has its own slot.
const revealCookiePrefix = "clerk_reveal_"

// Handler serves the admin interface.
type Handler struct {
	store  *store.Store
	auth   adminauth.Authenticator
	logger *slog.Logger

	csrf   *csrf
	reveal *revealStore
	pages  map[string]*template.Template

	// insecure records that admin authentication is a no-op, so the UI can say
	// so on every page rather than leaving it to be discovered.
	insecure bool
}

// New builds the admin handler. Pass insecure when the authenticator does not
// actually authenticate, so the interface can warn about it.
func New(s *store.Store, auth adminauth.Authenticator, insecure bool) (*Handler, error) {
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:    s,
		auth:     auth,
		logger:   slog.Default(),
		csrf:     newCSRF(),
		reveal:   newRevealStore(),
		pages:    pages,
		insecure: insecure,
	}, nil
}

// WithLogger returns a copy of h that logs to the given logger.
func (h *Handler) WithLogger(l *slog.Logger) *Handler {
	clone := *h
	clone.logger = l
	return &clone
}

// parsePages pairs each content template with the shared layout, so a page can
// only ever be rendered inside it.
func parsePages() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}

	pages := make(map[string]*template.Template)
	for _, name := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(name, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[base] = t
	}
	if len(pages) == 0 {
		return nil, errors.New("no admin templates were embedded")
	}
	return pages, nil
}

// Register wires the admin routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		// The directory is embedded at build time, so this cannot fail in a
		// built binary.
		panic(fmt.Sprintf("admin: embedded static assets unavailable: %v", err))
	}
	// noDirFS keeps http.FileServer from serving a browsable index of whatever
	// ends up in the embedded asset tree.
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(noDirFS{static}))))

	mux.HandleFunc("GET /admin", h.guard(h.listApplications))
	// ServeMux only synthesises /x -> /x/, never the reverse, so the
	// trailing-slash form has to be registered explicitly.
	mux.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /admin/applications/new", h.guard(h.newApplicationForm))
	mux.HandleFunc("POST /admin/applications", h.guardWrite(h.createApplication))
	mux.HandleFunc("GET /admin/applications/{id}", h.guard(h.showApplication))
	mux.HandleFunc("POST /admin/applications/{id}/secret", h.guardWrite(h.regenerateSecret))
	mux.HandleFunc("POST /admin/applications/{id}/redirect-uris", h.guardWrite(h.addRedirectURI))
	mux.HandleFunc("POST /admin/applications/{id}/redirect-uris/remove", h.guardWrite(h.removeRedirectURI))
	mux.HandleFunc("GET /admin/applications/{id}/delete", h.guard(h.confirmDeleteApplication))
	mux.HandleFunc("POST /admin/applications/{id}/delete", h.guardWrite(h.deleteApplication))
	mux.HandleFunc("POST /admin/applications/{id}/users", h.guardWrite(h.createUser))
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

// guardWrite additionally enforces CSRF on state-changing routes.
func (h *Handler) guardWrite(next handlerFunc) http.HandlerFunc {
	return h.guard(func(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
		if err := h.csrf.check(r); err != nil {
			h.logger.WarnContext(r.Context(), "rejected a request failing CSRF validation",
				"path", r.URL.Path, "method", r.Method)
			h.renderError(w, r, admin, http.StatusForbidden, "Request rejected",
				"This request could not be verified as coming from the admin interface. Reload the page and try again.")
			return
		}
		next(w, r, admin)
	})
}

// denied maps an authorization failure onto a response. It fails closed, and
// says which of the three reasons applied so the cause is diagnosable.
func (h *Handler) denied(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrUnauthenticated):
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

// noDirFS is an fs.FS that refuses to open directories, so a file server built
// on it cannot list their contents.
type noDirFS struct{ fs.FS }

func (f noDirFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}
