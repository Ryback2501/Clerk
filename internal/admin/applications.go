package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
)

// pageData is the view model the full pages render against.
type pageData struct {
	Title string
	Admin *adminauth.Admin

	CSRFToken string
	CSRFField string
	Error     string

	// Providers is the sign-in page's list of enabled upstreams.
	Providers []providerButton

	// SignedIn drives whether the layout offers a sign-out control.
	SignedIn bool

	// Register is the shell's empty registration form.
	Register registerForm
}

// registerForm is the body of the registration dialog. On a rejected
// submission it carries back what was typed and why it was refused.
type registerForm struct {
	CSRFToken string
	Name      string
	Error     string
}

// listData is the application list: only what a folded application shows.
type listData struct {
	Applications []appSummary
}

type appSummary struct {
	*store.Application
	UserCount int
}

// panelData is everything an unfolded application shows.
type panelData struct {
	CSRFToken string
	App       *store.Application
	Users     []*store.User

	// RevealedSecret is set only in the response to the request that generated
	// the secret. It is never stored and no other response carries it.
	RevealedSecret string

	// URIError/URIForm and UserError/UserForm carry a rejected submission back
	// into the section it came from.
	URIError  string
	URIForm   string
	UserError string
	UserForm  string
}

type alertData struct {
	Title   string
	Message string
}

// showShell renders the interface itself. It deliberately contains no
// application data: the script loads the list as soon as the page is up.
func (h *Handler) showShell(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	h.render(w, r, "admin", http.StatusOK, h.newPageData(w, r, admin, "Applications"))
}

func (h *Handler) listApplications(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	apps, err := h.store.ListApplications(r.Context())
	if err != nil {
		h.internalError(w, r, admin, "list applications", err)
		return
	}

	summaries := make([]appSummary, 0, len(apps))
	for _, app := range apps {
		n, err := h.store.CountUsers(r.Context(), app.ID)
		if err != nil {
			h.internalError(w, r, admin, "count users", err)
			return
		}
		summaries = append(summaries, appSummary{Application: app, UserCount: n})
	}
	h.renderFragment(w, r, "list", http.StatusOK, listData{Applications: summaries})
}

func (h *Handler) showApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}
	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

func (h *Handler) createApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	typed := r.PostFormValue("name")

	app, plainSecret, err := h.store.CreateApplication(r.Context(), strings.TrimSpace(typed), nil)
	if err != nil {
		// Only the administrator's own mistakes are theirs to see. Anything
		// else is an internal fault: it belongs in the log, under a 500.
		if !errors.Is(err, store.ErrValidation) {
			h.internalError(w, r, admin, "create application", err)
			return
		}
		h.renderFragment(w, r, "register-form", http.StatusUnprocessableEntity, registerForm{
			CSRFToken: h.csrf.Issue(w, r),
			Name:      typed,
			Error:     validationMessage(err),
		})
		return
	}

	h.logger.InfoContext(r.Context(), "application created",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)

	w.Header().Set(createdHeader, strconv.FormatInt(app.ID, 10))
	h.renderPanel(w, r, admin, app.ID, http.StatusCreated, panelData{RevealedSecret: plainSecret})
}

func (h *Handler) regenerateSecret(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	plainSecret, err := h.store.RegenerateClientSecret(r.Context(), app.ID)
	if err != nil {
		h.internalError(w, r, admin, "regenerate client secret", err)
		return
	}

	// The secret itself is never logged.
	h.logger.InfoContext(r.Context(), "client secret regenerated",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)

	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{RevealedSecret: plainSecret})
}

func (h *Handler) addRedirectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	uri := strings.TrimSpace(r.PostFormValue("uri"))
	if err := h.store.AddRedirectURI(r.Context(), app.ID, uri); err != nil {
		h.rejectURI(w, r, admin, app.ID, uri, "add redirect uri", err)
		return
	}
	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

func (h *Handler) removeRedirectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	if err := h.store.RemoveRedirectURI(r.Context(), app.ID, r.PostFormValue("uri")); err != nil {
		h.rejectURI(w, r, admin, app.ID, "", "remove redirect uri", err)
		return
	}
	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

// rejectURI answers a failed redirect URI change: the panel with the reason for
// a validation failure, a 404 for an application deleted meanwhile, and an
// internal error for anything else.
func (h *Handler) rejectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, appID int64, typed, what string, cause error) {
	switch {
	case errors.Is(cause, store.ErrValidation):
		h.renderPanel(w, r, admin, appID, http.StatusUnprocessableEntity,
			panelData{URIError: validationMessage(cause), URIForm: typed})
	case errors.Is(cause, store.ErrNotFound):
		h.notFound(w, r, admin)
	default:
		h.internalError(w, r, admin, what, cause)
	}
}

func (h *Handler) deleteApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	if err := h.store.DeleteApplication(r.Context(), app.ID); err != nil {
		h.internalError(w, r, admin, "delete application", err)
		return
	}

	h.logger.InfoContext(r.Context(), "application deleted",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)
	w.WriteHeader(http.StatusNoContent)
}

// renderPanel loads an application's current state and renders its panel,
// merged with whatever the caller has to add: a secret, or a rejected value.
func (h *Handler) renderPanel(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, appID int64, status int, data panelData) {
	app, err := h.store.GetApplication(r.Context(), appID)
	if errors.Is(err, store.ErrNotFound) {
		h.notFound(w, r, admin)
		return
	}
	if err != nil {
		h.internalError(w, r, admin, "load application", err)
		return
	}
	users, err := h.store.ListUsers(r.Context(), appID)
	if err != nil {
		h.internalError(w, r, admin, "list users", err)
		return
	}

	data.CSRFToken = h.csrf.Issue(w, r)
	data.App = app
	data.Users = users
	h.renderFragment(w, r, "panel", status, data)
}

// lookupApplication resolves the {id} path segment, answering 404 for both a
// malformed id and an unknown one: to a caller they are the same thing.
func (h *Handler) lookupApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) (*store.Application, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.notFound(w, r, admin)
		return nil, false
	}

	app, err := h.store.GetApplication(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		h.notFound(w, r, admin)
		return nil, false
	}
	if err != nil {
		h.internalError(w, r, admin, "load application", err)
		return nil, false
	}
	return app, true
}

// validationMessage strips the sentinel prefix so the administrator reads the
// problem rather than the plumbing.
func validationMessage(err error) string {
	msg := err.Error()
	return strings.TrimPrefix(msg, store.ErrValidation.Error()+": ")
}
