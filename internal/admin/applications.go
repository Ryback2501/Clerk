package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
)

// pageData is the view model every admin template renders against.
type pageData struct {
	Title    string
	Admin    *adminauth.Admin
	Insecure bool

	CSRFToken string
	Error     string

	Applications []*store.Application
	Application  *store.Application
	Users        []*store.User
	UserCount    int
	Form         applicationForm

	// UserError and UserForm carry a rejected "add user" submission back to
	// the page it came from.
	UserError string
	UserForm  string

	// RevealedSecret is set only on the single render that follows generating
	// a secret. It is never stored and never shown again.
	RevealedSecret string
}

// applicationForm preserves what the administrator typed, so a validation
// failure does not make them retype it.
type applicationForm struct {
	Name         string
	RedirectURIs string
}

func (h *Handler) listApplications(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	apps, err := h.store.ListApplications(r.Context())
	if err != nil {
		h.internalError(w, r, admin, "list applications", err)
		return
	}

	data := h.newPageData(w, r, admin, "Applications")
	data.Applications = apps
	h.render(w, r, "applications", http.StatusOK, data)
}

func (h *Handler) newApplicationForm(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	h.render(w, r, "application_new", http.StatusOK, h.newPageData(w, r, admin, "Register an application"))
}

func (h *Handler) createApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	form := applicationForm{
		Name:         strings.TrimSpace(r.PostFormValue("name")),
		RedirectURIs: r.PostFormValue("redirect_uris"),
	}

	app, plainSecret, err := h.store.CreateApplication(r.Context(), form.Name, splitURIs(form.RedirectURIs))
	if err != nil {
		// Only the administrator's own mistakes are theirs to see. Anything
		// else is an internal fault: it belongs in the log, under a 500.
		if !errors.Is(err, store.ErrValidation) {
			h.internalError(w, r, admin, "create application", err)
			return
		}
		data := h.newPageData(w, r, admin, "Register an application")
		data.Error = validationMessage(err)
		data.Form = form
		h.render(w, r, "application_new", http.StatusUnprocessableEntity, data)
		return
	}

	h.logger.InfoContext(r.Context(), "application created",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)

	h.revealOnce(w, app.ID, plainSecret)
	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

func (h *Handler) showApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	users, err := h.store.ListUsers(r.Context(), app.ID)
	if err != nil {
		h.internalError(w, r, admin, "list users", err)
		return
	}

	data := h.newPageData(w, r, admin, app.Name)
	data.Application = app
	data.Users = users
	data.RevealedSecret = h.takeRevealed(w, r, app.ID)
	h.render(w, r, "application", http.StatusOK, data)
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

	h.revealOnce(w, app.ID, plainSecret)
	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

func (h *Handler) addRedirectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	uri := strings.TrimSpace(r.PostFormValue("uri"))
	if err := h.store.AddRedirectURI(r.Context(), app.ID, uri); err != nil {
		h.redisplayApplication(w, r, admin, app.ID, err)
		return
	}
	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

func (h *Handler) removeRedirectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	uri := r.PostFormValue("uri")
	if err := h.store.RemoveRedirectURI(r.Context(), app.ID, uri); err != nil {
		h.redisplayApplication(w, r, admin, app.ID, err)
		return
	}
	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

func (h *Handler) confirmDeleteApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	// The count is shown so the administrator sees exactly how much is about to
	// be destroyed, rather than a generic warning.
	users, err := h.store.CountUsers(r.Context(), app.ID)
	if err != nil {
		h.internalError(w, r, admin, "count users", err)
		return
	}

	data := h.newPageData(w, r, admin, "Delete application")
	data.Application = app
	data.UserCount = users
	h.render(w, r, "application_delete", http.StatusOK, data)
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
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
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

// redisplayApplication re-renders the detail page carrying a validation error.
// A cause that is not a validation failure is an internal fault instead.
func (h *Handler) redisplayApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, id int64, cause error) {
	if !errors.Is(cause, store.ErrValidation) && !errors.Is(cause, store.ErrNotFound) {
		h.internalError(w, r, admin, "update redirect uris", cause)
		return
	}

	app, users, err := h.applicationWithUsers(r, id)
	if err != nil {
		h.internalError(w, r, admin, "load application", err)
		return
	}

	data := h.newPageData(w, r, admin, app.Name)
	data.Application = app
	data.Users = users
	data.Error = validationMessage(cause)
	h.render(w, r, "application", http.StatusUnprocessableEntity, data)
}

// validationMessage strips the sentinel prefix so the administrator reads the
// problem rather than the plumbing.
func validationMessage(err error) string {
	msg := err.Error()
	return strings.TrimPrefix(msg, store.ErrValidation.Error()+": ")
}

// splitURIs turns the textarea's one-per-line input into a list.
func splitURIs(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
