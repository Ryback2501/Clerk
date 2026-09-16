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
	Register nameForm
}

// nameForm is the dialog that names an application. Registering and renaming
// differ only in what it posts to and what it is called, so both render it and
// cannot drift apart. On a rejected submission it carries back what was typed
// and why it was refused.
type nameForm struct {
	Title     string
	Action    string
	Submit    string
	DialogID  string
	CSRFToken string

	// Name is what the field holds: the stored name, or what was typed and
	// refused. Original is what the application is actually called, which is
	// what cancelling restores and what "unchanged" is measured against — empty
	// while registering.
	Name     string
	Original string

	// ExcludeID is the application the live duplicate check must ignore, so a
	// rename never collides with itself. It is 0 while registering.
	ExcludeID int64

	Error string
}

func editURIForm(token string, appID int64, index int, uri string) rowForm {
	return rowForm{
		Title:       "Edit redirect URI",
		Action:      "/admin/applications/" + strconv.FormatInt(appID, 10) + "/redirect-uris/edit",
		Submit:      "Save",
		DialogID:    "edit-uri-" + strconv.FormatInt(appID, 10) + "-" + strconv.Itoa(index),
		CSRFToken:   token,
		Label:       "Redirect URI",
		Field:       "uri",
		Value:       uri,
		Original:    uri,
		Placeholder: "https://app.example.com/callback",
	}
}

func renameUserForm(token string, appID int64, user *store.User) rowForm {
	return rowForm{
		Title:       "Rename test user",
		Action:      "/admin/applications/" + strconv.FormatInt(appID, 10) + "/users/" + strconv.FormatInt(user.ID, 10) + "/name",
		Submit:      "Save",
		DialogID:    "rename-user-" + strconv.FormatInt(user.ID, 10),
		CSRFToken:   token,
		Label:       "User name",
		Field:       "username",
		Value:       user.Username,
		Original:    user.Username,
		Placeholder: "John Doe",
	}
}

func registerForm(token string) nameForm {
	return nameForm{
		Title:     "Register an application",
		Action:    "/admin/applications",
		Submit:    "Create",
		DialogID:  "register",
		CSRFToken: token,
	}
}

func renameForm(token string, app *store.Application) nameForm {
	return nameForm{
		Title:     "Rename application",
		Action:    "/admin/applications/" + strconv.FormatInt(app.ID, 10) + "/name",
		Submit:    "Save",
		DialogID:  "rename-" + strconv.FormatInt(app.ID, 10),
		CSRFToken: token,
		Name:      app.Name,
		Original:  app.Name,
		ExcludeID: app.ID,
	}
}

// listData is the application list: only what a folded application shows.
type listData struct {
	Applications []appSummary
}

type appSummary struct {
	*store.Application
	UserCount int
}

// rowForm is the dialog that edits one row: a redirect URI or a test user.
// Both work like the name dialog — the same message slot, and a button that
// stays disabled while the value is empty, unchanged or already taken.
type rowForm struct {
	Title     string
	Action    string
	Submit    string
	DialogID  string
	CSRFToken string

	// Label names the field; Field is its form name ("uri" or "username"),
	// which is also what the browser's duplicate check compares against.
	Label string
	Field string

	Value       string
	Original    string
	Placeholder string
	Error       string
}

// uriRow is one registered redirect URI, with the dialogs that edit and remove
// it. The index only has to be unique within the panel.
type uriRow struct {
	Index int
	URI   string
	Form  rowForm
}

// userRow is one test identity, with the dialog that renames it.
type userRow struct {
	*store.User
	Form rowForm
}

// panelData is everything an unfolded application shows.
type panelData struct {
	CSRFToken string
	App       *store.Application
	Users     []*store.User
	URIRows   []uriRow
	UserRows  []userRow

	// RenameForm is the dialog that renames this application.
	RenameForm nameForm

	// RevealedSecret is set only in the response to the request that generated
	// the secret, and is rendered into a dialog shown once. It is never stored,
	// and no other response carries it.
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
		rejected := registerForm(h.csrf.Issue(w, r))
		rejected.Name = typed
		rejected.Error = validationMessage(err)
		h.renderFragment(w, r, "name-form", http.StatusUnprocessableEntity, rejected)
		return
	}

	h.logger.InfoContext(r.Context(), "application created",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)

	w.Header().Set(createdHeader, strconv.FormatInt(app.ID, 10))
	h.renderPanel(w, r, admin, app.ID, http.StatusCreated, panelData{RevealedSecret: plainSecret})
}

// renameApplication changes the application's label. Everything a client is
// configured with stays as it is.
func (h *Handler) renameApplication(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	typed := r.PostFormValue("name")
	if err := h.store.RenameApplication(r.Context(), app.ID, typed); err != nil {
		switch {
		case errors.Is(err, store.ErrValidation):
			rejected := renameForm(h.csrf.Issue(w, r), app)
			rejected.Name = typed
			rejected.Error = validationMessage(err)
			h.renderFragment(w, r, "name-form", http.StatusUnprocessableEntity, rejected)
		case errors.Is(err, store.ErrNotFound):
			h.notFound(w, r, admin)
		default:
			h.internalError(w, r, admin, "rename application", err)
		}
		return
	}

	h.logger.InfoContext(r.Context(), "application renamed",
		"application_id", app.ID, "client_id", app.ClientID, "admin", admin.Subject)

	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

// checkName answers the dialog's live duplicate check: no content while the
// name is free, and the message to show when it is not.
func (h *Handler) checkName(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	// A malformed exclude is nobody's application, so the name is simply
	// checked against every row.
	exclude, _ := strconv.ParseInt(r.URL.Query().Get("exclude"), 10, 64)

	name := r.URL.Query().Get("name")
	if strings.TrimSpace(name) == "" {
		// An empty box is not a conflict; the field is required, which is what
		// stops it from being submitted.
		h.nameIsFree(w)
		return
	}

	free, err := h.store.NameIsAvailable(r.Context(), name, exclude)
	if err != nil {
		h.internalError(w, r, admin, "check application name", err)
		return
	}
	if free {
		h.nameIsFree(w)
		return
	}
	h.renderFragment(w, r, "name-taken", http.StatusConflict, nil)
}

// nameIsFree answers that nothing holds the name. It carries the same headers
// as every other answer: a cached "free" would go on offering a name somebody
// has since registered.
func (h *Handler) nameIsFree(w http.ResponseWriter) {
	setSecurityHeaders(w)
	w.WriteHeader(http.StatusNoContent)
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

// editRedirectURI replaces one registered URI, so a typo can be corrected
// without the round trip of removing and adding.
func (h *Handler) editRedirectURI(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	original := r.PostFormValue("original")
	typed := strings.TrimSpace(r.PostFormValue("uri"))
	if err := h.store.UpdateRedirectURI(r.Context(), app.ID, original, typed); err != nil {
		switch {
		case errors.Is(err, store.ErrValidation):
			// The dialog stays open, carrying the reason and what was typed.
			form := editURIForm(h.csrf.Issue(w, r), app.ID, h.uriIndex(app, original), original)
			form.Value = typed
			form.Error = validationMessage(err)
			h.renderFragment(w, r, "row-form", http.StatusUnprocessableEntity, form)
		case errors.Is(err, store.ErrNotFound):
			h.notFound(w, r, admin)
		default:
			h.internalError(w, r, admin, "update redirect uri", err)
		}
		return
	}
	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

// uriIndex finds the position a URI is rendered at, so a rejected edit returns
// to the dialog it came from. A URI that is no longer registered cannot reach
// this: the store reports that as not found.
func (h *Handler) uriIndex(app *store.Application, uri string) int {
	for i, registered := range app.RedirectURIs {
		if registered == uri {
			return i + 1
		}
	}
	return 0
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
	data.RenameForm = renameForm(data.CSRFToken, app)

	for i, uri := range app.RedirectURIs {
		index := i + 1
		data.URIRows = append(data.URIRows, uriRow{
			Index: index,
			URI:   uri,
			Form:  editURIForm(data.CSRFToken, app.ID, index, uri),
		})
	}
	for _, user := range users {
		data.UserRows = append(data.UserRows, userRow{
			User: user,
			Form: renameUserForm(data.CSRFToken, app.ID, user),
		})
	}
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
