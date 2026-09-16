package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/store"
)

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	user, err := h.store.CreateUser(r.Context(), app.ID, username)
	if err != nil {
		if !errors.Is(err, store.ErrValidation) {
			h.internalError(w, r, admin, "create user", err)
			return
		}
		h.renderPanel(w, r, admin, app.ID, http.StatusUnprocessableEntity,
			panelData{UserError: validationMessage(err), UserForm: username})
		return
	}

	// The sub is not secret — it is published in every ID token — so logging it
	// helps correlate an admin action with what a client later receives.
	h.logger.InfoContext(r.Context(), "test user created",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "admin", admin.Subject)

	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

// renameUser changes a test identity's name. Its sub is deliberately untouched:
// a client has already stored it.
func (h *Handler) renameUser(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, user, ok := h.lookupUser(w, r, admin)
	if !ok {
		return
	}

	typed := strings.TrimSpace(r.PostFormValue("username"))
	if err := h.store.RenameUser(r.Context(), user.ID, typed); err != nil {
		switch {
		case errors.Is(err, store.ErrValidation):
			form := renameUserForm(h.csrf.Issue(w, r), app.ID, user)
			form.Value = typed
			form.Error = validationMessage(err)
			h.renderFragment(w, r, "row-form", http.StatusUnprocessableEntity, form)
		case errors.Is(err, store.ErrNotFound):
			h.notFound(w, r, admin)
		default:
			h.internalError(w, r, admin, "rename user", err)
		}
		return
	}

	h.logger.InfoContext(r.Context(), "test user renamed",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "admin", admin.Subject)

	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, user, ok := h.lookupUser(w, r, admin)
	if !ok {
		return
	}

	if err := h.store.DeleteUser(r.Context(), user.ID); err != nil {
		h.internalError(w, r, admin, "delete user", err)
		return
	}

	h.logger.InfoContext(r.Context(), "test user deleted",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "admin", admin.Subject)

	h.renderPanel(w, r, admin, app.ID, http.StatusOK, panelData{})
}

// lookupUser resolves the {id} and {userID} path segments together.
//
// A user may only be reached through the application that owns them. Without
// that check, the id in the URL alone would be enough to rename or delete
// another application's identity.
func (h *Handler) lookupUser(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) (*store.Application, *store.User, bool) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return nil, nil, false
	}

	userID, err := strconv.ParseInt(r.PathValue("userID"), 10, 64)
	if err != nil {
		h.notFound(w, r, admin)
		return nil, nil, false
	}

	user, err := h.store.GetUser(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) {
		h.notFound(w, r, admin)
		return nil, nil, false
	}
	if err != nil {
		h.internalError(w, r, admin, "load user", err)
		return nil, nil, false
	}
	if user.ApplicationID != app.ID {
		h.notFound(w, r, admin)
		return nil, nil, false
	}
	return app, user, true
}
