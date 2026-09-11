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
		h.redisplayApplicationWithUserForm(w, r, admin, app.ID, username, err)
		return
	}

	// The sub is not secret — it is published in every ID token — so logging it
	// helps correlate an admin action with what a client later receives.
	h.logger.InfoContext(r.Context(), "test user created",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "admin", admin.Subject)

	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	app, ok := h.lookupApplication(w, r, admin)
	if !ok {
		return
	}

	userID, err := strconv.ParseInt(r.PathValue("userID"), 10, 64)
	if err != nil {
		h.notFound(w, r, admin)
		return
	}

	user, err := h.store.GetUser(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) {
		h.notFound(w, r, admin)
		return
	}
	if err != nil {
		h.internalError(w, r, admin, "load user", err)
		return
	}

	// A user may only be removed through the application that owns them.
	// Without this check, the id in the URL alone would be enough to delete
	// another application's identity.
	if user.ApplicationID != app.ID {
		h.notFound(w, r, admin)
		return
	}

	if err := h.store.DeleteUser(r.Context(), user.ID); err != nil {
		h.internalError(w, r, admin, "delete user", err)
		return
	}

	h.logger.InfoContext(r.Context(), "test user deleted",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "admin", admin.Subject)

	http.Redirect(w, r, "/admin/applications/"+strconv.FormatInt(app.ID, 10), http.StatusSeeOther)
}

// redisplayApplicationWithUserForm re-renders the application page carrying a
// validation error and the name that was rejected, so it need not be retyped.
func (h *Handler) redisplayApplicationWithUserForm(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, appID int64, username string, cause error) {
	app, users, err := h.applicationWithUsers(r, appID)
	if err != nil {
		h.internalError(w, r, admin, "load application", err)
		return
	}

	data := h.newPageData(w, r, admin, app.Name)
	data.Application = app
	data.Users = users
	data.UserError = validationMessage(cause)
	data.UserForm = username
	h.render(w, r, "application", http.StatusUnprocessableEntity, data)
}

func (h *Handler) applicationWithUsers(r *http.Request, appID int64) (*store.Application, []*store.User, error) {
	app, err := h.store.GetApplication(r.Context(), appID)
	if err != nil {
		return nil, nil, err
	}
	users, err := h.store.ListUsers(r.Context(), appID)
	if err != nil {
		return nil, nil, err
	}
	return app, users, nil
}
