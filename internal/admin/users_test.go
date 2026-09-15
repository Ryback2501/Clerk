package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func (h *harness) createUser(appID int64, name string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.post(appPath(appID)+"/users", url.Values{"username": {name}})
}

// Acceptance criterion 8.
func TestCreateUserThroughTheAdminUI(t *testing.T) {
	h := newHarness(t)
	app := h.createApp("App", "https://a.example.com/cb")

	got := h.createUser(app, "david")
	if got.Code != http.StatusOK {
		t.Fatalf("create user returned %d, want 200: %s", got.Code, got.Body.String())
	}

	users, err := h.store.ListUsers(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "david" {
		t.Fatalf("users = %v, want one named david", users)
	}

	body := got.Body.String()
	if !strings.Contains(body, "<td>david</td>") {
		t.Error("the refreshed panel does not list the new user")
	}
	// The sub is the stable account identifier a client will store, so an
	// administrator debugging an integration needs to be able to read it.
	if !strings.Contains(body, users[0].Sub) {
		t.Error("the user's sub is not shown, leaving no way to correlate it with a client")
	}
	if !strings.Contains(body, `data-user-count="1"`) {
		t.Error("the refreshed panel does not report the new user count")
	}
}

// Acceptance criterion 9: the message must say what is wrong, and the form must
// not lose what was typed.
func TestDuplicateUsernameIsRejectedInTheUI(t *testing.T) {
	h := newHarness(t)
	app := h.createApp("App", "https://a.example.com/cb")
	h.createUser(app, "david")

	got := h.createUser(app, "david")
	if got.Code != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate username returned %d, want 422", got.Code)
	}
	body := got.Body.String()
	if !strings.Contains(body, "already exists") {
		t.Error("the error message does not explain the conflict")
	}
	if !strings.Contains(body, `name="username" value="david"`) {
		t.Error("the rejected username was not kept in the form")
	}

	users, _ := h.store.ListUsers(context.Background(), app)
	if len(users) != 1 {
		t.Errorf("the rejected submission left %d users, want 1", len(users))
	}
}

// Acceptance criterion 10.
func TestSameUsernameIsAllowedInADifferentApplication(t *testing.T) {
	h := newHarness(t)
	first := h.createApp("First", "https://a.example.com/cb")
	second := h.createApp("Second", "https://b.example.com/cb")

	h.createUser(first, "david")
	if got := h.createUser(second, "david"); got.Code != http.StatusOK {
		t.Fatalf("the same username in another application returned %d, want 200", got.Code)
	}

	a, _ := h.store.ListUsers(context.Background(), first)
	b, _ := h.store.ListUsers(context.Background(), second)
	if a[0].Sub == b[0].Sub {
		t.Error("the two identities share a sub")
	}
}

// Acceptance criterion 28.
func TestDeleteUserLeavesTheApplicationAndOtherUsersAlone(t *testing.T) {
	h := newHarness(t)
	app := h.createApp("App", "https://a.example.com/cb")
	h.createUser(app, "david")
	h.createUser(app, "alice")

	users, _ := h.store.ListUsers(context.Background(), app)
	var doomed int64
	for _, u := range users {
		if u.Username == "david" {
			doomed = u.ID
		}
	}

	rec := h.post(appPath(app)+"/users/"+itoa(doomed)+"/delete", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user returned %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<td>david</td>") {
		t.Error("the refreshed panel still lists the deleted user")
	}

	remaining, _ := h.store.ListUsers(context.Background(), app)
	if len(remaining) != 1 || remaining[0].Username != "alice" {
		t.Errorf("remaining users = %v, want just alice", remaining)
	}
	if _, err := h.store.GetApplication(context.Background(), app); err != nil {
		t.Errorf("deleting a user affected the application: %v", err)
	}
}

// A user may only be deleted through the application that owns them, or one
// administrator could remove another application's identity by guessing an id.
func TestUserCannotBeDeletedThroughAnotherApplication(t *testing.T) {
	h := newHarness(t)
	owner := h.createApp("Owner", "https://a.example.com/cb")
	other := h.createApp("Other", "https://b.example.com/cb")
	h.createUser(owner, "david")

	users, _ := h.store.ListUsers(context.Background(), owner)
	victim := users[0].ID

	rec := h.post(appPath(other)+"/users/"+itoa(victim)+"/delete", url.Values{})
	if rec.Code != http.StatusNotFound {
		t.Errorf("deleting through a foreign application returned %d, want 404", rec.Code)
	}

	if _, err := h.store.GetUser(context.Background(), victim); err != nil {
		t.Errorf("the user was deleted despite the mismatched application: %v", err)
	}
}

func TestUserRoutesRequireCSRF(t *testing.T) {
	h := newHarness(t)
	app := h.createApp("App", "https://a.example.com/cb")
	h.createUser(app, "david")
	users, _ := h.store.ListUsers(context.Background(), app)

	for _, path := range []string{
		appPath(app) + "/users",
		appPath(app) + "/users/" + itoa(users[0].ID) + "/delete",
	} {
		req := newForm(http.MethodPost, path, "username=x")
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without a CSRF token = %d, want 403", path, rec.Code)
		}
	}
}

// The login page will render these names, and so does the admin UI.
func TestUsernameIsEscapedInTheUI(t *testing.T) {
	h := newHarness(t)
	app := h.createApp("App", "https://a.example.com/cb")
	h.createUser(app, `<img src=x onerror=alert(1)>`)

	body := h.get(appPath(app)).Body.String()
	if strings.Contains(body, "<img src=x") {
		t.Error("the username was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;img") {
		t.Error("the escaped username is not present")
	}
}

func TestUsersOfOtherApplicationsAreNotListed(t *testing.T) {
	h := newHarness(t)
	first := h.createApp("First", "https://a.example.com/cb")
	second := h.createApp("Second", "https://b.example.com/cb")
	h.createUser(first, "only-in-first")
	h.createUser(second, "only-in-second")

	body := h.get(appPath(first)).Body.String()
	if strings.Contains(body, "only-in-second") {
		t.Error("another application's user is listed")
	}
	if !strings.Contains(body, "only-in-first") {
		t.Error("the application's own user is missing")
	}
}
