package store

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func mustCreateUser(t *testing.T, s *Store, appID int64, username string) *User {
	t.Helper()
	u, err := s.CreateUser(ctx(), appID, username)
	if err != nil {
		t.Fatalf("CreateUser(%q) error: %v", username, err)
	}
	return u
}

// Acceptance criterion 8.
func TestCreateUser(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	u := mustCreateUser(t, s, app.ID, "david")

	if u.Username != "david" {
		t.Errorf("Username = %q, want %q", u.Username, "david")
	}
	if u.ApplicationID != app.ID {
		t.Errorf("ApplicationID = %d, want %d", u.ApplicationID, app.ID)
	}
	if u.Sub == "" {
		t.Fatal("no sub was generated")
	}
}

// Acceptance criterion 11, and the rules in §5 about what a sub may not be.
func TestSubIsOpaqueAndUnrelatedToTheUser(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	u := mustCreateUser(t, s, app.ID, "david")

	// Not derived from the user-visible name.
	if strings.Contains(strings.ToLower(u.Sub), "david") {
		t.Errorf("sub %q contains the username", u.Sub)
	}
	// Not the database primary key.
	if u.Sub == strconv.FormatInt(u.ID, 10) {
		t.Errorf("sub %q is the primary key", u.Sub)
	}
	if _, err := strconv.Atoi(u.Sub); err == nil {
		t.Errorf("sub %q is a bare number, which risks exposing an internal counter", u.Sub)
	}
	// Unguessable: 128 bits, base64url encoded.
	if len(u.Sub) < 22 {
		t.Errorf("sub %q is only %d chars; too little entropy", u.Sub, len(u.Sub))
	}
	if strings.ContainsAny(u.Sub, "+/=") {
		t.Errorf("sub %q is not base64url; it must be safe in a JWT claim and a URL", u.Sub)
	}
}

// Acceptance criterion 11: subs are unique across the entire provider, not just
// within an application.
func TestSubsAreGloballyUniqueAcrossApplications(t *testing.T) {
	s := openTemp(t)
	a, _ := createApp(t, s, "App A")
	b, _ := createApp(t, s, "App B")

	seen := make(map[string]bool)
	for i := range 50 {
		name := "user" + strconv.Itoa(i)
		for _, appID := range []int64{a.ID, b.ID} {
			u := mustCreateUser(t, s, appID, name)
			if seen[u.Sub] {
				t.Fatalf("sub %q was issued twice", u.Sub)
			}
			seen[u.Sub] = true
		}
	}
}

// Acceptance criterion 10: the same person-name in two applications is two
// different identities, and must not collapse to one subject.
func TestSameUsernameInTwoApplicationsGetsDifferentSubs(t *testing.T) {
	s := openTemp(t)
	a, _ := createApp(t, s, "App A")
	b, _ := createApp(t, s, "App B")

	first := mustCreateUser(t, s, a.ID, "david")
	second := mustCreateUser(t, s, b.ID, "david")

	if first.Sub == second.Sub {
		t.Error("the same username in two applications produced the same sub")
	}
}

// Acceptance criterion 9.
func TestDuplicateUsernameWithinOneApplicationIsRejected(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")
	mustCreateUser(t, s, app.ID, "david")

	_, err := s.CreateUser(ctx(), app.ID, "david")
	if err == nil {
		t.Fatal("a duplicate username was accepted")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("error %v is not marked as a validation failure", err)
	}
	if !strings.Contains(err.Error(), "david") {
		t.Errorf("error %v does not name the conflicting user", err)
	}
}

// Acceptance criterion 11: a user's sub must not change over their lifetime,
// or every client that stored it would lose track of the account.
func TestSubIsStableForTheLifetimeOfTheUser(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")
	created := mustCreateUser(t, s, app.ID, "david")

	for range 3 {
		got, err := s.GetUser(ctx(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Sub != created.Sub {
			t.Fatalf("sub changed: %q -> %q", created.Sub, got.Sub)
		}
	}

	byApp, err := s.ListUsers(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(byApp) != 1 || byApp[0].Sub != created.Sub {
		t.Error("the sub differs when read through the list")
	}
}

func TestCreateUserRejectsBadUsernames(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	for _, tc := range []struct {
		name     string
		username string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"contains a control character", "dav\x00id"},
		{"contains a newline", "david\nalice"},
		{"excessively long", strings.Repeat("a", 300)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.CreateUser(ctx(), app.ID, tc.username); err == nil {
				t.Errorf("CreateUser accepted a username that is %s", tc.name)
			} else if !errors.Is(err, ErrValidation) {
				t.Errorf("error %v is not marked as a validation failure", err)
			}
		})
	}
}

func TestCreateUserTrimsSurroundingWhitespace(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	u := mustCreateUser(t, s, app.ID, "  david  ")
	if u.Username != "david" {
		t.Errorf("Username = %q, want it trimmed", u.Username)
	}
	// The trimmed form is what uniqueness applies to.
	if _, err := s.CreateUser(ctx(), app.ID, "david"); err == nil {
		t.Error("a username differing only by surrounding whitespace was accepted as distinct")
	}
}

func TestCreateUserForUnknownApplicationFails(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CreateUser(ctx(), 4242, "david"); err == nil {
		t.Error("a user was created for an application that does not exist")
	}
}

func TestListUsersIsScopedToItsApplicationAndOrdered(t *testing.T) {
	s := openTemp(t)
	a, _ := createApp(t, s, "App A")
	b, _ := createApp(t, s, "App B")

	mustCreateUser(t, s, a.ID, "zulu")
	mustCreateUser(t, s, a.ID, "alpha")
	mustCreateUser(t, s, b.ID, "bravo")

	users, err := s.ListUsers(ctx(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2 (the other application's user must not appear)", len(users))
	}
	if users[0].Username != "alpha" || users[1].Username != "zulu" {
		t.Errorf("users = [%q %q], want them ordered by name", users[0].Username, users[1].Username)
	}
}

// Acceptance criterion 28.
func TestDeleteUserAffectsNothingElse(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")
	doomed := mustCreateUser(t, s, app.ID, "david")
	survivor := mustCreateUser(t, s, app.ID, "alice")

	if err := s.DeleteUser(ctx(), doomed.ID); err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}

	if _, err := s.GetUser(ctx(), doomed.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted user is still present: %v", err)
	}
	if _, err := s.GetApplication(ctx(), app.ID); err != nil {
		t.Errorf("deleting a user affected its application: %v", err)
	}
	got, err := s.GetUser(ctx(), survivor.ID)
	if err != nil {
		t.Fatalf("deleting one user removed another: %v", err)
	}
	if got.Sub != survivor.Sub {
		t.Error("the surviving user's sub changed")
	}
}

// Once a username is freed it can be reused — but the new account is a new
// identity and must not inherit the old subject.
func TestRecreatingADeletedUserIssuesANewSub(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	original := mustCreateUser(t, s, app.ID, "david")
	if err := s.DeleteUser(ctx(), original.ID); err != nil {
		t.Fatal(err)
	}
	recreated := mustCreateUser(t, s, app.ID, "david")

	if recreated.Sub == original.Sub {
		t.Error("a recreated user inherited the deleted user's sub")
	}
}

func TestDeleteUnknownUserIsNotFound(t *testing.T) {
	s := openTemp(t)
	if err := s.DeleteUser(ctx(), 4242); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestGetUserBySub(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")
	created := mustCreateUser(t, s, app.ID, "david")

	got, err := s.GetUserBySub(ctx(), created.Sub)
	if err != nil {
		t.Fatalf("GetUserBySub() error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("got user %d, want %d", got.ID, created.ID)
	}
	if _, err := s.GetUserBySub(ctx(), "no-such-sub"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown sub returned %v, want ErrNotFound", err)
	}
}
