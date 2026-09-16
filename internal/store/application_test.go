package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Ryback2501/Clerk/internal/secret"
)

func ctx() context.Context { return context.Background() }

func createApp(t *testing.T, s *Store, name string, uris ...string) (*Application, string) {
	t.Helper()
	app, plain, err := s.CreateApplication(ctx(), name, uris)
	if err != nil {
		t.Fatalf("CreateApplication(%q) error: %v", name, err)
	}
	return app, plain
}

// Acceptance criteria 2, 3, 4, 5.
func TestCreateApplicationGeneratesCredentials(t *testing.T) {
	s := openTemp(t)

	app, plain := createApp(t, s, "My Test Application", "https://app.example.com/cb")

	if app.ClientID == "" {
		t.Error("client id was not generated")
	}
	if plain == "" {
		t.Fatal("the client secret was not returned to the caller; it can never be shown again")
	}

	// Only a hash is persisted, and it must verify against the plaintext.
	var stored string
	if err := s.DB().QueryRow(`SELECT client_secret_hash FROM applications WHERE id = ?`, app.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == plain {
		t.Fatal("the client secret is stored in plaintext")
	}
	if strings.Contains(stored, plain) {
		t.Fatal("the stored hash contains the plaintext secret")
	}
	if !secret.VerifySecret(stored, plain) {
		t.Error("the stored hash does not verify against the returned secret")
	}

	// The struct handed back to the UI must never carry the hash.
	if strings.Contains(app.ClientID, stored) {
		t.Error("the client id embeds the secret hash")
	}
}

func TestCreateApplicationGeneratesUniqueCredentialsPerApplication(t *testing.T) {
	s := openTemp(t)

	a, aSecret := createApp(t, s, "App A")
	b, bSecret := createApp(t, s, "App B")

	if a.ClientID == b.ClientID {
		t.Error("two applications share a client id")
	}
	if aSecret == bSecret {
		t.Error("two applications share a client secret")
	}
}

func TestCreateApplicationRejectsBadInput(t *testing.T) {
	s := openTemp(t)

	for _, tc := range []struct {
		name    string
		appName string
		uris    []string
		wantSub string
	}{
		{"empty name", "", nil, "name"},
		{"blank name", "   ", nil, "name"},
		{"relative redirect uri", "App", []string{"/callback"}, "absolute"},
		{"redirect uri with fragment", "App", []string{"https://a.example.com/cb#x"}, "fragment"},
		{"unparseable redirect uri", "App", []string{"://nope"}, "redirect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := s.CreateApplication(ctx(), tc.appName, tc.uris); err == nil {
				t.Fatalf("CreateApplication accepted %s", tc.name)
			} else if !strings.Contains(strings.ToLower(err.Error()), tc.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// A failed create must not leave a half-built application behind.
func TestCreateApplicationIsAtomic(t *testing.T) {
	s := openTemp(t)

	if _, _, err := s.CreateApplication(ctx(), "App", []string{"https://ok.example.com/cb", "not-a-url"}); err == nil {
		t.Fatal("CreateApplication accepted an invalid redirect URI")
	}

	apps, err := s.ListApplications(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("a failed create left %d application(s) behind", len(apps))
	}
}

// Acceptance criterion 7.
func TestApplicationKeepsMultipleRedirectURIs(t *testing.T) {
	s := openTemp(t)
	want := []string{"https://a.example.com/cb", "https://b.example.com/cb"}

	app, _ := createApp(t, s, "App", want...)

	got, err := s.GetApplication(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RedirectURIs) != len(want) {
		t.Fatalf("got %d redirect URIs, want %d", len(got.RedirectURIs), len(want))
	}
	for i, uri := range want {
		if got.RedirectURIs[i] != uri {
			t.Errorf("redirect URI %d = %q, want %q", i, got.RedirectURIs[i], uri)
		}
	}
}

func TestAddAndRemoveRedirectURI(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://a.example.com/cb")

	if err := s.AddRedirectURI(ctx(), app.ID, "https://b.example.com/cb"); err != nil {
		t.Fatalf("AddRedirectURI() error: %v", err)
	}
	if err := s.AddRedirectURI(ctx(), app.ID, "https://b.example.com/cb"); err == nil {
		t.Error("the same redirect URI was added twice")
	}
	if err := s.AddRedirectURI(ctx(), app.ID, "javascript:alert(1)"); err == nil {
		t.Error("a non-http redirect URI was accepted")
	}

	if err := s.RemoveRedirectURI(ctx(), app.ID, "https://a.example.com/cb"); err != nil {
		t.Fatalf("RemoveRedirectURI() error: %v", err)
	}
	got, err := s.GetApplication(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://b.example.com/cb" {
		t.Errorf("redirect URIs = %v, want just the added one", got.RedirectURIs)
	}

	if err := s.RemoveRedirectURI(ctx(), app.ID, "https://never-registered.example.com/cb"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing an unregistered URI returned %v, want ErrNotFound", err)
	}
}

// Acceptance criterion 6: an administrator must never have to delete and
// recreate an application merely because the secret was lost.
func TestRegenerateClientSecretInvalidatesTheOldOne(t *testing.T) {
	s := openTemp(t)
	app, original := createApp(t, s, "App")

	regenerated, err := s.RegenerateClientSecret(ctx(), app.ID)
	if err != nil {
		t.Fatalf("RegenerateClientSecret() error: %v", err)
	}
	if regenerated == original {
		t.Fatal("regeneration returned the same secret")
	}

	var stored string
	if err := s.DB().QueryRow(`SELECT client_secret_hash FROM applications WHERE id = ?`, app.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !secret.VerifySecret(stored, regenerated) {
		t.Error("the new secret does not verify against the stored hash")
	}
	if secret.VerifySecret(stored, original) {
		t.Error("the previous secret still verifies after regeneration")
	}

	// Regeneration must not disturb the client id clients are configured with.
	after, err := s.GetApplication(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ClientID != app.ClientID {
		t.Errorf("client id changed on secret regeneration: %q -> %q", app.ClientID, after.ClientID)
	}
}

func TestGetApplicationByClientID(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://a.example.com/cb")

	got, err := s.GetApplicationByClientID(ctx(), app.ClientID)
	if err != nil {
		t.Fatalf("GetApplicationByClientID() error: %v", err)
	}
	if got.ID != app.ID {
		t.Errorf("got application %d, want %d", got.ID, app.ID)
	}
	if len(got.RedirectURIs) != 1 {
		t.Errorf("redirect URIs were not loaded: %v", got.RedirectURIs)
	}

	if _, err := s.GetApplicationByClientID(ctx(), "no-such-client"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown client id returned %v, want ErrNotFound", err)
	}
}

func TestGetApplicationUnknownIDIsNotFound(t *testing.T) {
	s := openTemp(t)
	if _, err := s.GetApplication(ctx(), 4242); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestListApplicationsIsOrderedAndCarriesNoSecrets(t *testing.T) {
	s := openTemp(t)
	createApp(t, s, "Zulu")
	createApp(t, s, "Alpha")

	apps, err := s.ListApplications(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d applications, want 2", len(apps))
	}
	if apps[0].Name != "Alpha" || apps[1].Name != "Zulu" {
		t.Errorf("applications = [%q %q], want them ordered by name", apps[0].Name, apps[1].Name)
	}
}

// Acceptance criterion 27.
func TestDeleteApplicationRemovesItAndItsUsers(t *testing.T) {
	s := openTemp(t)
	doomed, _ := createApp(t, s, "Doomed", "https://a.example.com/cb")
	keep, _ := createApp(t, s, "Keeper", "https://b.example.com/cb")

	if err := insertUser(t, s, doomed.ID, "david", "sub-doomed"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(t, s, keep.ID, "david", "sub-keep"); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteApplication(ctx(), doomed.ID); err != nil {
		t.Fatalf("DeleteApplication() error: %v", err)
	}

	if _, err := s.GetApplication(ctx(), doomed.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the application still exists: %v", err)
	}
	for table, want := range map[string]int{"users": 0, "redirect_uris": 0} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE application_id = ?`, doomed.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s: %d rows remain for the deleted application, want %d", table, n, want)
		}
	}

	// Acceptance criterion 28: the other application is untouched.
	if _, err := s.GetApplication(ctx(), keep.ID); err != nil {
		t.Errorf("deleting one application affected another: %v", err)
	}
	var survivors int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE application_id = ?`, keep.ID).Scan(&survivors); err != nil {
		t.Fatal(err)
	}
	if survivors != 1 {
		t.Errorf("the surviving application has %d users, want 1", survivors)
	}
}

func TestDeleteUnknownApplicationIsNotFound(t *testing.T) {
	s := openTemp(t)
	if err := s.DeleteApplication(ctx(), 4242); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// Callers must be able to tell "the administrator typed something wrong" from
// "the database is broken": the first is a 422 with the message shown, the
// second a 500 with the detail kept in the log.
func TestValidationFailuresAreDistinguishableFromInternalErrors(t *testing.T) {
	s := openTemp(t)

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"empty application name", func() error {
			_, _, err := s.CreateApplication(ctx(), "", nil)
			return err
		}},
		{"malformed redirect uri", func() error {
			_, _, err := s.CreateApplication(ctx(), "App", []string{"nope"})
			return err
		}},
		{"non-http redirect uri on add", func() error {
			app, _ := createApp(t, s, "App2")
			return s.AddRedirectURI(ctx(), app.ID, "javascript:alert(1)")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrValidation) {
				t.Errorf("error %v is not marked as a validation failure", err)
			}
		})
	}
}

// Pasting the same URI twice into the form is an obvious typo, not a reason to
// reject the whole registration with a constraint violation.
func TestCreateApplicationTolueratesRepeatedRedirectURIs(t *testing.T) {
	s := openTemp(t)

	app, _, err := s.CreateApplication(ctx(), "App", []string{
		"https://a.example.com/cb",
		"https://a.example.com/cb",
		"https://b.example.com/cb",
	})
	if err != nil {
		t.Fatalf("CreateApplication() rejected a repeated redirect URI: %v", err)
	}
	if len(app.RedirectURIs) != 2 {
		t.Errorf("got %d redirect URIs, want the 2 distinct ones: %v", len(app.RedirectURIs), app.RedirectURIs)
	}
}

func TestCountUsers(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")
	other, _ := createApp(t, s, "Other")

	for i, name := range []string{"a", "b", "c"} {
		if err := insertUser(t, s, app.ID, name, "sub-"+name+string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := insertUser(t, s, other.ID, "z", "sub-z"); err != nil {
		t.Fatal(err)
	}

	got, err := s.CountUsers(ctx(), app.ID)
	if err != nil {
		t.Fatalf("CountUsers() error: %v", err)
	}
	if got != 3 {
		t.Errorf("CountUsers() = %d, want 3", got)
	}
}

// Two applications with the same name are indistinguishable in the admin list,
// so the name is claimed exclusively — ignoring case and surrounding or
// repeated whitespace, which the eye does not distinguish either.
func TestCreateApplicationRejectsADuplicateName(t *testing.T) {
	s := openTemp(t)
	createApp(t, s, "My Test Application")

	for _, name := range []string{
		"My Test Application",
		"my test application",
		"  My Test Application  ",
		"My  Test   Application",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := s.CreateApplication(ctx(), name, nil)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("CreateApplication(%q) error = %v, want a validation error", name, err)
			}
			if !strings.Contains(err.Error(), "already exists") {
				t.Errorf("error = %v, want it to say the name already exists", err)
			}
		})
	}

	apps, err := s.ListApplications(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Errorf("%d applications exist, want the one that was created", len(apps))
	}
}

func TestRenameApplication(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "Before", "https://a.example.com/cb")
	if _, err := s.CreateUser(ctx(), app.ID, "david"); err != nil {
		t.Fatal(err)
	}

	if err := s.RenameApplication(ctx(), app.ID, "  After  "); err != nil {
		t.Fatalf("RenameApplication() error: %v", err)
	}

	renamed, err := s.GetApplication(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "After" {
		t.Errorf("name = %q, want the trimmed new name", renamed.Name)
	}
	// Renaming is only a label change: nothing a client depends on may move.
	if renamed.ClientID != app.ClientID {
		t.Error("the client id changed with the name")
	}
	if len(renamed.RedirectURIs) != 1 {
		t.Errorf("redirect URIs = %v, want them kept", renamed.RedirectURIs)
	}
	users, err := s.ListUsers(ctx(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Errorf("%d users survived the rename, want 1", len(users))
	}
}

func TestRenameApplicationRejectsANameInUse(t *testing.T) {
	s := openTemp(t)
	first, _ := createApp(t, s, "First")
	createApp(t, s, "Second")

	err := s.RenameApplication(ctx(), first.ID, "second")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("error = %v, want a validation error", err)
	}

	unchanged, _ := s.GetApplication(ctx(), first.ID)
	if unchanged.Name != "First" {
		t.Errorf("name = %q, want it unchanged after a rejected rename", unchanged.Name)
	}
}

// An application never collides with itself, so its own name may be restyled.
func TestRenameApplicationAcceptsItsOwnName(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "My Application")

	if err := s.RenameApplication(ctx(), app.ID, "MY APPLICATION"); err != nil {
		t.Fatalf("RenameApplication() error: %v", err)
	}
	renamed, _ := s.GetApplication(ctx(), app.ID)
	if renamed.Name != "MY APPLICATION" {
		t.Errorf("name = %q, want the new capitalisation", renamed.Name)
	}
}

func TestRenameApplicationRejectsABlankName(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App")

	if err := s.RenameApplication(ctx(), app.ID, "   "); !errors.Is(err, ErrValidation) {
		t.Errorf("error = %v, want a validation error", err)
	}
}

func TestRenameApplicationReportsAnUnknownApplication(t *testing.T) {
	s := openTemp(t)
	if err := s.RenameApplication(ctx(), 4242, "Whatever"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestNameIsAvailable(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "Taken")

	for _, tc := range []struct {
		name    string
		exclude int64
		want    bool
	}{
		{"Taken", 0, false},
		{"  taken ", 0, false},
		{"Free", 0, true},
		{"Taken", app.ID, true}, // its own name, when it is the one being renamed
		{"   ", 0, false},
	} {
		got, err := s.NameIsAvailable(ctx(), tc.name, tc.exclude)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("NameIsAvailable(%q, exclude=%d) = %v, want %v", tc.name, tc.exclude, got, tc.want)
		}
	}
}

func TestUpdateRedirectURI(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://a.example.com/cb", "https://b.example.com/cb")

	if err := s.UpdateRedirectURI(ctx(), app.ID, "https://a.example.com/cb", " https://new.example.com/cb "); err != nil {
		t.Fatalf("UpdateRedirectURI() error: %v", err)
	}

	updated, _ := s.GetApplication(ctx(), app.ID)
	want := []string{"https://b.example.com/cb", "https://new.example.com/cb"}
	if len(updated.RedirectURIs) != len(want) {
		t.Fatalf("redirect URIs = %v, want %v", updated.RedirectURIs, want)
	}
	for _, uri := range want {
		if !slices.Contains(updated.RedirectURIs, uri) {
			t.Errorf("redirect URIs = %v, want them to contain %q", updated.RedirectURIs, uri)
		}
	}
}

func TestUpdateRedirectURIRejectsBadAndDuplicateValues(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://a.example.com/cb", "https://b.example.com/cb")

	for _, tc := range []struct{ name, to, want string }{
		{"not a url", "not-a-url", "absolute"},
		{"javascript", "javascript:alert(1)", "redirect"},
		{"already registered", "https://b.example.com/cb", "already"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.UpdateRedirectURI(ctx(), app.ID, "https://a.example.com/cb", tc.to)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("error = %v, want a validation error", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// Leaving a URI as it is changes nothing and is not a conflict.
	if err := s.UpdateRedirectURI(ctx(), app.ID, "https://a.example.com/cb", "https://a.example.com/cb"); err != nil {
		t.Errorf("rewriting a URI to itself failed: %v", err)
	}

	app, _ = s.GetApplication(ctx(), app.ID)
	if len(app.RedirectURIs) != 2 {
		t.Errorf("redirect URIs = %v, want the original two", app.RedirectURIs)
	}
}

func TestUpdateRedirectURIReportsAnUnknownOriginal(t *testing.T) {
	s := openTemp(t)
	app, _ := createApp(t, s, "App", "https://a.example.com/cb")

	// A URI that is already gone is reported as gone whatever it would have
	// been changed to: the row the caller is editing no longer exists, and
	// answering "that value is invalid" would send them correcting the wrong
	// thing.
	for _, replacement := range []string{"https://new.example.com/cb", "not-a-url"} {
		err := s.UpdateRedirectURI(ctx(), app.ID, "https://gone.example.com/cb", replacement)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("UpdateRedirectURI(to %q) error = %v, want ErrNotFound", replacement, err)
		}
	}

	// Nor may one application edit another's.
	other, _ := createApp(t, s, "Other", "https://b.example.com/cb")
	if err := s.UpdateRedirectURI(ctx(), other.ID, "https://a.example.com/cb", "https://c.example.com/cb"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}
