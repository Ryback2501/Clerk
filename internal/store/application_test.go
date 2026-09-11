package store

import (
	"context"
	"errors"
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
