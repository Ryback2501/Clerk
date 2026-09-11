package adminauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests pin the single detail that silently breaks the whole
// integration: which claim each provider's subject identifier comes from.
//
// Bouncer stores the identifier its own sign-in recorded — passport's
// profile.id. Sending a different one produces a 404 from the access check and
// looks exactly like "this person has no role", with nothing in any log to say
// the identifier was wrong.

func TestGoogleUsesTheOIDCSubject(t *testing.T) {
	claims := map[string]any{
		"sub":   "109876543210",
		"oid":   "should-not-be-used",
		"name":  "Ada Lovelace",
		"email": "ada@example.com",
	}

	got, err := googleIdentity(rawClaims(t, claims), nil)
	if err != nil {
		t.Fatalf("googleIdentity() error: %v", err)
	}
	if got.Subject != "109876543210" {
		t.Errorf("Subject = %q, want the OIDC sub claim", got.Subject)
	}
	if got.Provider != "google" {
		t.Errorf("Provider = %q, want google (the name Bouncer keys on)", got.Provider)
	}
	if got.Name != "Ada Lovelace" {
		t.Errorf("Name = %q, want the display name", got.Name)
	}
}

// Microsoft issues sub as a pairwise identifier, different for every client
// application. Bouncer recorded the directory object id instead, so using sub
// here would never match and every Microsoft administrator would be refused.
func TestMicrosoftUsesTheObjectIDNotTheSubject(t *testing.T) {
	claims := map[string]any{
		"sub":  "pairwise-value-unique-to-this-client",
		"oid":  "00000000-1111-2222-3333-444444444444",
		"name": "Grace Hopper",
	}

	got, err := microsoftIdentity(rawClaims(t, claims), nil)
	if err != nil {
		t.Fatalf("microsoftIdentity() error: %v", err)
	}
	if got.Subject == "pairwise-value-unique-to-this-client" {
		t.Fatal("Microsoft identity used the sub claim; it is pairwise per client and will never match what Bouncer stored")
	}
	if got.Subject != "00000000-1111-2222-3333-444444444444" {
		t.Errorf("Subject = %q, want the oid claim", got.Subject)
	}
	if got.Provider != "microsoft" {
		t.Errorf("Provider = %q, want microsoft", got.Provider)
	}
}

// Without oid there is nothing that can match, so failing loudly beats sending
// a value that will be silently rejected downstream.
func TestMicrosoftWithoutAnObjectIDIsAnError(t *testing.T) {
	claims := map[string]any{"sub": "only-a-sub", "name": "Nobody"}

	if _, err := microsoftIdentity(rawClaims(t, claims), nil); err == nil {
		t.Fatal("a Microsoft token with no oid claim was accepted")
	}
}

func TestLinkedInUsesTheOIDCSubject(t *testing.T) {
	claims := map[string]any{"sub": "linkedin-member-id", "name": "Alan Turing"}

	got, err := linkedinIdentity(rawClaims(t, claims), nil)
	if err != nil {
		t.Fatalf("linkedinIdentity() error: %v", err)
	}
	if got.Subject != "linkedin-member-id" {
		t.Errorf("Subject = %q, want the userinfo sub claim", got.Subject)
	}
	if got.Provider != "linkedin" {
		t.Errorf("Provider = %q, want linkedin", got.Provider)
	}
}

// GitHub has no OIDC at all, so the identity comes from its REST API and the
// subject is the numeric user id rendered as a string.
func TestGitHubUsesTheNumericUserID(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gho_test" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		if got := r.Header.Get("Accept"); got == "" {
			t.Error("the GitHub API call sends no Accept header")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    583231,
			"login": "octocat",
			"name":  "The Octocat",
		})
	}))
	defer api.Close()

	got, err := gitHubIdentity(context.Background(), api.Client(), api.URL, "gho_test")
	if err != nil {
		t.Fatalf("gitHubIdentity() error: %v", err)
	}
	if got.Subject != "583231" {
		t.Errorf("Subject = %q, want the numeric id as a string", got.Subject)
	}
	if got.Provider != "github" {
		t.Errorf("Provider = %q, want github", got.Provider)
	}
	if got.Name != "The Octocat" {
		t.Errorf("Name = %q, want the display name", got.Name)
	}
}

// A GitHub account with no display name still has a login to show.
func TestGitHubFallsBackToTheLogin(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octocat", "name": ""})
	}))
	defer api.Close()

	got, err := gitHubIdentity(context.Background(), api.Client(), api.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "octocat" {
		t.Errorf("Name = %q, want the login as a fallback", got.Name)
	}
}

func TestGitHubRejectsAnIdentityWithoutAnID(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"login": "octocat"})
	}))
	defer api.Close()

	if _, err := gitHubIdentity(context.Background(), api.Client(), api.URL, "tok"); err == nil {
		t.Error("a GitHub response with no id was accepted")
	}
}

func TestGitHubReportsAPIFailures(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer api.Close()

	if _, err := gitHubIdentity(context.Background(), api.Client(), api.URL, "tok"); err == nil {
		t.Error("a 401 from the GitHub API was treated as success")
	}
}

// The provider names are the exact strings Bouncer stores alongside each sub.
func TestProviderNamesMatchWhatBouncerRecords(t *testing.T) {
	for _, want := range []string{"google", "github", "microsoft", "linkedin"} {
		if _, ok := SupportedProviders[want]; !ok {
			t.Errorf("provider %q is not supported; Bouncer records that name", want)
		}
	}
	for name := range SupportedProviders {
		if name != strings.ToLower(name) {
			t.Errorf("provider name %q is not lowercase; Bouncer stores lowercase names", name)
		}
	}
}

func rawClaims(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
