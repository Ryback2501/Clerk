package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// Identity is who an upstream provider says the browser belongs to.
//
// Subject is the value Bouncer is queried with, so it must be whatever that
// service recorded for this person — see the per-provider notes below.
type Identity struct {
	Subject  string
	Provider string
	Name     string
}

// ProviderKind describes how one upstream provider is spoken to.
type ProviderKind struct {
	// Name is the identifier Bouncer stores alongside each subject. It must
	// match exactly, in lowercase.
	Name string

	// Issuer is the OIDC issuer for discovery. Empty for GitHub, which has no
	// OIDC at all.
	Issuer string

	// Endpoint is used when there is no OIDC discovery to rely on.
	Endpoint oauth2.Endpoint

	// Scopes requested at authorization.
	Scopes []string

	// identityFromClaims reads an Identity out of a verified ID token.
	identityFromClaims func(raw []byte, userInfo []byte) (Identity, error)
}

// SupportedProviders is every upstream this build can sign administrators in
// with. The map keys are the names Bouncer records.
//
// The subject each one contributes is deliberately not uniform. Bouncer stores
// the identifier its own sign-in captured, and matching it is the whole of the
// integration:
//
//   - google    the OIDC sub claim
//   - microsoft the oid claim, never sub — Microsoft issues sub pairwise per
//     client application, so this provider's sub would differ from the one
//     Bouncer saw and would never match
//   - github    the numeric REST API user id, since GitHub has no OIDC
//   - linkedin  the userinfo sub claim
var SupportedProviders = map[string]ProviderKind{
	"google": {
		Name:               "google",
		Issuer:             "https://accounts.google.com",
		Scopes:             []string{"openid", "profile", "email"},
		identityFromClaims: googleIdentity,
	},
	"microsoft": {
		Name:               "microsoft",
		Issuer:             "https://login.microsoftonline.com/common/v2.0",
		Scopes:             []string{"openid", "profile", "email"},
		identityFromClaims: microsoftIdentity,
	},
	"linkedin": {
		Name:               "linkedin",
		Issuer:             "https://www.linkedin.com/oauth",
		Scopes:             []string{"openid", "profile", "email"},
		identityFromClaims: linkedinIdentity,
	},
	"github": {
		Name:     "github",
		Endpoint: endpoints.GitHub,
		Scopes:   []string{"read:user"},
	},
}

// gitHubAPIUser is the endpoint an access token is exchanged for an identity at.
const gitHubAPIUser = "https://api.github.com"

func googleIdentity(raw []byte, _ []byte) (Identity, error) {
	var c struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Identity{}, fmt.Errorf("decode google claims: %w", err)
	}
	if c.Sub == "" {
		return Identity{}, errors.New("google identity has no sub claim")
	}
	return Identity{Subject: c.Sub, Provider: "google", Name: displayName(c.Name, c.Email)}, nil
}

func microsoftIdentity(raw []byte, _ []byte) (Identity, error) {
	var c struct {
		OID   string `json:"oid"`
		Name  string `json:"name"`
		Email string `json:"email"`
		UPN   string `json:"preferred_username"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Identity{}, fmt.Errorf("decode microsoft claims: %w", err)
	}
	// Deliberately not falling back to sub. A pairwise identifier would be
	// accepted here and then silently fail every authorization check, which is
	// far harder to diagnose than refusing outright.
	if c.OID == "" {
		return Identity{}, errors.New("microsoft identity has no oid claim; sub cannot be used because it is pairwise per client")
	}
	return Identity{Subject: c.OID, Provider: "microsoft", Name: displayName(c.Name, c.Email, c.UPN)}, nil
}

func linkedinIdentity(raw []byte, _ []byte) (Identity, error) {
	var c struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Identity{}, fmt.Errorf("decode linkedin claims: %w", err)
	}
	if c.Sub == "" {
		return Identity{}, errors.New("linkedin identity has no sub claim")
	}
	return Identity{Subject: c.Sub, Provider: "linkedin", Name: displayName(c.Name, c.Email)}, nil
}

// gitHubIdentity resolves an access token to a GitHub account.
//
// GitHub is not an OpenID Connect provider, so there is no ID token to read:
// the identity comes from the REST API, and the subject is the numeric account
// id, which is what Bouncer recorded.
func gitHubIdentity(ctx context.Context, client *http.Client, apiBase, accessToken string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("call the github api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("github api returned %s", resp.Status)
	}

	// Bounded read: the response is small and comes from outside.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, fmt.Errorf("read the github api response: %w", err)
	}

	var account struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &account); err != nil {
		return Identity{}, fmt.Errorf("decode the github api response: %w", err)
	}
	if account.ID == 0 {
		return Identity{}, errors.New("github identity has no account id")
	}

	return Identity{
		Subject:  strconv.FormatInt(account.ID, 10),
		Provider: "github",
		Name:     displayName(account.Name, account.Login),
	}, nil
}

// displayName picks the first non-empty candidate, for the UI only.
func displayName(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return "Administrator"
}

// mustJSON re-encodes claims that were decoded into a map. Marshalling a
// map[string]any of JSON-derived values cannot fail.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
