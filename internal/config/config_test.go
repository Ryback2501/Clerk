package config

import (
	"strings"
	"testing"
	"time"
)

// envMap adapts a map to the Getenv signature so tests never touch process state.
func envMap(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

// runnable adds the minimum administration setup a configuration needs to be
// accepted, so a test about something else does not have to restate it.
func runnable(m map[string]string) Getenv {
	if m["CLERK_GOOGLE_CLIENT_ID"] == "" && m["CLERK_BOUNCER_URL"] == "" {
		m["CLERK_BOUNCER_URL"] = "http://bouncer.internal"
		m["CLERK_BOUNCER_API_KEY"] = "bncr_test"
		m["CLERK_GOOGLE_CLIENT_ID"] = "google-id"
		m["CLERK_GOOGLE_CLIENT_SECRET"] = "google-secret"
	}
	return envMap(m)
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(runnable(map[string]string{"CLERK_ISSUER": "http://localhost:8080"}))
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if got := cfg.ListenAddr; got != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", got, DefaultListenAddr)
	}
	if got := cfg.DBPath; got != DefaultDBPath {
		t.Errorf("DBPath = %q, want %q", got, DefaultDBPath)
	}
	if got := cfg.KeysPath; got != DefaultKeysPath {
		t.Errorf("KeysPath = %q, want %q", got, DefaultKeysPath)
	}
	if got := cfg.CodeTTL; got != DefaultCodeTTL {
		t.Errorf("CodeTTL = %s, want %s", got, DefaultCodeTTL)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	cfg, err := Load(runnable(map[string]string{
		"CLERK_ISSUER":           "https://idp.example.com",
		"CLERK_LISTEN_ADDR":      ":9999",
		"CLERK_DB_PATH":          "/tmp/clerk.db",
		"CLERK_KEYS_PATH":        "/tmp/signing.pem",
		"CLERK_CODE_TTL":         "30s",
		"CLERK_ACCESS_TOKEN_TTL": "15m",
		"CLERK_ID_TOKEN_TTL":     "2h",
	}))
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if got, want := cfg.ListenAddr, ":9999"; got != want {
		t.Errorf("ListenAddr = %q, want %q", got, want)
	}
	if got, want := cfg.CodeTTL, 30*time.Second; got != want {
		t.Errorf("CodeTTL = %s, want %s", got, want)
	}
	if got, want := cfg.AccessTokenTTL, 15*time.Minute; got != want {
		t.Errorf("AccessTokenTTL = %s, want %s", got, want)
	}
	if got, want := cfg.IDTokenTTL, 2*time.Hour; got != want {
		t.Errorf("IDTokenTTL = %s, want %s", got, want)
	}
}

// A trailing slash on the issuer would otherwise produce "//authorize" in the
// discovery document, which strict OIDC clients reject.
func TestLoadStripsIssuerTrailingSlash(t *testing.T) {
	cfg, err := Load(runnable(map[string]string{"CLERK_ISSUER": "https://idp.example.com/oidc/"}))
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got, want := cfg.Issuer.String(), "https://idp.example.com/oidc"; got != want {
		t.Errorf("Issuer = %q, want %q", got, want)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{
			name:    "missing issuer",
			env:     map[string]string{},
			wantSub: "CLERK_ISSUER is required",
		},
		{
			name:    "issuer with unsupported scheme",
			env:     map[string]string{"CLERK_ISSUER": "ftp://idp.example.com"},
			wantSub: "must use http or https",
		},
		{
			name:    "issuer without host",
			env:     map[string]string{"CLERK_ISSUER": "https://"},
			wantSub: "must include a host",
		},
		{
			name:    "issuer with query string",
			env:     map[string]string{"CLERK_ISSUER": "https://idp.example.com?a=b"},
			wantSub: "must not contain a query string",
		},
		{
			name:    "issuer with fragment",
			env:     map[string]string{"CLERK_ISSUER": "https://idp.example.com#frag"},
			wantSub: "must not contain a fragment",
		},
		{
			name: "unparseable duration",
			env: map[string]string{
				"CLERK_ISSUER":   "http://localhost:8080",
				"CLERK_CODE_TTL": "sixty",
			},
			wantSub: "not a valid duration",
		},
		{
			name: "non-positive duration",
			env: map[string]string{
				"CLERK_ISSUER":   "http://localhost:8080",
				"CLERK_CODE_TTL": "-5s",
			},
			wantSub: "must be at least 1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(runnable(tt.env))
			if err == nil {
				t.Fatalf("Load() succeeded with %+v, want error containing %q", cfg, tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantSub)
			}
		})
	}
}

// All configuration problems should surface together so operators need one
// restart to fix a broken deployment, not one per mistake.
func TestLoadReportsAllProblemsAtOnce(t *testing.T) {
	_, err := Load(envMap(map[string]string{
		"CLERK_CODE_TTL":     "nope",
		"CLERK_ID_TOKEN_TTL": "-1s",
	}))
	if err == nil {
		t.Fatal("Load() succeeded, want error")
	}
	for _, want := range []string{"CLERK_ISSUER is required", "CLERK_CODE_TTL", "CLERK_ID_TOKEN_TTL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing mention of %q", err, want)
		}
	}
}

func TestTokenLifetimesMustBeAtLeastOneSecond(t *testing.T) {
	for _, key := range []string{"CLERK_CODE_TTL", "CLERK_ACCESS_TOKEN_TTL", "CLERK_ID_TOKEN_TTL"} {
		t.Run(key, func(t *testing.T) {
			_, err := Load(runnable(map[string]string{
				"CLERK_ISSUER": "http://localhost:8080",
				key:            "500ms",
			}))
			if err == nil {
				t.Errorf("%s=500ms was accepted; it truncates to expires_in=0", key)
			}

			if _, err := Load(runnable(map[string]string{
				"CLERK_ISSUER": "http://localhost:8080",
				key:            "1s",
			})); err != nil {
				t.Errorf("%s=1s was rejected: %v", key, err)
			}
		})
	}
}

func TestAdminOAuthConfiguration(t *testing.T) {
	base := map[string]string{
		"CLERK_ISSUER":               "https://clerk.example.com",
		"CLERK_BOUNCER_URL":          "http://bouncer.internal",
		"CLERK_BOUNCER_API_KEY":      "bncr_secret",
		"CLERK_GOOGLE_CLIENT_ID":     "google-id",
		"CLERK_GOOGLE_CLIENT_SECRET": "google-secret",
		"CLERK_GITHUB_CLIENT_ID":     "github-id",
		"CLERK_GITHUB_CLIENT_SECRET": "github-secret",
	}

	cfg, err := Load(envMap(base))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if got := len(cfg.AdminProviders); got != 2 {
		t.Fatalf("configured %d providers, want 2: %v", got, cfg.AdminProviders)
	}
	if cfg.AdminProviders["google"].ClientID != "google-id" {
		t.Errorf("google client id = %q", cfg.AdminProviders["google"].ClientID)
	}
	if cfg.BouncerURL != "http://bouncer.internal" {
		t.Errorf("BouncerURL = %q", cfg.BouncerURL)
	}
	// The default required role must be explicit, not empty-means-anything.
	if cfg.BouncerRequiredRole != "admin" {
		t.Errorf("BouncerRequiredRole = %q, want admin by default", cfg.BouncerRequiredRole)
	}
}

// A provider with only half its credentials is a deployment mistake that would
// otherwise show up as that provider silently missing from the sign-in page.
func TestHalfConfiguredProviderIsRejected(t *testing.T) {
	_, err := Load(envMap(map[string]string{
		"CLERK_ISSUER":           "https://clerk.example.com",
		"CLERK_BOUNCER_URL":      "http://bouncer.internal",
		"CLERK_BOUNCER_API_KEY":  "bncr_secret",
		"CLERK_GOOGLE_CLIENT_ID": "google-id",
	}))
	if err == nil {
		t.Fatal("a provider with a client id but no secret was accepted")
	}
	if !strings.Contains(err.Error(), "GOOGLE") {
		t.Errorf("error %v does not name the provider at fault", err)
	}
}

// Real administration configuration is always required: there is no way to
// run the admin interface unauthenticated.
func TestAdminConfigurationIsRequired(t *testing.T) {
	_, err := Load(envMap(map[string]string{"CLERK_ISSUER": "https://clerk.example.com"}))
	if err == nil {
		t.Fatal("a configuration without admin sign-in was accepted")
	}
}

// Configuring sign-in without the role service would authenticate people and
// then have nothing to authorize them against.
func TestProvidersWithoutBouncerAreRejected(t *testing.T) {
	_, err := Load(envMap(map[string]string{
		"CLERK_ISSUER":               "https://clerk.example.com",
		"CLERK_GOOGLE_CLIENT_ID":     "id",
		"CLERK_GOOGLE_CLIENT_SECRET": "secret",
	}))
	if err == nil {
		t.Fatal("OAuth providers were accepted with no role service configured")
	}
}
