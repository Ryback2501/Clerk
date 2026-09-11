// Package config loads and validates Clerk's runtime configuration from the
// environment. Every value is resolved once at startup so that a misconfigured
// deployment fails immediately and loudly rather than at the first token request.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Defaults applied when the corresponding environment variable is unset.
const (
	DefaultListenAddr     = ":8080"
	DefaultDBPath         = "/data/clerk.db"
	DefaultKeysPath       = "/keys/signing.pem"
	DefaultCodeTTL        = time.Minute
	DefaultAccessTokenTTL = time.Hour
	DefaultIDTokenTTL     = time.Hour
)

// Config is the fully validated runtime configuration.
type Config struct {
	// Issuer is the public base URL of this provider. It is published as the
	// "issuer" of the discovery document and as the "iss" claim of every ID
	// token, so it must match what clients are configured with exactly.
	Issuer *url.URL

	ListenAddr string
	DBPath     string
	KeysPath   string

	CodeTTL        time.Duration
	AccessTokenTTL time.Duration
	IDTokenTTL     time.Duration

	// AdminInsecure permits running with administration wide open, which is
	// the only mode available until the external sign-in adapter lands. It
	// must be set deliberately: defaulting to it would mean every image built
	// from this source exposes application creation, secret regeneration and
	// deletion to anyone who can reach the port.
	AdminInsecure bool
}

// Getenv reads an environment variable. Taking it as a parameter keeps Load
// pure, so tests never mutate real process state.
type Getenv func(string) string

// Load reads configuration via getenv and validates it. All problems found are
// reported together, so a misconfigured deployment needs one restart to fix
// rather than one per mistake.
func Load(getenv Getenv) (*Config, error) {
	var problems []error

	cfg := &Config{
		ListenAddr: withDefault(getenv("CLERK_LISTEN_ADDR"), DefaultListenAddr),
		DBPath:     withDefault(getenv("CLERK_DB_PATH"), DefaultDBPath),
		KeysPath:   withDefault(getenv("CLERK_KEYS_PATH"), DefaultKeysPath),
	}

	issuer, err := parseIssuer(getenv("CLERK_ISSUER"))
	if err != nil {
		problems = append(problems, err)
	}
	cfg.Issuer = issuer

	for _, d := range []struct {
		key    string
		target *time.Duration
		def    time.Duration
	}{
		{"CLERK_CODE_TTL", &cfg.CodeTTL, DefaultCodeTTL},
		{"CLERK_ACCESS_TOKEN_TTL", &cfg.AccessTokenTTL, DefaultAccessTokenTTL},
		{"CLERK_ID_TOKEN_TTL", &cfg.IDTokenTTL, DefaultIDTokenTTL},
	} {
		v, err := parseDuration(d.key, getenv(d.key), d.def)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		*d.target = v
	}

	insecure, err := parseBool("CLERK_ADMIN_INSECURE", getenv("CLERK_ADMIN_INSECURE"))
	if err != nil {
		problems = append(problems, err)
	}
	cfg.AdminInsecure = insecure

	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return cfg, nil
}

// parseBool accepts the spellings people actually type in a compose file.
func parseBool(key, raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false, got %q", key, raw)
	}
}

// parseIssuer enforces the shape OpenID Connect requires of an issuer
// identifier: an absolute http(s) URL with no query or fragment. A trailing
// slash is stripped so that concatenating endpoint paths cannot produce a
// double slash, which some strict clients reject.
func parseIssuer(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("CLERK_ISSUER is required (e.g. http://localhost:8080)")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("CLERK_ISSUER is not a valid URL: %w", err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("CLERK_ISSUER must use http or https, got %q", u.Scheme)
	case u.Host == "":
		return nil, fmt.Errorf("CLERK_ISSUER must include a host, got %q", raw)
	case u.RawQuery != "":
		return nil, fmt.Errorf("CLERK_ISSUER must not contain a query string, got %q", raw)
	case u.Fragment != "":
		return nil, fmt.Errorf("CLERK_ISSUER must not contain a fragment, got %q", raw)
	}

	// Strip every trailing slash, not just one: "https://host//" would otherwise
	// leave a path of "/", making the published issuer inconsistent with the
	// endpoint URLs derived from it (RFC 8414 section 3.3).
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func parseDuration(key, raw string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration (e.g. 60s, 5m): %w", key, err)
	}
	// Lifetimes are reported to clients in whole seconds, so anything under a
	// second truncates to zero and reads as already expired.
	if d < time.Second {
		return 0, fmt.Errorf("%s must be at least 1s, got %s", key, d)
	}
	return d, nil
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
