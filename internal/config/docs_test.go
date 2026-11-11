package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Clerk's settings are documented in two places: .env.example and the table of
// every setting under "3. Configuration" in the README. These tests keep both
// in step with the code: every name Clerk reads must be in both places, both
// must list only names Clerk reads, and .env.example must be accepted as it is.
// The names Clerk reads are recorded from Load itself, never copied by hand.

const (
	envExamplePath = "../../.env.example"
	readmePath     = "../../README.md"
)

// notDocumented are names Clerk reads that the documents leave out on purpose.
var notDocumented = []string{
	"GITHUB_ISSUER", // GitHub has no OIDC issuer, so there is nothing to override.
}

func TestDocumentedSettingsMatchTheConfiguration(t *testing.T) {
	err := compareSettings(settingsClerkReads(),
		envExampleSettings(readFile(t, envExamplePath)),
		readmeSettings(t, readFile(t, readmePath)))
	if err != nil {
		t.Errorf("the documented settings do not match the configuration:\n%v", err)
	}
}

func TestEnvExampleIsAcceptedByTheConfiguration(t *testing.T) {
	if err := loadEnvExample(readFile(t, envExamplePath)); err != nil {
		t.Errorf(".env.example: %v", err)
	}
}

func TestEnvExampleHasTheOptionalIssuers(t *testing.T) {
	text := readFile(t, envExamplePath)
	for _, want := range []string{
		"# Only to use a different issuer than Google's own\n# GOOGLE_ISSUER=",
		"# Only to use a different issuer than LinkedIn's own\n# LINKEDIN_ISSUER=",
	} {
		if !strings.Contains(text, want) {
			t.Errorf(".env.example does not have, commented out with its comment:\n%s", want)
		}
	}
}

func TestSettingsCheckNamesAnUndocumentedSetting(t *testing.T) {
	read := append(settingsClerkReads(), "NEW_SETTING")
	env := envExampleSettings(readFile(t, envExamplePath))
	readme := readmeSettings(t, readFile(t, readmePath))

	err := compareSettings(read, env, readme)
	for _, want := range []string{
		"NEW_SETTING: missing from .env.example",
		"NEW_SETTING: missing from the README table",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got:\n%v", want, err)
		}
	}
}

func TestSettingsCheckNamesARemovedSetting(t *testing.T) {
	read := settingsClerkReads()
	env := envExampleSettings(readFile(t, envExamplePath))
	readme := readmeSettings(t, readFile(t, readmePath))

	t.Run("from .env.example", func(t *testing.T) {
		err := compareSettings(read, without(env, "DB_PATH"), readme)
		if err == nil || !strings.Contains(err.Error(), "DB_PATH: missing from .env.example") {
			t.Errorf("the removed line is not named:\n%v", err)
		}
	})
	t.Run("from the README table", func(t *testing.T) {
		err := compareSettings(read, env, without(readme, "CODE_TTL"))
		if err == nil || !strings.Contains(err.Error(), "CODE_TTL: missing from the README table") {
			t.Errorf("the removed row is not named:\n%v", err)
		}
	})
}

func TestSettingsCheckNamesAMadeUpSetting(t *testing.T) {
	read := settingsClerkReads()
	env := envExampleSettings(readFile(t, envExamplePath))
	readme := readmeSettings(t, readFile(t, readmePath))

	t.Run("in .env.example", func(t *testing.T) {
		err := compareSettings(read, append(env, "MADE_UP"), readme)
		if err == nil || !strings.Contains(err.Error(), "MADE_UP: in .env.example, but Clerk does not read it") {
			t.Errorf("the made-up setting is not named:\n%v", err)
		}
	})
	t.Run("in the README table", func(t *testing.T) {
		err := compareSettings(read, env, append(readme, "MADE_UP"))
		if err == nil || !strings.Contains(err.Error(), "MADE_UP: in the README table, but Clerk does not read it") {
			t.Errorf("the made-up setting is not named:\n%v", err)
		}
	})
}

func TestSettingsCheckReportsClerksOwnErrorForAnInvalidValue(t *testing.T) {
	text := readFile(t, envExamplePath) + "\nCODE_TTL=soon\n"

	err := loadEnvExample(text)
	if err == nil {
		t.Fatal("an invalid value in an active line was accepted")
	}
	_, clerks := Load(envMap(envFileValues(text)))
	if clerks == nil || !strings.Contains(err.Error(), clerks.Error()) {
		t.Errorf("the error is not Clerk's own.\n got: %v\nwant it to contain: %v", err, clerks)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// settingsClerkReads records every name Load asks for. All four providers have
// credentials, so each <PROVIDER>_ISSUER is read too.
func settingsClerkReads() []string {
	var names []string
	Load(func(name string) string {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
		if strings.HasSuffix(name, "_CLIENT_ID") || strings.HasSuffix(name, "_CLIENT_SECRET") {
			return "set"
		}
		return ""
	})
	return names
}

// settingLine is a NAME=value line, active or commented out ("# NAME=value").
var settingLine = regexp.MustCompile(`^(#\s*)?([A-Z][A-Z0-9_]*)=(.*)$`)

// envExampleSettings lists every name .env.example sets or shows commented out.
func envExampleSettings(text string) []string {
	var names []string
	for _, line := range strings.Split(text, "\n") {
		if m := settingLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			names = append(names, m[2])
		}
	}
	return names
}

// envFileValues reads the active lines the way `docker run --env-file` does:
// NAME=value, the value taken as it is.
func envFileValues(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if m := settingLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == "" {
			values[m[2]] = m[3]
		}
	}
	return values
}

// loadEnvExample runs the active lines of .env.example through Load, so a
// value Clerk would refuse fails with Clerk's own message.
func loadEnvExample(text string) error {
	if _, err := Load(envMap(envFileValues(text))); err != nil {
		return fmt.Errorf("Clerk refuses its active lines:\n%w", err)
	}
	return nil
}

var (
	// The README's providers, in the order of its <PROVIDER>_… rows.
	readmeProviders = []string{"GOOGLE", "GITHUB", "MICROSOFT", "LINKEDIN"}
	backtickName    = regexp.MustCompile("`([A-Z<][A-Z0-9_<>]*)`")
)

// readmeSettings lists the names in the first column of the table of every
// setting under "## 3. Configuration". A <PROVIDER>_… row counts for each
// provider.
func readmeSettings(t *testing.T, text string) []string {
	t.Helper()
	_, section, ok := strings.Cut(text, "\n## 3. Configuration\n")
	if !ok {
		t.Fatal("README.md has no \"## 3. Configuration\" section")
	}
	section, _, _ = strings.Cut(section, "\n## ")

	var names []string
	inTable := false
	for _, line := range strings.Split(section, "\n") {
		switch {
		case strings.HasPrefix(line, "| Setting |"):
			inTable = true
			continue
		case inTable && strings.HasPrefix(line, "|---"):
			continue
		case inTable && !strings.HasPrefix(line, "|"):
			inTable = false
		}
		if !inTable {
			continue
		}
		first := strings.SplitN(strings.TrimPrefix(line, "|"), "|", 2)[0]
		for _, m := range backtickName.FindAllStringSubmatch(first, -1) {
			name := m[1]
			if rest, ok := strings.CutPrefix(name, "<PROVIDER>_"); ok {
				for _, p := range readmeProviders {
					names = append(names, p+"_"+rest)
				}
				continue
			}
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		t.Fatal("README.md: no settings table under \"## 3. Configuration\"")
	}
	return names
}

// compareSettings reports every name Clerk reads that a document leaves out,
// and every name a document lists that Clerk does not read.
func compareSettings(read, envExample, readme []string) error {
	var problems []string
	for _, name := range read {
		if slices.Contains(notDocumented, name) {
			continue
		}
		if !slices.Contains(envExample, name) {
			problems = append(problems, name+": missing from .env.example")
		}
		if !slices.Contains(readme, name) {
			problems = append(problems, name+": missing from the README table")
		}
	}
	for _, doc := range []struct {
		where string
		names []string
	}{{".env.example", envExample}, {"the README table", readme}} {
		for _, name := range doc.names {
			if !slices.Contains(read, name) {
				problems = append(problems, name+": in "+doc.where+", but Clerk does not read it")
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	return errors.New(strings.Join(slices.Compact(problems), "\n"))
}

func without(names []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == drop })
}
