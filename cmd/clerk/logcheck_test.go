package main

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// The log check: record everything Clerk logs, at every level and through
// every logger, and find any secret in it.

// The check itself: a secret anywhere in a line is reported with its name and
// the line, once per line it appears in.
func TestFindSecretsNamesTheSecretAndTheLine(t *testing.T) {
	logs := "level=INFO msg=ok\n" +
		"level=DEBUG msg=\"token issued\" token=eyJ.abc.def\n" +
		"level=INFO msg=done\n"
	leaks := findSecrets(logs, []namedSecret{
		{"access token", "eyJ.abc.def"},
		{"client secret", "never-logged"},
	})
	if len(leaks) != 1 {
		t.Fatalf("got %d leaks, want 1: %+v", len(leaks), leaks)
	}
	if leaks[0].name != "access token" || leaks[0].line != `level=DEBUG msg="token issued" token=eyJ.abc.def` {
		t.Errorf("leak = %+v", leaks[0])
	}
}

// A secret too short to search for safely is a mistake in the test, not a
// pass: an empty string is "found" everywhere, and a short one by chance.
func TestFindSecretsRefusesAnUnusableSecret(t *testing.T) {
	leaks := findSecrets("anything", []namedSecret{{"empty", ""}})
	if len(leaks) != 1 || !strings.Contains(leaks[0].line, "too short") {
		t.Errorf("an empty secret was not reported: %+v", leaks)
	}
}

// The capture records every level, debug included, from Clerk's logger and
// from the default loggers alike, and puts the defaults back afterwards.
func TestCaptureLogsRecordsEveryLevelAndEveryLogger(t *testing.T) {
	before, beforeOutput := slog.Default(), log.Writer()
	t.Run("capture", func(t *testing.T) {
		logs := captureLogs(t)
		logs.Logger.Debug("from clerk's logger at debug")
		slog.Debug("from the default slog logger at debug")
		log.Print("from the standard log package")

		got := logs.String()
		for _, want := range []string{
			"from clerk's logger at debug",
			"from the default slog logger at debug",
			"from the standard log package",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the capture missed %q:\n%s", want, got)
			}
		}
	})
	if slog.Default() != before || log.Writer() != beforeOutput {
		t.Error("the default loggers were not put back after the test")
	}
}

// namedSecret is a value that must never be logged, with the name a failure
// reports it by.
type namedSecret struct{ name, value string }

type leak struct{ name, line string }

// minSecretLength keeps the search meaningful: every real secret here is far
// longer, while a short value would match unrelated text by chance.
const minSecretLength = 8

// findSecrets reports every line of logs that contains one of the secrets.
func findSecrets(logs string, secrets []namedSecret) []leak {
	var leaks []leak
	for _, s := range secrets {
		if len(s.value) < minSecretLength {
			leaks = append(leaks, leak{s.name, fmt.Sprintf("(the value is too short to search for: %d characters)", len(s.value))})
			continue
		}
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, s.value) {
				leaks = append(leaks, leak{s.name, line})
			}
		}
	}
	return leaks
}

// logCapture records everything logged during a test.
type logCapture struct {
	Logger *slog.Logger
	mu     sync.Mutex
	buf    bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// captureLogs returns a debug-level logger to hand to Clerk, and also routes
// the default slog logger and the standard log package into the same record,
// so a line written through either of those is caught too. Everything is put
// back when the test ends.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	c.Logger = slog.New(slog.NewTextHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug}))

	prevDefault, prevOutput, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(c.Logger)
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
	})
	return c
}
