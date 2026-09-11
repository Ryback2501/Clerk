package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A listener bound to every interface cannot be dialled at that address from
// inside the container; the probe has to use the loopback address.
func TestHealthcheckHostIsDialable(t *testing.T) {
	for _, tc := range []struct{ listen, want string }{
		{":8080", "127.0.0.1:8080"},
		{"0.0.0.0:8080", "127.0.0.1:8080"},
		{"[::]:9999", "127.0.0.1:9999"},
		{"127.0.0.1:3000", "127.0.0.1:3000"},
		{"localhost:3000", "localhost:3000"},
		{"nonsense", "127.0.0.1:8080"},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			if got := healthcheckHost(tc.listen); got != tc.want {
				t.Errorf("healthcheckHost(%q) = %q, want %q", tc.listen, got, tc.want)
			}
		})
	}
}

func TestHealthcheckRequested(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"/clerk"}, false},
		{[]string{"/clerk", "-healthcheck"}, true},
		{[]string{"/clerk", "--healthcheck"}, true},
		{[]string{"/clerk", "serve"}, false},
	} {
		if got := healthcheckRequested(tc.args); got != tc.want {
			t.Errorf("healthcheckRequested(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestRunHealthcheckReportsServingAndFailure(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	if err := runHealthcheck(strings.TrimPrefix(healthy.URL, "http://")); err != nil {
		t.Errorf("a serving endpoint was reported unhealthy: %v", err)
	}

	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sick.Close()

	if err := runHealthcheck(strings.TrimPrefix(sick.URL, "http://")); err == nil {
		t.Error("a failing endpoint was reported healthy")
	}

	// Nothing listening at all.
	if err := runHealthcheck("127.0.0.1:1"); err == nil {
		t.Error("an unreachable endpoint was reported healthy")
	}
}
