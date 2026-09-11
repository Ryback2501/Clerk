package adminauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubBouncer mirrors the documented responses of Bouncer's /api/v1/access.
func stubBouncer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func grantedResponse(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "sub": "` + r.URL.Query().Get("sub") + `",
		  "application": {"id":"a1","customId":"clerk","name":"Clerk"},
		  "role": {"id":"r1","customId":"` + role + `","name":"Role"}
		}`))
	}
}

func newBouncer(t *testing.T, srv *httptest.Server, requiredRole string) *Bouncer {
	t.Helper()
	b, err := NewBouncer(BouncerConfig{
		BaseURL:      srv.URL,
		APIKey:       "bncr_test_key",
		RequiredRole: requiredRole,
		Client:       srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBouncerGrantsWhenTheRoleMatches(t *testing.T) {
	var gotAuth, gotSub, gotProvider string
	srv := stubBouncer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSub = r.URL.Query().Get("sub")
		gotProvider = r.URL.Query().Get("provider")
		grantedResponse("admin")(w, r)
	})

	b := newBouncer(t, srv, "admin")
	err := b.Authorize(context.Background(), Identity{Subject: "109876543210", Provider: "google"})
	if err != nil {
		t.Fatalf("Authorize() error: %v", err)
	}

	if gotAuth != "Bearer bncr_test_key" {
		t.Errorf("Authorization = %q, want the API key as a bearer token", gotAuth)
	}
	if gotSub != "109876543210" {
		t.Errorf("sub = %q, want the identity's subject verbatim", gotSub)
	}
	// Bouncer needs the provider to disambiguate the same sub across providers.
	if gotProvider != "google" {
		t.Errorf("provider = %q, want google", gotProvider)
	}
}

// The whole point of the required-role setting: a 200 alone is not enough, or
// adding any new role in Bouncer would silently grant full administration.
func TestBouncerRefusesAnUnexpectedRole(t *testing.T) {
	srv := stubBouncer(t, grantedResponse("viewer"))
	b := newBouncer(t, srv, "admin")

	err := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("Authorize() = %v, want ErrForbidden for a role other than the required one", err)
	}
}

// An empty requirement accepts any active role, which is the documented way to
// delegate the decision entirely to Bouncer.
func TestBouncerWithNoRequiredRoleAcceptsAnyActiveRole(t *testing.T) {
	srv := stubBouncer(t, grantedResponse("anything"))
	b := newBouncer(t, srv, "")

	if err := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"}); err != nil {
		t.Errorf("Authorize() = %v, want the role accepted", err)
	}
}

func TestBouncerMapsItsResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"user has no role in this application", http.StatusNotFound, `{"error":"user_not_found"}`, ErrForbidden},
		{"role inactive or expired", http.StatusForbidden, `{"error":"role_inactive"}`, ErrForbidden},
		{"the api key is wrong", http.StatusUnauthorized, `{"error":"invalid_api_key"}`, ErrUnavailable},
		{"the api key has expired", http.StatusUnauthorized, `{"error":"api_key_expired"}`, ErrUnavailable},
		{"bad request", http.StatusBadRequest, `{"error":"validation_error"}`, ErrUnavailable},
		{"bouncer is broken", http.StatusInternalServerError, `{}`, ErrUnavailable},
		{"bouncer is down for maintenance", http.StatusBadGateway, ``, ErrUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := stubBouncer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			b := newBouncer(t, srv, "admin")

			err := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"})
			if !errors.Is(err, tt.want) {
				t.Errorf("Authorize() = %v, want %v", err, tt.want)
			}
		})
	}
}

// A misconfigured API key is an operator problem, not the administrator's:
// reporting it as "you lack the role" would send them to the wrong place.
func TestBouncerDistinguishesItsOwnMisconfigurationFromRefusal(t *testing.T) {
	srv := stubBouncer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_api_key"}`))
	})
	b := newBouncer(t, srv, "admin")

	err := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"})
	if errors.Is(err, ErrForbidden) {
		t.Error("a bad API key was reported as the administrator lacking a role")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Authorize() = %v, want ErrUnavailable", err)
	}
}

// An outage must fail closed, and must not hang the admin UI indefinitely.
func TestBouncerUnreachableFailsClosed(t *testing.T) {
	b, err := NewBouncer(BouncerConfig{
		BaseURL:      "http://127.0.0.1:1",
		APIKey:       "bncr_test_key",
		RequiredRole: "admin",
		Timeout:      200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	got := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"})
	if !errors.Is(got, ErrUnavailable) {
		t.Errorf("Authorize() = %v, want ErrUnavailable", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the call took %s; a Bouncer outage must not hang the admin UI", elapsed)
	}
}

func TestBouncerRequiresConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  BouncerConfig
	}{
		{"no base url", BouncerConfig{APIKey: "bncr_k"}},
		{"no api key", BouncerConfig{BaseURL: "http://localhost"}},
		{"unparseable base url", BouncerConfig{BaseURL: "://nope", APIKey: "bncr_k"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewBouncer(tt.cfg); err == nil {
				t.Error("NewBouncer accepted an incomplete configuration")
			}
		})
	}
}

// The API key is a credential and must never reach a log or an error message
// that could be surfaced.
func TestBouncerErrorsDoNotCarryTheAPIKey(t *testing.T) {
	srv := stubBouncer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	b := newBouncer(t, srv, "admin")

	err := b.Authorize(context.Background(), Identity{Subject: "s", Provider: "google"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if contains(err.Error(), "bncr_test_key") {
		t.Errorf("the error message contains the API key: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
