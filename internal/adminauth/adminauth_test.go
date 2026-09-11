package adminauth

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// The stub exists so the admin UI can be built and tested before the real
// OAuth + Bouncer implementation lands. It must be obvious in the type system
// that it authorises everyone.
func TestAllowAllAuthenticatesEveryRequest(t *testing.T) {
	var a Authenticator = AllowAll{}

	admin, err := a.Authenticate(httptest.NewRequest("GET", "/admin", nil))
	if err != nil {
		t.Fatalf("AllowAll.Authenticate() error: %v", err)
	}
	if admin == nil {
		t.Fatal("AllowAll.Authenticate() returned no admin")
	}
	if admin.Name == "" || admin.Subject == "" {
		t.Error("the stub admin should be identifiable in the UI and in logs")
	}
}

// Callers distinguish these cases to choose a redirect, a 403 or a 503, so the
// sentinels must stay separable.
func TestErrorSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrUnauthenticated, ErrForbidden, ErrUnavailable}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %d and %d are not distinguishable", i, j)
			}
		}
	}
}
