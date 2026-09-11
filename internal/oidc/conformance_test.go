package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Discovery is a contract. Every endpoint it advertises must answer, or a
// client that follows it breaks on an endpoint this provider claims to have.
func TestEveryAdvertisedEndpointAnswers(t *testing.T) {
	f := newFlow(t)
	doc := discoveryDoc(t, f.provider())

	for field, method := range map[string]string{
		"authorization_endpoint": http.MethodGet,
		"token_endpoint":         http.MethodPost,
		"userinfo_endpoint":      http.MethodGet,
		"jwks_uri":               http.MethodGet,
	} {
		advertised, _ := doc[field].(string)
		u, err := url.Parse(advertised)
		if err != nil {
			t.Fatalf("%s = %q is not a URL", field, advertised)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, u.Path, nil)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		f.mux.ServeHTTP(rec, req)

		// Any answer but "no such route" proves the endpoint exists.
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s advertises %s but %s %s returned %d",
				field, advertised, method, u.Path, rec.Code)
		}
	}
}
