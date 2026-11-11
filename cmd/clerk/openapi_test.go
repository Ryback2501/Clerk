package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	liberrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi-validator/schema_validation"

	"github.com/Ryback2501/Clerk/internal/keys"
	"github.com/Ryback2501/Clerk/internal/oidc"
	"github.com/Ryback2501/Clerk/internal/store"
)

// docs/openapi.yaml describes the endpoints third-party applications and
// operators call. These tests keep it honest: it must be a valid OpenAPI 3.1
// document, and its paths and methods must be exactly the public routes Clerk
// serves. The served routes are recorded from the code that registers them,
// so a new or changed route cannot slip past the document unnoticed.
//
// The admin routes and the static files are deliberately not part of it: the
// former are internal UI endpoints, the latter are not an API.

const openAPIPath = "../../docs/openapi.yaml"

func TestOpenAPIDocumentMatchesPublicRoutes(t *testing.T) {
	documented, err := documentedRoutes(readOpenAPI(t))
	if err != nil {
		t.Fatalf("docs/openapi.yaml: %v", err)
	}
	if err := compareRoutes(servedRoutes(t), documented); err != nil {
		t.Errorf("docs/openapi.yaml does not match the public routes:\n%v", err)
	}
}

func TestOpenAPICheckNamesAnUndocumentedRoute(t *testing.T) {
	documented, err := documentedRoutes(readOpenAPI(t))
	if err != nil {
		t.Fatalf("docs/openapi.yaml: %v", err)
	}
	served := append(servedRoutes(t), "GET /logout")

	err = compareRoutes(served, documented)
	if err == nil {
		t.Fatal("an undocumented route was accepted")
	}
	if !strings.Contains(err.Error(), "served but not documented: GET /logout") {
		t.Errorf("the error does not name the missing route:\n%v", err)
	}
}

func TestOpenAPICheckNamesAnUnservedOperation(t *testing.T) {
	spec := strings.Replace(string(readOpenAPI(t)), "\n  /token:\n", `
  /token:
    delete:
      summary: Not served by Clerk.
      responses:
        "204":
          description: Nothing.
`, 1)
	documented, err := documentedRoutes([]byte(spec))
	if err != nil {
		t.Fatalf("the edited document should still be valid: %v", err)
	}

	err = compareRoutes(servedRoutes(t), documented)
	if err == nil {
		t.Fatal("a documented operation Clerk does not serve was accepted")
	}
	if !strings.Contains(err.Error(), "documented but not served: DELETE /token") {
		t.Errorf("the error does not name the unserved operation:\n%v", err)
	}
}

func TestOpenAPICheckRejectsABrokenDocument(t *testing.T) {
	original := string(readOpenAPI(t))
	const title = "  title: Clerk OpenID Connect provider\n"
	if !strings.Contains(original, title) {
		t.Fatalf("docs/openapi.yaml no longer has the line this test removes: %q", title)
	}

	cases := []struct {
		name string
		spec string
		why  string // part of the reason the check must give
	}{
		{
			name: "a required field is missing",
			spec: strings.Replace(original, title, "", 1),
			why:  "title",
		},
		{
			name: "the YAML is invalid",
			spec: original + "\npaths: [unclosed\n",
			why:  "yaml",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := documentedRoutes([]byte(tc.spec))
			if err == nil {
				t.Fatal("the broken document was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.why) {
				t.Errorf("the error does not say why (want it to mention %q):\n%v", tc.why, err)
			}
		})
	}
}

// The document leaves the admin routes out on purpose, so the recorded routes
// must never include them, nor the static files.
func TestOpenAPICheckIgnoresAdminRoutes(t *testing.T) {
	for _, route := range servedRoutes(t) {
		_, path, _ := strings.Cut(route, " ")
		if strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/static/") {
			t.Errorf("the check records %q, which the document leaves out on purpose", route)
		}
	}
}

func readOpenAPI(t *testing.T) []byte {
	t.Helper()
	spec, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read the OpenAPI document: %v", err)
	}
	return spec
}

// routeRecorder stands in for the router and keeps every pattern registered on
// it, such as "GET /jwks".
type routeRecorder struct{ patterns []string }

func (r *routeRecorder) Handle(pattern string, _ http.Handler) {
	r.patterns = append(r.patterns, pattern)
}

func (r *routeRecorder) HandleFunc(pattern string, _ func(http.ResponseWriter, *http.Request)) {
	r.patterns = append(r.patterns, pattern)
}

// servedRoutes records the public routes the way the server registers them:
// the OIDC provider, for an issuer with no path, and the health check.
func servedRoutes(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "clerk.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	signer, err := keys.LoadOrGenerate(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}

	provider, err := oidc.New(oidc.Options{
		Issuer: &url.URL{Scheme: "https", Host: "clerk.test"},
		Signer: signer,
		Store:  db,
	})
	if err != nil {
		t.Fatalf("oidc provider: %v", err)
	}

	rec := &routeRecorder{}
	provider.Register(rec)
	registerHealth(rec)
	return rec.patterns
}

// documentedRoutes validates spec as an OpenAPI 3.1 document and returns the
// operations it describes, as "METHOD /path".
func documentedRoutes(spec []byte) ([]string, error) {
	doc, err := libopenapi.NewDocument(spec)
	if err != nil {
		return nil, fmt.Errorf("not a readable OpenAPI document: %w", err)
	}
	if v := doc.GetVersion(); !strings.HasPrefix(v, "3.1") {
		return nil, fmt.Errorf("OpenAPI version is %q, want 3.1", v)
	}
	if ok, problems := schema_validation.ValidateOpenAPIDocument(doc); !ok {
		var errs []error
		for _, p := range problems {
			errs = append(errs, schemaProblem(p))
		}
		return nil, fmt.Errorf("not a valid OpenAPI 3.1 document:\n%w", errors.Join(errs...))
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, fmt.Errorf("build the OpenAPI model: %w", err)
	}
	var routes []string
	if model.Model.Paths == nil {
		return routes, nil
	}
	for path, item := range model.Model.Paths.PathItems.FromOldest() {
		for method := range item.GetOperations().FromOldest() {
			routes = append(routes, strings.ToUpper(method)+" "+path)
		}
	}
	return routes, nil
}

// schemaProblem renders one validation problem with each schema failure under
// it, so the test output says exactly what is wrong and where.
func schemaProblem(p *liberrors.ValidationError) error {
	var b strings.Builder
	fmt.Fprintf(&b, "  line %d: %s", p.SpecLine, p.Reason)
	for _, f := range p.SchemaValidationErrors {
		fmt.Fprintf(&b, "\n    - %s", f.Error())
	}
	return errors.New(b.String())
}

// compareRoutes reports every route served but not documented, and every
// operation documented but not served.
func compareRoutes(served, documented []string) error {
	var problems []string
	for _, r := range served {
		if !slices.Contains(documented, r) {
			problems = append(problems, "served but not documented: "+r)
		}
	}
	for _, r := range documented {
		if !slices.Contains(served, r) {
			problems = append(problems, "documented but not served: "+r)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	return errors.New(strings.Join(problems, "\n"))
}
