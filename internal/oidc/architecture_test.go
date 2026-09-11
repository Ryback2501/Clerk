package oidc

import (
	"go/build"
	"strings"
	"testing"
)

// The OIDC endpoints must keep serving even when admin authentication or its
// Bouncer dependency is broken. The cheapest durable guarantee of that is a
// compile-time dependency rule: this package may not reach into the admin side
// at all, directly or transitively.
func TestOIDCDoesNotDependOnAdminPackages(t *testing.T) {
	const modulePath = "github.com/Ryback2501/Clerk"
	forbidden := []string{modulePath + "/internal/admin", modulePath + "/internal/adminauth"}

	seen := map[string]bool{}
	var walk func(pkgPath string, trail []string, root bool)
	walk = func(pkgPath string, trail []string, root bool) {
		if seen[pkgPath] {
			return
		}
		seen[pkgPath] = true

		pkg, err := build.Import(pkgPath, "", 0)
		if err != nil {
			if root {
				// Without this the whole guard would silently pass while
				// checking nothing, and CLAUDE.md cites this test as the
				// enforcement of the dependency rule.
				t.Fatalf("cannot resolve %s, so this test would prove nothing: %v", pkgPath, err)
			}
			// A package that does not exist yet (internal/admin arrives in a
			// later slice) cannot be depended on.
			return
		}
		for _, imp := range pkg.Imports {
			if !strings.HasPrefix(imp, modulePath) {
				continue
			}
			for _, bad := range forbidden {
				if imp == bad {
					t.Errorf("internal/oidc must not depend on %s\n  path: %s -> %s",
						bad, strings.Join(trail, " -> "), imp)
				}
			}
			// Copy rather than append in place: successive iterations would
			// otherwise share one backing array and the reported chain could
			// name a sibling import instead of the real path.
			next := make([]string, len(trail), len(trail)+1)
			copy(next, trail)
			walk(imp, append(next, imp), false)
		}
	}
	walk(modulePath+"/internal/oidc", []string{"internal/oidc"}, true)
}
