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
	var walk func(pkgPath string, trail []string)
	walk = func(pkgPath string, trail []string) {
		if seen[pkgPath] {
			return
		}
		seen[pkgPath] = true

		pkg, err := build.Import(pkgPath, "", 0)
		if err != nil {
			// Packages that do not exist yet (admin arrives in a later slice)
			// simply cannot be depended on.
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
			walk(imp, append(trail, imp))
		}
	}
	walk(modulePath+"/internal/oidc", []string{"internal/oidc"})
}
