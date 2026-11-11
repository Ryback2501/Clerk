package standin

import (
	"os/exec"
	"strings"
	"testing"
)

// The stand-in signs anyone in as an administrator, so it must never reach the
// binary. This checks the binary's real dependency list, not file contents.
func TestTheStandInNeverReachesTheBinary(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/Ryback2501/Clerk/cmd/clerk").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const self = "github.com/Ryback2501/Clerk/internal/standin"
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == self || strings.HasPrefix(pkg, self+"/") {
			t.Errorf("the clerk binary depends on the test-only package %s", pkg)
		}
	}
}
