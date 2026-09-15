package adminauth

import (
	"errors"
	"testing"
)

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
