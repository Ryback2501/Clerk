package oidc

import (
	"context"
	"net/http"
	"testing"

	"github.com/Ryback2501/Clerk/internal/store"
)

// End to end: the attacker redeems a leaked code first and gets a token; when
// the legitimate client then presents the same code, that token must die.
func TestReplayAtTheTokenEndpointRevokesTheEarlierToken(t *testing.T) {
	f := newFlow(t)
	form := f.tokenForm(f.obtainCode(t, nil))

	first := decodeToken(t, f.exchange(form))
	if _, err := f.store.LookupAccessToken(context.Background(), first.AccessToken); err != nil {
		t.Fatalf("the first token is not usable: %v", err)
	}

	rec := f.exchange(form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("the replay returned %d, want 400", rec.Code)
	}

	if _, err := f.store.LookupAccessToken(context.Background(), first.AccessToken); err == nil {
		t.Error("the token from the first redemption survived the replay")
	} else if err != store.ErrNotFound {
		t.Errorf("unexpected error: %v", err)
	}
}
