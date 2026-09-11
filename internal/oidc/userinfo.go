package oidc

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Ryback2501/Clerk/internal/store"
)

// bearerPrefix is the only Authorization scheme this endpoint accepts.
const bearerPrefix = "Bearer "

// handleUserInfo returns the claims for the identity an access token stands
// for (OIDC Core §5.3).
//
// The response is the same minimal identity the ID token asserts. Nothing here
// depends on administration or its authorization service: a client that has a
// valid token must keep being able to resolve it.
func (p *Provider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		// RFC 6750 §3.1: omit the error code when no credentials were offered
		// at all — there is nothing yet to call invalid.
		p.unauthorized(w, r, "", "")
		return
	}

	granted, err := p.store.LookupAccessToken(r.Context(), token)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Unknown and expired are the same answer here: neither tells the
		// caller anything about which it was.
		p.logger.WarnContext(r.Context(), "userinfo request with an invalid access token")
		p.unauthorized(w, r, "invalid_token", "the access token is expired or invalid")
		return
	case err != nil:
		p.logger.ErrorContext(r.Context(), "look up access token", "err", err)
		p.writeJSONStatus(w, r, http.StatusInternalServerError, map[string]string{
			"error": errServerError,
		})
		return
	}

	user, err := p.store.GetUser(r.Context(), granted.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The identity was deleted after the token was issued, so there is
		// nothing left to describe.
		p.logger.WarnContext(r.Context(), "userinfo request for a deleted user",
			"user_id", granted.UserID)
		p.unauthorized(w, r, "invalid_token", "the access token is expired or invalid")
		return
	case err != nil:
		p.logger.ErrorContext(r.Context(), "load user for userinfo", "err", err, "user_id", granted.UserID)
		p.writeJSONStatus(w, r, http.StatusInternalServerError, map[string]string{
			"error": errServerError,
		})
		return
	}

	// sub always; everything else follows the scope the token actually carries.
	claims := map[string]any{"sub": user.Sub}
	if slices.Contains(strings.Fields(granted.Scope), "profile") {
		claims["name"] = user.Username
	}

	p.writeJSONStatus(w, r, http.StatusOK, claims)
}

// bearerToken extracts the credential from the Authorization header. The
// scheme name is case-insensitive per RFC 7235, but the token itself is not.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}

	token := strings.TrimSpace(header[len(bearerPrefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// unauthorized writes a 401 with the challenge RFC 6750 §3 requires.
func (p *Provider) unauthorized(w http.ResponseWriter, r *http.Request, code, description string) {
	challenge := `Bearer realm="clerk"`
	if code != "" {
		challenge += `, error="` + code + `", error_description="` + description + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)

	// The body carries no identity detail: the caller has not shown it may
	// have any.
	p.writeJSONStatus(w, r, http.StatusUnauthorized, map[string]string{
		"error": "invalid_token",
	})
}
