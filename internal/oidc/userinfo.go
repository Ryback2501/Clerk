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
	token, ok := accessTokenFrom(r)
	if !ok {
		// RFC 6750 §3.1: omit the error code when no credentials were offered
		// at all. Saying "invalid_token" here would tell a client whose header
		// a proxy stripped that its perfectly good token is bad, and it would
		// discard the session.
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
		// Defence in depth. The tokens table cascades on user deletion, so in
		// practice LookupAccessToken has already failed above; this branch
		// matters only if that foreign key is ever not enforced.
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

// accessTokenFrom extracts the credential a UserInfo request carries.
//
// The Authorization header is preferred (RFC 6750 §2.1). A form-encoded POST
// body is also accepted (§2.2), because OIDC Core §5.3.1 permits POST and a
// client using it would otherwise be silently refused despite presenting a
// valid token.
func accessTokenFrom(r *http.Request) (string, bool) {
	if token, ok := bearerToken(r); ok {
		return token, true
	}

	if r.Method != http.MethodPost {
		return "", false
	}
	// RFC 6750 §2.2 requires this content type; reading any other body would
	// accept credentials from places the spec does not put them.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return "", false
	}
	if err := r.ParseForm(); err != nil {
		return "", false
	}
	if token := strings.TrimSpace(r.PostFormValue("access_token")); token != "" {
		return token, true
	}
	return "", false
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
//
// An empty code means no credentials were offered, which is not the same as a
// bad one: both the challenge and the body then omit the error, so a client
// cannot mistake a stripped header for a rejected token.
func (p *Provider) unauthorized(w http.ResponseWriter, r *http.Request, code, description string) {
	challenge := `Bearer realm="clerk"`
	body := map[string]string{}

	if code != "" {
		challenge += `, error="` + quoteEscape(code) + `", error_description="` + quoteEscape(description) + `"`
		body["error"] = code
		body["error_description"] = description
	}
	w.Header().Set("WWW-Authenticate", challenge)

	// The body carries no identity detail: the caller has not shown it may
	// have any.
	p.writeJSONStatus(w, r, http.StatusUnauthorized, body)
}

// quoteEscape makes a value safe inside an RFC 7235 quoted-string. Today's
// callers pass fixed literals, but a header built by concatenation is one
// careless caller away from being splittable.
func quoteEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// Control characters, including CR and LF, are dropped outright.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
