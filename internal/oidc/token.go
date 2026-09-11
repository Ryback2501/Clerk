package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Ryback2501/Clerk/internal/store"
)

// Token endpoint error codes (RFC 6749 §5.2).
const (
	errInvalidGrant         = "invalid_grant"
	errInvalidClient        = "invalid_client"
	errUnsupportedGrantType = "unsupported_grant_type"
)

// grantAuthorizationCode is the only grant this provider implements. Refresh
// tokens are deliberately out of scope and are not advertised.
const grantAuthorizationCode = "authorization_code"

// tokenResponse is the successful body of a token exchange (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// handleToken exchanges an authorization code for tokens.
func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.tokenError(w, r, http.StatusBadRequest, errInvalidRequest, "the request body could not be parsed")
		return
	}

	if grant := r.PostFormValue("grant_type"); grant != grantAuthorizationCode {
		p.tokenError(w, r, http.StatusBadRequest, errUnsupportedGrantType,
			"only the authorization_code grant is supported")
		return
	}

	// ---- Authenticate the client before looking at the grant.
	app, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	code := r.PostFormValue("code")
	if code == "" {
		p.tokenError(w, r, http.StatusBadRequest, errInvalidRequest, "code is required")
		return
	}

	// Consuming marks the code used even when a later check fails. That is
	// deliberate: a code presented with the wrong redirect URI or a failed
	// PKCE check has very likely been intercepted, and letting it stay
	// redeemable would leave the window open.
	granted, err := p.store.ConsumeAuthCode(r.Context(), code)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.logger.WarnContext(r.Context(), "token request with an unknown code", "application_id", app.ID)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, "the authorization code is not valid")
		return
	case errors.Is(err, store.ErrCodeExpired):
		p.logger.WarnContext(r.Context(), "token request with an expired code", "application_id", app.ID)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, "the authorization code has expired")
		return
	case errors.Is(err, store.ErrCodeReplayed):
		// Worth a louder line than the others: a second presentation of a code
		// suggests it was captured somewhere.
		p.logger.WarnContext(r.Context(), "authorization code replayed",
			"application_id", app.ID, "issued_to_application_id", granted)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, "the authorization code has already been used")
		return
	case err != nil:
		p.logger.ErrorContext(r.Context(), "consume authorization code", "err", err)
		p.tokenError(w, r, http.StatusInternalServerError, errServerError, "the code could not be exchanged")
		return
	}

	// ---- The code must belong to this client.
	if granted.ApplicationID != app.ID {
		p.logger.WarnContext(r.Context(), "client presented a code issued to another application",
			"application_id", app.ID, "code_application_id", granted.ApplicationID)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, "the authorization code was not issued to this client")
		return
	}

	// ---- ...and must come back with the redirect URI it was issued for.
	if r.PostFormValue("redirect_uri") != granted.RedirectURI {
		p.logger.WarnContext(r.Context(), "token request with a mismatched redirect uri",
			"application_id", app.ID)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant,
			"redirect_uri does not match the one the code was issued for")
		return
	}

	if err := verifyPKCE(granted, r.PostFormValue("code_verifier")); err != nil {
		p.logger.WarnContext(r.Context(), "pkce verification failed",
			"application_id", app.ID, "reason", err.Error())
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, err.Error())
		return
	}

	user, err := p.store.GetUser(r.Context(), granted.UserID)
	if err != nil {
		// The user was deleted between authorization and exchange, or the
		// store failed. Either way there is no identity to assert.
		p.logger.ErrorContext(r.Context(), "load user for token exchange", "err", err, "user_id", granted.UserID)
		p.tokenError(w, r, http.StatusBadRequest, errInvalidGrant, "the authorized user no longer exists")
		return
	}

	accessToken, err := p.store.IssueAccessToken(r.Context(), app.ID, user.ID, granted.Scope, p.accessTokenTTL)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "issue access token", "err", err)
		p.tokenError(w, r, http.StatusInternalServerError, errServerError, "the tokens could not be issued")
		return
	}

	idToken, err := p.mintIDToken(app.ClientID, user, granted)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "mint id token", "err", err)
		p.tokenError(w, r, http.StatusInternalServerError, errServerError, "the tokens could not be issued")
		return
	}

	// Neither token is ever logged.
	p.logger.InfoContext(r.Context(), "tokens issued",
		"application_id", app.ID, "user_id", user.ID, "sub", user.Sub, "scope", granted.Scope)

	p.writeToken(w, r, tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(p.accessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       granted.Scope,
	})
}

// authenticateClient resolves and verifies the client's credentials, accepting
// both methods the discovery document advertises. On failure it has already
// written the response.
func (p *Provider) authenticateClient(w http.ResponseWriter, r *http.Request) (*store.Application, bool) {
	clientID, clientSecret, usedBasic := clientCredentials(r)
	if clientID == "" {
		p.tokenErrorAuth(w, r, usedBasic, "client authentication is required")
		return nil, false
	}

	app, err := p.store.GetApplicationByClientID(r.Context(), clientID)
	if errors.Is(err, store.ErrNotFound) {
		p.logger.WarnContext(r.Context(), "token request from an unknown client", "client_id", clientID)
		p.tokenErrorAuth(w, r, usedBasic, "client authentication failed")
		return nil, false
	}
	if err != nil {
		p.logger.ErrorContext(r.Context(), "load application", "err", err)
		p.tokenError(w, r, http.StatusInternalServerError, errServerError, "the request could not be processed")
		return nil, false
	}

	ok, err := p.store.VerifyClientSecret(r.Context(), app.ID, clientSecret)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "verify client secret", "err", err)
		p.tokenError(w, r, http.StatusInternalServerError, errServerError, "the request could not be processed")
		return nil, false
	}
	if !ok {
		p.logger.WarnContext(r.Context(), "token request with an invalid client secret",
			"application_id", app.ID, "client_id", clientID)
		p.tokenErrorAuth(w, r, usedBasic, "client authentication failed")
		return nil, false
	}
	return app, true
}

// clientCredentials reads the credentials from either advertised method.
// HTTP Basic takes precedence, and RFC 6749 §2.3.1 requires its two halves to
// be form-urlencoded before base64, which Go's BasicAuth does not undo.
func clientCredentials(r *http.Request) (id, secret string, usedBasic bool) {
	if user, pass, ok := r.BasicAuth(); ok {
		decodedUser, err := url.QueryUnescape(user)
		if err != nil {
			decodedUser = user
		}
		decodedPass, err := url.QueryUnescape(pass)
		if err != nil {
			decodedPass = pass
		}
		return decodedUser, decodedPass, true
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret"), false
}

// verifyPKCE checks a code verifier against the challenge the code carries.
func verifyPKCE(granted *store.AuthCode, verifier string) error {
	switch {
	case granted.CodeChallenge == "" && verifier == "":
		return nil
	case granted.CodeChallenge == "":
		return errors.New("a code_verifier was supplied for a code issued without a challenge")
	case verifier == "":
		return errors.New("code_verifier is required for this code")
	case granted.CodeChallengeMethod != "S256":
		// Authorization rejects anything else, so reaching here means the row
		// was tampered with.
		return errors.New("unsupported code challenge method")
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(granted.CodeChallenge)) != 1 {
		return errors.New("the code_verifier does not match the challenge")
	}
	return nil
}

// mintIDToken builds the signed assertion of who signed in.
func (p *Provider) mintIDToken(clientID string, user *store.User, granted *store.AuthCode) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.signer.Private()},
		// The kid lets a client pick the right key out of the JWKS.
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), p.signer.KeyID()),
	)
	if err != nil {
		return "", err
	}

	now := p.now()
	claims := jwt.Claims{
		Issuer:   p.base(),
		Subject:  user.Sub,
		Audience: jwt.Audience{clientID},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(p.idTokenTTL)),
	}

	// Claims beyond the registered set: the nonce binds this token to the
	// authorization request, and name is the whole of what "profile" means here.
	extra := map[string]any{}
	if granted.Nonce != "" {
		extra["nonce"] = granted.Nonce
	}
	if slices.Contains(strings.Fields(granted.Scope), "profile") {
		extra["name"] = user.Username
	}

	return jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
}

func (p *Provider) writeToken(w http.ResponseWriter, r *http.Request, body tokenResponse) {
	p.writeJSONStatus(w, r, http.StatusOK, body)
}

// tokenError writes an OAuth error response.
func (p *Provider) tokenError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	p.writeJSONStatus(w, r, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// tokenErrorAuth writes an invalid_client response. RFC 6749 §5.2 requires a
// challenge when the client attempted HTTP Basic authentication.
func (p *Provider) tokenErrorAuth(w http.ResponseWriter, r *http.Request, usedBasic bool, description string) {
	// The challenge is sent for both methods: it tells a client that failed
	// with form credentials which scheme this endpoint accepts.
	w.Header().Set("WWW-Authenticate", `Basic realm="clerk", charset="UTF-8"`)
	p.tokenError(w, r, http.StatusUnauthorized, errInvalidClient, description)
}

// writeJSONStatus writes a token-endpoint body. These responses carry
// credentials, so they must never be cached.
func (p *Provider) writeJSONStatus(w http.ResponseWriter, r *http.Request, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "encode token response", "err", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		p.logger.ErrorContext(r.Context(), "write token response", "err", err)
	}
}
