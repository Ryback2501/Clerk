package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Ryback2501/Clerk/internal/store"
)

// OAuth 2.0 error codes this provider emits (RFC 6749 §4.1.2.1).
const (
	errInvalidRequest          = "invalid_request"
	errUnsupportedResponseType = "unsupported_response_type"
	errInvalidScope            = "invalid_scope"
	errServerError             = "server_error"
)

// scopeOpenID must be present for a request to be an OpenID Connect request at
// all, as opposed to plain OAuth 2.0.
const scopeOpenID = "openid"

// supportedScopes mirrors what the discovery document advertises.
var supportedScopes = []string{scopeOpenID, "profile"}

// authorizeRequest is a request that has passed the checks needed to trust its
// redirect URI. Everything after that point can be reported to the client.
type authorizeRequest struct {
	app                 *store.Application
	redirectURI         string
	state               string
	nonce               string
	scope               string
	codeChallenge       string
	codeChallengeMethod string
}

// handleAuthorize starts the Authorization Code flow.
//
// Error handling here is in two distinct phases, and the split is the whole
// security property. Until the client and the redirect URI are both known to
// be registered, nothing may be sent to that URI — redirecting first would
// make this endpoint an open redirector and would leak authorization errors to
// whatever address an attacker put in the query string. Only once the URI is
// proven to belong to the client do errors travel back to it.
func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// ---- Phase 1: establish who is asking, and where they may be answered.
	clientID := q.Get("client_id")
	if clientID == "" {
		p.refuse(w, r, "Invalid authorization request",
			"The request did not identify which application is asking you to sign in.", "")
		return
	}

	app, err := p.store.GetApplicationByClientID(r.Context(), clientID)
	if errors.Is(err, store.ErrNotFound) {
		p.logger.WarnContext(r.Context(), "authorization request for an unknown client",
			"client_id", clientID)
		p.refuse(w, r, "Unknown application",
			"No application is registered with that client identifier.", "")
		return
	}
	if err != nil {
		p.logger.ErrorContext(r.Context(), "load application", "err", err)
		p.refuse(w, r, "Something went wrong",
			"The authorization request could not be processed.", "")
		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		p.refuse(w, r, "Invalid authorization request",
			"The request did not say where to send you after signing in.", "")
		return
	}
	if !slices.Contains(app.RedirectURIs, redirectURI) {
		// Deliberately not echoed back to the browser: it is attacker-supplied.
		p.logger.WarnContext(r.Context(), "authorization request with an unregistered redirect uri",
			"client_id", clientID, "application_id", app.ID)
		p.refuse(w, r, "Invalid redirect URI",
			"The address this application asked to be returned to is not registered with it.",
			"Redirect URIs are matched exactly. Check for a trailing slash, a different port, or http instead of https.")
		return
	}

	// ---- Phase 2: the redirect URI is trusted; errors may go back to it.
	req := authorizeRequest{
		app:                 app,
		redirectURI:         redirectURI,
		state:               q.Get("state"),
		nonce:               q.Get("nonce"),
		scope:               q.Get("scope"),
		codeChallenge:       q.Get("code_challenge"),
		codeChallengeMethod: q.Get("code_challenge_method"),
	}

	switch responseType := q.Get("response_type"); {
	case responseType == "":
		p.redirectError(w, r, req, errInvalidRequest, "response_type is required")
		return
	case responseType != "code":
		// Only the Authorization Code flow is implemented; the discovery
		// document says so, and anything else is a configuration mistake.
		p.redirectError(w, r, req, errUnsupportedResponseType,
			"only the authorization code flow is supported")
		return
	}

	if err := validateScope(req.scope); err != nil {
		p.redirectError(w, r, req, errInvalidScope, err.Error())
		return
	}
	if err := validatePKCE(req.codeChallenge, req.codeChallengeMethod); err != nil {
		p.redirectError(w, r, req, errInvalidRequest, err.Error())
		return
	}

	users, err := p.store.ListUsers(r.Context(), app.ID)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "list users", "err", err, "application_id", app.ID)
		p.redirectError(w, r, req, errServerError, "could not load the application's test users")
		return
	}
	if len(users) == 0 {
		// A provider-side configuration gap rather than a client error, so it
		// is explained on screen instead of bounced back as an OAuth error.
		p.logger.WarnContext(r.Context(), "authorization request for an application with no users",
			"application_id", app.ID)
		p.renderPage(w, r, "no_users", http.StatusOK, pageData{
			Title:           "No test users",
			ApplicationName: app.Name,
		})
		return
	}

	parked, err := p.store.CreateAuthRequest(r.Context(), store.AuthRequest{
		ApplicationID:       app.ID,
		RedirectURI:         req.redirectURI,
		State:               req.state,
		Nonce:               req.nonce,
		Scope:               req.scope,
		CodeChallenge:       req.codeChallenge,
		CodeChallengeMethod: req.codeChallengeMethod,
	}, p.authRequestTTL)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "park authorization request", "err", err)
		p.redirectError(w, r, req, errServerError, "could not start the sign-in")
		return
	}

	p.logger.InfoContext(r.Context(), "authorization request accepted",
		"application_id", app.ID, "client_id", clientID, "scope", req.scope,
		"pkce", req.codeChallenge != "")

	p.renderPage(w, r, "login", http.StatusOK, pageData{
		Title:           "Sign in to " + app.Name,
		ApplicationName: app.Name,
		Users:           users,
		RequestID:       parked.ID,
		CSRFToken:       p.csrf.Issue(w, r),
	})
}

// handleLogin completes the flow: the user picked an identity and pressed
// Login. There is no password step by design — the simplification in this
// provider is user authentication, nothing else.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := p.csrf.Check(r); err != nil {
		p.logger.WarnContext(r.Context(), "login submission failed CSRF validation")
		p.refuse(w, r, "Request rejected",
			"This sign-in could not be verified as coming from this provider. Start again from the application.", "")
		return
	}

	// Consuming the handle here is what makes one rendered form good for at
	// most one authorization code.
	parked, err := p.store.ConsumeAuthRequest(r.Context(), r.PostFormValue("request_id"))
	if errors.Is(err, store.ErrNotFound) {
		p.refuse(w, r, "Sign-in expired",
			"This sign-in is no longer valid. It may have expired or already been completed. Start again from the application.", "")
		return
	}
	if err != nil {
		p.logger.ErrorContext(r.Context(), "consume authorization request", "err", err)
		p.refuse(w, r, "Something went wrong", "The sign-in could not be completed.", "")
		return
	}

	req := authorizeRequest{
		redirectURI:         parked.RedirectURI,
		state:               parked.State,
		nonce:               parked.Nonce,
		scope:               parked.Scope,
		codeChallenge:       parked.CodeChallenge,
		codeChallengeMethod: parked.CodeChallengeMethod,
	}

	userID, err := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
	if err != nil {
		p.redirectError(w, r, req, errInvalidRequest, "no test user was selected")
		return
	}

	user, err := p.store.GetUser(r.Context(), userID)
	if err != nil || user.ApplicationID != parked.ApplicationID {
		// The selected identity must belong to the application that started
		// this request; otherwise a tampered form could sign in as anyone in
		// the provider.
		p.logger.WarnContext(r.Context(), "login selected a user outside the requesting application",
			"application_id", parked.ApplicationID, "user_id", userID)
		p.refuse(w, r, "Invalid selection",
			"That test user does not belong to the application you are signing in to.", "")
		return
	}

	plainCode, _, err := p.store.IssueAuthCode(r.Context(), store.AuthCode{
		ApplicationID:       parked.ApplicationID,
		UserID:              user.ID,
		RedirectURI:         parked.RedirectURI,
		Nonce:               parked.Nonce,
		Scope:               parked.Scope,
		CodeChallenge:       parked.CodeChallenge,
		CodeChallengeMethod: parked.CodeChallengeMethod,
	}, p.codeTTL)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "issue authorization code", "err", err)
		p.redirectError(w, r, req, errServerError, "could not issue an authorization code")
		return
	}

	// The code itself is a credential and is never logged.
	p.logger.InfoContext(r.Context(), "test user signed in",
		"application_id", parked.ApplicationID, "user_id", user.ID, "sub", user.Sub)

	target := appendQuery(parked.RedirectURI, url.Values{
		"code":  {plainCode},
		"state": {parked.State},
	}, parked.State != "")
	http.Redirect(w, r, target, http.StatusFound)
}

// redirectError returns an OAuth error to the client's registered redirect URI.
// state is echoed untouched: it is the client's own CSRF value and this
// provider never interprets it.
func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, req authorizeRequest, code, description string) {
	p.logger.WarnContext(r.Context(), "authorization request rejected",
		"error", code, "description", description)

	target := appendQuery(req.redirectURI, url.Values{
		"error":             {code},
		"error_description": {description},
		"state":             {req.state},
	}, req.state != "")
	http.Redirect(w, r, target, http.StatusFound)
}

// appendQuery adds parameters to a URI, preserving any the client already put
// there. state is dropped when the client did not send one, rather than echoed
// back empty.
func appendQuery(raw string, params url.Values, keepState bool) string {
	u, err := url.Parse(raw)
	if err != nil {
		// The URI was validated at registration, so this is unreachable in
		// practice; returning it unchanged is the safe fallback.
		return raw
	}

	q := u.Query()
	for k, vs := range params {
		if k == "state" && !keepState {
			continue
		}
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func validateScope(scope string) error {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return errors.New("scope is required and must include openid")
	}
	if !slices.Contains(fields, scopeOpenID) {
		return errors.New("scope must include openid")
	}
	for _, s := range fields {
		if !slices.Contains(supportedScopes, s) {
			return errors.New("unsupported scope: " + s)
		}
	}
	return nil
}

// validatePKCE accepts either no proof key at all or a complete S256
// challenge. "plain" is deliberately unsupported: it offers no protection
// against an attacker who can read the authorization request, and the
// discovery document advertises S256 only.
func validatePKCE(challenge, method string) error {
	switch {
	case challenge == "" && method == "":
		return nil
	case challenge == "":
		return errors.New("code_challenge_method was given without a code_challenge")
	case method == "":
		return errors.New("code_challenge requires code_challenge_method=S256")
	case method != "S256":
		return errors.New("unsupported code_challenge_method: only S256 is supported")
	}
	return nil
}
