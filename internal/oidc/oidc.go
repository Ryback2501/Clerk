// Package oidc implements Clerk's OpenID Connect provider endpoints.
//
// Everything in this package must keep working regardless of whether admin
// authentication or its Bouncer dependency is healthy, so it deliberately
// imports neither internal/admin nor internal/adminauth.
package oidc

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ryback2501/Clerk/internal/keys"
	"github.com/Ryback2501/Clerk/internal/store"
	"github.com/Ryback2501/Clerk/internal/web"
)

//go:embed all:templates
var templateFS embed.FS

// Defaults for the lifetimes the provider controls.
const (
	// DefaultCodeTTL is short by design: an authorization code is redeemed
	// within seconds of being issued, so a long window only widens the
	// opportunity to replay an intercepted one.
	DefaultCodeTTL = time.Minute

	// DefaultAuthRequestTTL bounds how long a rendered login page stays valid.
	DefaultAuthRequestTTL = 15 * time.Minute

	// DefaultTokenTTL is the fallback lifetime for access and ID tokens.
	DefaultTokenTTL = time.Hour
)

// Endpoint paths, relative to the issuer.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	AuthorizePath = "/authorize"
	TokenPath     = "/token"
	UserInfoPath  = "/userinfo"
	JWKSPath      = "/jwks"
)

// Options are the dependencies a Provider needs.
type Options struct {
	// Issuer is the public base URL of this provider.
	Issuer *url.URL

	// Signer holds the RS256 key ID tokens are signed with.
	Signer *keys.Signer

	// Store is the database the provider reads clients and users from.
	Store *store.Store

	// Lifetimes; each defaults when left zero.
	CodeTTL        time.Duration
	AuthRequestTTL time.Duration
	AccessTokenTTL time.Duration
	IDTokenTTL     time.Duration

	// Logger defaults to the package-level logger.
	Logger *slog.Logger

	// Now defaults to time.Now. Overriding it lets tests assert token
	// lifetimes exactly instead of sleeping.
	Now func() time.Time
}

// Provider serves the OIDC endpoints.
type Provider struct {
	issuer *url.URL
	signer *keys.Signer
	store  *store.Store
	logger *slog.Logger

	csrf  *web.CSRF
	pages map[string]*template.Template

	codeTTL        time.Duration
	authRequestTTL time.Duration
	accessTokenTTL time.Duration
	idTokenTTL     time.Duration

	// now is injectable so token lifetimes can be tested without sleeping.
	now func() time.Time
}

// New builds a Provider.
func New(opts Options) (*Provider, error) {
	switch {
	case opts.Issuer == nil:
		return nil, errors.New("oidc: an issuer is required")
	case opts.Signer == nil:
		return nil, errors.New("oidc: a signing key is required")
	case opts.Store == nil:
		return nil, errors.New("oidc: a store is required")
	}

	pages, err := parsePages()
	if err != nil {
		return nil, err
	}

	p := &Provider{
		issuer:         opts.Issuer,
		signer:         opts.Signer,
		store:          opts.Store,
		logger:         opts.Logger,
		csrf:           web.NewCSRF(web.LoginCSRFCookie),
		pages:          pages,
		codeTTL:        opts.CodeTTL,
		authRequestTTL: opts.AuthRequestTTL,
		accessTokenTTL: opts.AccessTokenTTL,
		idTokenTTL:     opts.IDTokenTTL,
		now:            opts.Now,
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}
	if p.codeTTL == 0 {
		p.codeTTL = DefaultCodeTTL
	}
	if p.authRequestTTL == 0 {
		p.authRequestTTL = DefaultAuthRequestTTL
	}
	if p.accessTokenTTL == 0 {
		p.accessTokenTTL = DefaultTokenTTL
	}
	if p.idTokenTTL == 0 {
		p.idTokenTTL = DefaultTokenTTL
	}
	return p, nil
}

// parsePages pairs each content template with the shared layout.
func parsePages() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}

	pages := make(map[string]*template.Template)
	for _, name := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(name, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[base] = t
	}
	if len(pages) == 0 {
		return nil, errors.New("oidc: no templates were embedded")
	}
	return pages, nil
}

// pageData is the view model the login and error pages render against.
type pageData struct {
	Title           string
	Stylesheet      string
	ApplicationName string
	Message         string
	Detail          string
	Users           []*store.User
	RequestID       string
	CSRFToken       string
	CSRFField       string

	// AuthorizeAction is where the login form posts. It is rendered rather
	// than hardcoded because the endpoints are mounted under the issuer's
	// path, and a form pointing at the server root would be unreachable there.
	AuthorizeAction string

	// formAction is the value of the CSP directive of the same name, empty on
	// pages that submit nowhere.
	formAction string
}

// renderPage writes an HTML page. Rendering into a buffer first means a
// failure halfway through cannot emit a half-written page under a 200.
func (p *Provider) renderPage(w http.ResponseWriter, r *http.Request, page string, status int, data pageData) {
	tmpl, ok := p.pages[page]
	if !ok {
		p.logger.ErrorContext(r.Context(), "unknown template", "page", page)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	data.Stylesheet = p.path(web.StaticPath) + web.StylesheetFile
	data.CSRFField = web.CSRFFieldName

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		p.logger.ErrorContext(r.Context(), "render template", "page", page, "err", err)
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// form-action is scoped per page. The login form's response is a redirect
	// to the client's registered URI, and WebKit enforces form-action across
	// redirects that follow a form submission — a bare 'self' would break
	// sign-in in Safari at the final hop while working elsewhere.
	formAction := "'none'"
	if data.formAction != "" {
		formAction = data.formAction
	}
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "+
			"form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		p.logger.ErrorContext(r.Context(), "write response", "page", page, "err", err)
	}
}

// refuse reports a problem to the person in front of the browser without
// sending anything to the client application. It is used for exactly the cases
// where the request cannot be shown to belong to a registered client.
func (p *Provider) refuse(w http.ResponseWriter, r *http.Request, title, message, detail string) {
	p.refuseStatus(w, r, http.StatusBadRequest, title, message, detail)
}

// refuseStatus is refuse with an explicit status, so an internal fault is not
// reported as a client error — a proxy or uptime check reading a 400 would
// treat a database outage as permanent and never retry or alarm.
func (p *Provider) refuseStatus(w http.ResponseWriter, r *http.Request, status int, title, message, detail string) {
	p.renderPage(w, r, "error", status, pageData{
		Title:   title,
		Message: message,
		Detail:  detail,
	})
}

// Register wires the provider's endpoints onto mux. The method is part of each
// pattern, so anything but GET falls through to a 405.
//
// Endpoints are mounted under the issuer's path, not at the server root. An
// issuer of https://example.com/oidc advertises https://example.com/oidc/jwks
// in its discovery document, so that is the path this server must answer on —
// otherwise every client that follows discovery gets a 404 on JWKS and can
// never verify an ID token. Deployments behind a proxy must therefore forward
// the full path rather than stripping the prefix.
func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.path(DiscoveryPath), p.handleDiscovery)
	mux.HandleFunc("GET "+p.path(JWKSPath), p.handleJWKS)
	mux.HandleFunc("GET "+p.path(AuthorizePath), p.handleAuthorize)
	mux.HandleFunc("POST "+p.path(AuthorizePath), p.handleLogin)
	mux.HandleFunc("POST "+p.path(TokenPath), p.handleToken)

	// Serve the shared assets under the issuer's path too, so a proxy
	// forwarding only that prefix still reaches the login page's stylesheet.
	if prefix := p.path(web.StaticPath); prefix != web.StaticPath {
		web.RegisterAt(mux, prefix)
	}
}

// base is the issuer with any trailing slash removed, so joining a path cannot
// produce a doubled separator. config.parseIssuer already normalises this; the
// trim keeps Provider correct when constructed directly, as tests do.
func (p *Provider) base() string {
	return strings.TrimRight(p.issuer.String(), "/")
}

// path renders an endpoint path as served by this process: the issuer's path
// prefix plus the endpoint.
func (p *Provider) path(endpoint string) string {
	return strings.TrimRight(p.issuer.Path, "/") + endpoint
}

// absolute renders an endpoint path as the absolute URL clients should call.
func (p *Provider) absolute(endpoint string) string {
	return p.base() + endpoint
}

// discoveryDocument is the OpenID Provider Metadata served at
// /.well-known/openid-configuration. Only capabilities that are actually
// implemented are advertised: a client that sees refresh_token or an implicit
// response type here would request it and fail.
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := discoveryDocument{
		Issuer:                            p.base(),
		AuthorizationEndpoint:             p.absolute(AuthorizePath),
		TokenEndpoint:                     p.absolute(TokenPath),
		UserInfoEndpoint:                  p.absolute(UserInfoPath),
		JWKSURI:                           p.absolute(JWKSPath),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "iat", "exp", "nonce", "name"},
	}
	p.writeJSON(w, r, doc)
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	p.writeJSON(w, r, p.signer.JWKS())
}

func (p *Provider) writeJSON(w http.ResponseWriter, r *http.Request, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		// Encoding a fixed struct cannot realistically fail; if it does, the
		// response is already unrecoverable, so report it without detail.
		p.logger.ErrorContext(r.Context(), "encode response", "path", r.URL.Path, "err", err)
		// Not http.Error: it would label this JSON body as text/plain, which a
		// client checking the content type before parsing would refuse to read.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		p.logger.ErrorContext(r.Context(), "write response", "path", r.URL.Path, "err", err)
	}
}
