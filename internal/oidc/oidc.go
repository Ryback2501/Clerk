// Package oidc implements Clerk's OpenID Connect provider endpoints.
//
// Everything in this package must keep working regardless of whether admin
// authentication or its Bouncer dependency is healthy, so it deliberately
// imports neither internal/admin nor internal/adminauth.
package oidc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Ryback2501/Clerk/internal/keys"
)

// Endpoint paths, relative to the issuer.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	AuthorizePath = "/authorize"
	TokenPath     = "/token"
	UserInfoPath  = "/userinfo"
	JWKSPath      = "/jwks"
)

// Provider serves the OIDC endpoints.
type Provider struct {
	issuer *url.URL
	signer *keys.Signer
	logger *slog.Logger
}

// New builds a Provider for the given issuer identity and signing key.
func New(issuer *url.URL, signer *keys.Signer) *Provider {
	return &Provider{issuer: issuer, signer: signer, logger: slog.Default()}
}

// WithLogger returns a copy of p that logs to the given logger.
func (p *Provider) WithLogger(l *slog.Logger) *Provider {
	clone := *p
	clone.logger = l
	return &clone
}

// Register wires the provider's endpoints onto mux. The method is part of each
// pattern, so anything but GET falls through to a 405.
func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+DiscoveryPath, p.handleDiscovery)
	mux.HandleFunc("GET "+JWKSPath, p.handleJWKS)
}

// absolute renders an endpoint path as an absolute URL under the issuer.
// The issuer is stored without a trailing slash, so a simple join cannot
// produce a doubled separator.
func (p *Provider) absolute(path string) string {
	return strings.TrimSuffix(p.issuer.String(), "/") + path
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
		Issuer:                            p.issuer.String(),
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
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
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
