package authcode

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// Dynamic client registration (RFC 7591). Policy (proposed for owner review,
// docs/extended-grants.md): registration is off unless the operator enables
// it; registered clients are limited to a fixed safe subset of grants and
// authentication methods; redirect URIs follow the same rules as the
// authorization endpoint. RFC 7592 management is not implemented.

// RegistrationRequest is the subset of RFC 7591 §2 metadata this server
// honors. Unknown members are rejected by the HTTP layer, never ignored.
type RegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// RegistrationResponse is the RFC 7591 §3.2.1 response.
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
}

const (
	maxRegisteredRedirectURIs = 10
	maxClientNameLen          = 128
)

// registrableGrants are the grants a dynamically registered client may hold.
// client_credentials is excluded on purpose: it would let any registrant mint
// machine tokens.
var registrableGrants = map[string]bool{
	GrantAuthorizationCode: true,
	GrantRefreshToken:      true,
	GrantDeviceCode:        true,
}

// Register validates and stores a new client. allowedScopes is the policy
// ceiling: a client may only be registered for scopes within it, and gets all
// of them when it requests none is NOT the default: no scope is granted
// unless requested.
func (s *Service) Register(ctx context.Context, req RegistrationRequest, allowedScopes []string) (RegistrationResponse, error) {
	if len(req.RedirectURIs) == 0 {
		return RegistrationResponse{}, oauth.InvalidRedirectURI("redirect_uris is required")
	}
	if len(req.RedirectURIs) > maxRegisteredRedirectURIs {
		return RegistrationResponse{}, oauth.InvalidRedirectURI("too many redirect_uris")
	}
	for _, u := range req.RedirectURIs {
		if err := s.validateRegisteredRedirect(u); err != nil {
			return RegistrationResponse{}, err
		}
	}
	if len(req.ClientName) > maxClientNameLen {
		return RegistrationResponse{}, oauth.InvalidClientMetadata("client_name is too long")
	}

	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = MethodBasic // RFC 7591 default is client_secret_basic
	}
	switch method {
	case MethodBasic, MethodPost, "none":
	default:
		return RegistrationResponse{}, oauth.InvalidClientMetadata("token_endpoint_auth_method is not supported")
	}

	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode}
	}
	seen := map[string]bool{}
	for _, g := range grants {
		if !registrableGrants[g] || seen[g] {
			return RegistrationResponse{}, oauth.InvalidClientMetadata("grant_types contains an unsupported or repeated value")
		}
		seen[g] = true
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			return RegistrationResponse{}, oauth.InvalidClientMetadata("only response_type code is supported")
		}
	}
	if seen[GrantRefreshToken] && !seen[GrantAuthorizationCode] && !seen[GrantDeviceCode] {
		return RegistrationResponse{}, oauth.InvalidClientMetadata("refresh_token requires another grant")
	}

	var scopes []string
	if req.Scope != "" {
		allowed := map[string]bool{}
		for _, a := range allowedScopes {
			allowed[a] = true
		}
		for _, tok := range strings.Split(req.Scope, " ") {
			if tok == "" || !validScopeToken(tok) || !allowed[tok] {
				return RegistrationResponse{}, oauth.InvalidClientMetadata("scope is malformed or not permitted")
			}
			scopes = append(scopes, tok)
		}
	}

	idRaw, err := s.rnd.Bytes(16)
	if err != nil {
		return RegistrationResponse{}, oauth.ServerError(err)
	}
	rec := oauth.Client{
		ID:           "dyn-" + hex.EncodeToString(idRaw),
		Name:         req.ClientName,
		AuthMethod:   method,
		Public:       method == "none",
		RedirectURIs: req.RedirectURIs,
		Scopes:       scopes,
		GrantTypes:   grants,
	}
	resp := RegistrationResponse{
		ClientID: rec.ID, RedirectURIs: rec.RedirectURIs, ClientName: rec.Name,
		TokenEndpointAuthMethod: method, GrantTypes: grants, ResponseTypes: []string{"code"},
		Scope: strings.Join(scopes, " "),
	}
	if !rec.Public {
		secRaw, err := s.rnd.Bytes(tokenBytes)
		if err != nil {
			return RegistrationResponse{}, oauth.ServerError(err)
		}
		sec := hex.EncodeToString(secRaw)
		if rec.SecretHash, err = secret.Hash(s.rnd, sec); err != nil {
			return RegistrationResponse{}, oauth.ServerError(err)
		}
		resp.ClientSecret = sec
		// 0 = the secret does not expire (RFC 7591 §3.2.1).
		resp.ClientSecretExpiresAt = 0
	}
	if err := s.store.Clients().Create(ctx, rec); err != nil {
		if errors.Is(err, oauth.ErrConflict) {
			return RegistrationResponse{}, oauth.ServerError(err)
		}
		return RegistrationResponse{}, oauth.ServerError(err)
	}
	return resp, nil
}

// validateRegisteredRedirect applies the registration-time redirect rules: an
// absolute URI without fragment or userinfo; https, an RFC 8252 loopback
// http literal, or a private-use scheme.
func (s *Service) validateRegisteredRedirect(raw string) error {
	bad := func(msg string) error { return oauth.InvalidRedirectURI(msg) }
	if raw == "" || strings.ContainsAny(raw, "#\x00\r\n \t") {
		return bad("redirect_uri must not be empty or contain a fragment or whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil {
		return bad("redirect_uri must be an absolute URI without userinfo")
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return bad("redirect_uri needs a host")
		}
	case "http":
		h := u.Hostname()
		if !(isLoopbackHost(h) || s.insecure) {
			return bad("http redirect_uri is only allowed for loopback")
		}
	case "javascript", "data", "file", "vbscript", "about", "blob", "ftp":
		return bad("redirect_uri scheme is not allowed")
	default:
		// Private-use scheme (RFC 8252 §7.1) must contain a dot.
		if !strings.Contains(u.Scheme, ".") {
			return bad("private-use redirect_uri scheme must be a reverse domain name")
		}
	}
	return nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
