// Package authcode implements the authorization-code slice of the server:
// authorization request validation (exact redirect URI matching, S256-only
// PKCE, scope), one-time code issuance, client authentication at the token
// endpoint, and atomic single-use code redemption.
//
// It is independent of HTTP: the server package parses requests (rejecting
// duplicated parameters first, see oauth.ParseParams) and renders the results.
// Every failure is a typed *oauth.Error; storage failures surface as
// server_error without leaking detail.
package authcode

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// Defaults. Codes are short-lived (RFC 6749 §4.1.2 recommends at most ten
// minutes; a code is only needed for one immediate back-channel request).
const (
	DefaultCodeTTL        = 60 * time.Second
	DefaultAccessTokenTTL = time.Hour

	codeBytes  = 32 // 256 bits of entropy
	tokenBytes = 32
)

// Grant and method names.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantRefreshToken      = "refresh_token"

	MethodBasic = "client_secret_basic"
	MethodPost  = "client_secret_post"
)

// DefaultRefreshTokenTTL is how long a minted refresh token stays usable when
// the Service is not told otherwise. Refresh tokens are rotated on every use,
// so the TTL bounds one family, not one token.
const DefaultRefreshTokenTTL = 30 * 24 * time.Hour

// ErrInvalidCredentials is returned for every failed resource-owner login:
// unknown user, wrong password and empty input are indistinguishable.
var ErrInvalidCredentials = errors.New("authcode: invalid credentials")

// Config configures a Service.
type Config struct {
	Store  oauth.Store
	Clock  oauth.Clock
	Random oauth.Random

	// AllowInsecureRedirects permits plain-http non-loopback redirect URIs
	// (development only; refused in production by internal/config).
	AllowInsecureRedirects bool

	CodeTTL        time.Duration // DefaultCodeTTL when zero
	AccessTokenTTL time.Duration // DefaultAccessTokenTTL when zero

	// Tokens, when set, mints signed RFC 9068 access tokens (and their
	// revocation/introspection records) instead of the legacy opaque
	// placeholder. It is wired by the app; nil keeps the self-contained
	// behaviour the shared contract tests rely on before the token-lifecycle
	// slice is assembled.
	Tokens *token.Service

	// RefreshTokenTTL bounds a refresh-token rotation family (DefaultRefreshTokenTTL
	// when zero). Ignored when Tokens is nil.
	RefreshTokenTTL time.Duration
}

// Service is the authorization-code engine.
type Service struct {
	store    oauth.Store
	clock    oauth.Clock
	rnd      oauth.Random
	insecure bool
	codeTTL  time.Duration
	tokenTTL time.Duration

	tokens     *token.Service
	refreshTTL time.Duration

	// dummyHash is verified against when a client or user does not exist so
	// that a missing identity costs the same as a wrong secret.
	dummyHash string
}

// New validates cfg and returns a Service. It fails closed when a dependency
// is missing rather than defaulting one.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Clock == nil || cfg.Random == nil {
		return nil, errors.New("authcode: store, clock and random source are required")
	}
	s := &Service{
		store: cfg.Store, clock: cfg.Clock, rnd: cfg.Random,
		insecure: cfg.AllowInsecureRedirects,
		codeTTL:  cfg.CodeTTL, tokenTTL: cfg.AccessTokenTTL,
		tokens:     cfg.Tokens,
		refreshTTL: cfg.RefreshTokenTTL,
	}
	if s.codeTTL <= 0 {
		s.codeTTL = DefaultCodeTTL
	}
	if s.tokenTTL <= 0 {
		s.tokenTTL = DefaultAccessTokenTTL
	}
	if s.refreshTTL <= 0 {
		s.refreshTTL = DefaultRefreshTokenTTL
	}
	junk, err := cfg.Random.Bytes(16)
	if err != nil {
		return nil, fmt.Errorf("authcode: seed dummy hash: %w", err)
	}
	s.dummyHash, err = secret.Hash(cfg.Random, hex.EncodeToString(junk))
	if err != nil {
		return nil, fmt.Errorf("authcode: dummy hash: %w", err)
	}
	return s, nil
}

// AuthRequest is a validated authorization request.
type AuthRequest struct {
	Client        oauth.Client
	RedirectURI   string // the exact URI that was requested (loopback port included)
	State         string
	Scope         string
	CodeChallenge string
	Nonce         string // OIDC nonce, echoed in the id_token
}

// TokenResponse is a successful token response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// ---- authorization endpoint ----

// ResolveClient performs the checks whose failure must never redirect
// (RFC 6749 §4.1.2.1): a missing or unknown client, or a missing or
// unregistered redirect URI, is reported to the resource owner instead,
// because redirecting would make the server an open redirector.
//
// It returns the client and the requested redirect URI, which may differ from
// the registered string only by the port of a loopback literal (RFC 8252 §7.3).
func (s *Service) ResolveClient(ctx context.Context, p oauth.Params) (oauth.Client, string, error) {
	id := p.Get("client_id")
	if id == "" {
		return oauth.Client{}, "", oauth.InvalidRequest("client_id is required")
	}
	c, err := s.store.Clients().Get(ctx, id)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		// 401 follows the shared contract; no challenge is attached because
		// no client authentication was attempted at this endpoint.
		return oauth.Client{}, "", oauth.InvalidClient("unknown client", false).WithStatus(401)
	case err != nil:
		return oauth.Client{}, "", oauth.ServerError(err)
	}
	uri := p.Get("redirect_uri")
	if uri == "" {
		return oauth.Client{}, "", oauth.InvalidRequest("redirect_uri is required")
	}
	if !oauth.MatchRedirectURI(c.RedirectURIs, uri, s.insecure) {
		return oauth.Client{}, "", oauth.InvalidRequest("redirect_uri does not match a registered URI")
	}
	return c, uri, nil
}

// ValidateRequest checks the remaining authorization parameters. Its errors
// are safe to deliver through the (already validated) redirect URI.
func (s *Service) ValidateRequest(c oauth.Client, redirectURI string, p oauth.Params) (AuthRequest, error) {
	switch rt := p.Get("response_type"); rt {
	case "":
		return AuthRequest{}, oauth.InvalidRequest("response_type is required")
	case "code":
	default:
		// Implicit (token), hybrid and ID-token response types are not
		// supported; nothing but a code is ever returned in a redirect.
		return AuthRequest{}, oauth.UnsupportedResponseType("only response_type=code is supported")
	}
	// Signed or by-reference request objects are not implemented. Ignoring
	// them would let a client believe its protected parameters were honored.
	if p.Has("request") || p.Has("request_uri") {
		return AuthRequest{}, oauth.InvalidRequest("request objects are not supported")
	}
	if !grantAllowed(c, GrantAuthorizationCode) {
		return AuthRequest{}, oauth.UnauthorizedClient("client may not use the authorization code grant")
	}

	challenge := p.Get("code_challenge")
	if challenge == "" {
		return AuthRequest{}, oauth.InvalidRequest("code_challenge is required (PKCE)")
	}
	switch m := p.Get("code_challenge_method"); m {
	case "":
		return AuthRequest{}, oauth.InvalidRequest("code_challenge_method is required")
	case oauth.MethodS256:
	default:
		return AuthRequest{}, oauth.InvalidRequest("only code_challenge_method=S256 is supported")
	}
	if !oauth.ValidCodeChallenge(challenge) {
		return AuthRequest{}, oauth.InvalidRequest("code_challenge is malformed")
	}

	scope, err := validateScope(c, p.Get("scope"))
	if err != nil {
		return AuthRequest{}, err
	}
	return AuthRequest{
		Client: c, RedirectURI: redirectURI, State: p.Get("state"),
		Scope: scope, CodeChallenge: challenge, Nonce: p.Get("nonce"),
	}, nil
}

// IssueCode creates a one-time authorization code for userID and returns it.
// Only the SHA-256 of the code is stored, together with everything the
// redemption must re-check (client, exact redirect URI, PKCE challenge).
func (s *Service) IssueCode(ctx context.Context, req AuthRequest, userID string) (string, error) {
	raw, err := s.rnd.Bytes(codeBytes)
	if err != nil {
		return "", oauth.ServerError(err)
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	rec := oauth.AuthorizationCode{
		CodeHash:            hashCode(code),
		ClientID:            req.Client.ID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: oauth.MethodS256,
		Nonce:               req.Nonce,
		ExpiresAt:           s.clock.Now().Add(s.codeTTL),
	}
	if err := s.store.AuthCodes().Create(ctx, rec); err != nil {
		return "", oauth.ServerError(err)
	}
	return code, nil
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// ---- token endpoint ----

// Token handles a token request. authorization is the raw Authorization
// header ("" when absent); p holds the form body parameters.
func (s *Service) Token(ctx context.Context, authorization string, p oauth.Params) (TokenResponse, error) {
	grant := p.Get("grant_type")
	if grant == "" {
		return TokenResponse{}, oauth.InvalidRequest("grant_type is required")
	}
	// Decide support before authenticating so an unsupported grant (including
	// the prohibited password grant) is refused without touching credentials.
	if grant != GrantAuthorizationCode && grant != GrantClientCredentials && grant != GrantRefreshToken {
		return TokenResponse{}, oauth.UnsupportedGrantType("grant_type is not supported")
	}

	client, err := s.authenticateClient(ctx, authorization, p)
	if err != nil {
		return TokenResponse{}, err
	}
	if !grantAllowed(client, grant) {
		return TokenResponse{}, oauth.UnauthorizedClient("client may not use this grant type")
	}

	switch grant {
	case GrantAuthorizationCode:
		return s.redeemCode(ctx, client, p)
	case GrantRefreshToken:
		return s.refreshToken(ctx, client, p)
	default:
		return s.clientCredentials(ctx, client, p)
	}
}

func (s *Service) redeemCode(ctx context.Context, client oauth.Client, p oauth.Params) (TokenResponse, error) {
	code := p.Get("code")
	if code == "" {
		return TokenResponse{}, oauth.InvalidRequest("code is required")
	}
	redirectURI := p.Get("redirect_uri")
	if redirectURI == "" {
		return TokenResponse{}, oauth.InvalidRequest("redirect_uri is required")
	}
	// A verifier that is absent or malformed can never match: refuse it before
	// the code is consumed so a broken request does not burn a good code.
	verifier := p.Get("code_verifier")
	if !oauth.ValidCodeVerifier(verifier) {
		return TokenResponse{}, oauth.InvalidGrant("code_verifier is missing or malformed")
	}

	// Atomic one-time redemption. From here on the code is spent whatever the
	// outcome: every further check is a single guess per code.
	now := s.clock.Now()
	rec, err := s.store.AuthCodes().Consume(ctx, hashCode(code), now)
	switch {
	case errors.Is(err, oauth.ErrNotFound), errors.Is(err, oauth.ErrAlreadyConsumed):
		// Replay or fabricated code. (RFC 9700 §2.1.1 asks that tokens issued
		// from a replayed code be revoked; access tokens are not persisted in
		// this slice, so there is nothing to revoke yet.)
		return TokenResponse{}, oauth.InvalidGrant("authorization code is invalid, expired or already used")
	case err != nil:
		return TokenResponse{}, oauth.ServerError(err)
	}

	if !now.Before(rec.ExpiresAt) {
		return TokenResponse{}, oauth.InvalidGrant("authorization code is invalid, expired or already used")
	}
	if rec.ClientID != client.ID {
		return TokenResponse{}, oauth.InvalidGrant("authorization code was not issued to this client")
	}
	// Exact comparison with the URI used at authorization (RFC 6749 §4.1.3),
	// including a loopback port: no pattern matching on this side.
	if rec.RedirectURI != redirectURI {
		return TokenResponse{}, oauth.InvalidGrant("redirect_uri does not match the authorization request")
	}
	if rec.CodeChallengeMethod != oauth.MethodS256 || !oauth.VerifyS256(rec.CodeChallenge, verifier) {
		return TokenResponse{}, oauth.InvalidGrant("code_verifier does not match the code_challenge")
	}
	resp, err := s.issueTokens(ctx, client.ID, rec.UserID, rec.Scope, true, "")
	if err != nil {
		return TokenResponse{}, err
	}
	// OIDC Core 3.1.3.3: an id_token accompanies the response only when the
	// granted scope includes openid.
	if s.tokens != nil && hasScope(rec.Scope, "openid") {
		idt, err := s.tokens.IssueIDToken(ctx, token.IDTokenParams{ClientID: client.ID, Subject: rec.UserID, Nonce: rec.Nonce})
		if err != nil {
			return TokenResponse{}, err
		}
		resp.IDToken = idt
	}
	return resp, nil
}

func hasScope(scope, want string) bool {
	for _, f := range strings.Fields(scope) {
		if f == want {
			return true
		}
	}
	return false
}

func (s *Service) clientCredentials(ctx context.Context, client oauth.Client, p oauth.Params) (TokenResponse, error) {
	if client.Public {
		return TokenResponse{}, oauth.UnauthorizedClient("a public client cannot use the client credentials grant")
	}
	scope, err := validateScope(client, p.Get("scope"))
	if err != nil {
		return TokenResponse{}, err
	}
	// The subject of a machine-to-machine token is the client itself (RFC 9068
	// §2.2); no refresh token is issued for this grant.
	return s.issueTokens(ctx, client.ID, client.ID, scope, false, "")
}

// refreshToken handles grant_type=refresh_token (RFC 6749 §6): authenticates
// the refresh token against the presented client, enforces client binding and
// scope narrowing, then rotates it and mints a replacement pair.
func (s *Service) refreshToken(ctx context.Context, client oauth.Client, p oauth.Params) (TokenResponse, error) {
	raw := p.Get("refresh_token")
	if raw == "" {
		return TokenResponse{}, oauth.InvalidRequest("refresh_token is required")
	}
	hash := hashToken(raw)

	// Read the original record without consuming it so client binding and
	// scope are checked before any rotation (a wrong client or an escalation
	// must not burn the legitimate token).
	rec, err := s.store.RefreshTokens().GetByHash(ctx, hash)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return TokenResponse{}, oauth.InvalidGrant("refresh token is invalid or expired")
	case err != nil:
		return TokenResponse{}, oauth.ServerError(err)
	}

	// Client binding: the token must belong to the presenting client.
	if rec.ClientID != client.ID {
		return TokenResponse{}, oauth.InvalidGrant("refresh token was not issued to this client")
	}
	if !s.clock.Now().Before(rec.ExpiresAt) {
		return TokenResponse{}, oauth.InvalidGrant("refresh token is invalid or expired")
	}

	// Scope narrowing: the requested scope must be a subset of the original.
	scope := rec.Scope
	if requested := p.Get("scope"); requested != "" {
		var err error
		scope, err = narrowScope(rec.Scope, requested)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	// Consume (rotate) the presented token within its family. On replay the
	// family is revoked and the grant refused (reuse detection).
	rotated, err := s.rotateRefresh(ctx, hash, rec.FamilyID)
	switch {
	case errors.Is(err, oauth.ErrAlreadyConsumed):
		return TokenResponse{}, oauth.InvalidGrant("refresh token is invalid")
	case err != nil:
		return TokenResponse{}, oauth.ServerError(err)
	}

	// The replacement shares the rotated token's family so a replayed member
	// revokes the whole lineage, including this new token (RFC 6819 §5.2.2.3 /
	// RFC 9700 §2.1.5 cascade revocation).
	return s.issueTokens(ctx, client.ID, rec.UserID, scope, true, rotated.FamilyID)
}

// issueTokens mints an access token and, when withRefresh is true, a refresh
// token. familyID, when non-empty, is the rotation family the minted refresh
// token joins (empty mints a fresh family). When the Service has a token.Service
// it uses it for signed RFC 9068 access tokens; otherwise it falls back to the
// legacy opaque placeholder so the pre-lifecycle contract tests keep passing.
func (s *Service) issueTokens(ctx context.Context, clientID, subject, scope string, withRefresh bool, familyID string) (TokenResponse, error) {
	resp := TokenResponse{TokenType: "Bearer", Scope: scope}

	if s.tokens != nil {
		at, err := s.tokens.Issue(ctx, token.IssueParams{ClientID: clientID, Subject: subject, Scope: scope})
		if err != nil {
			return TokenResponse{}, err
		}
		resp.AccessToken = at.Value
		resp.TokenType = at.TokenType
		resp.ExpiresIn = int64(at.ExpiresAt.Sub(at.IssuedAt) / time.Second)
	} else {
		raw, err := s.rnd.Bytes(tokenBytes)
		if err != nil {
			return TokenResponse{}, oauth.ServerError(err)
		}
		resp.AccessToken = base64.RawURLEncoding.EncodeToString(raw)
		resp.ExpiresIn = int64(s.tokenTTL / time.Second)
	}

	if withRefresh {
		rt, err := s.mintRefreshToken(ctx, clientID, subject, scope, familyID)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.RefreshToken = rt
	}
	return resp, nil
}

// mintRefreshToken creates an opaque refresh token and persists only its hash.
// When familyID is non-empty the token joins that existing rotation family
// (used on rotation so a replay revokes the whole lineage); otherwise a fresh
// family is minted (a new grant lineage).
func (s *Service) mintRefreshToken(ctx context.Context, clientID, userID, scope, familyID string) (string, error) {
	raw, err := s.rnd.Bytes(tokenBytes)
	if err != nil {
		return "", oauth.ServerError(err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	if familyID == "" {
		fam, err := s.rnd.Bytes(16)
		if err != nil {
			return "", oauth.ServerError(err)
		}
		familyID = hex.EncodeToString(fam)
	}
	rec := oauth.RefreshToken{
		TokenHash: hashToken(value),
		FamilyID:  familyID,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: s.clock.Now().Add(s.refreshTTL),
	}
	if err := s.store.RefreshTokens().Create(ctx, rec); err != nil {
		return "", oauth.ServerError(err)
	}
	return value, nil
}

// rotateRefresh consumes a refresh token, revoking its family on replay. It
// delegates to token.Service when present so the service owns family-replay
// revocation; otherwise it uses the store directly and revokes the family
// itself on replay (mirroring token.Service.RotateRefresh).
func (s *Service) rotateRefresh(ctx context.Context, hash, familyID string) (oauth.RefreshToken, error) {
	if s.tokens != nil {
		return s.tokens.RotateRefresh(ctx, hash, familyID)
	}
	t, err := s.store.RefreshTokens().Rotate(ctx, hash, s.clock.Now())
	if errors.Is(err, oauth.ErrAlreadyConsumed) && familyID != "" {
		_, _ = s.store.RefreshTokens().RevokeFamily(ctx, familyID, s.clock.Now())
	}
	return t, err
}

func hashToken(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// ---- client authentication ----

// AuthenticateClient authenticates the caller of a client-authenticated
// endpoint (token, introspection, revocation) using exactly one method and
// enforcing the method the client registered. It is the exported form of the
// token endpoint's authentication used by the token-lifecycle endpoints, which
// need the client identity for owner binding.
func (s *Service) AuthenticateClient(ctx context.Context, authorization string, p oauth.Params) (oauth.Client, error) {
	return s.authenticateClient(ctx, authorization, p)
}

// authenticateClient authenticates the caller of the token endpoint using
// exactly one method, and enforces the method the client registered.
func (s *Service) authenticateClient(ctx context.Context, authorization string, p oauth.Params) (oauth.Client, error) {
	if authorization != "" {
		return s.authenticateBasic(ctx, authorization, p)
	}

	id := p.Get("client_id")
	if id == "" {
		return oauth.Client{}, invalidClientBody("client authentication is required")
	}
	c, err := s.lookupClient(ctx, id)
	if err != nil {
		return oauth.Client{}, wrapAuthErr(err, false)
	}
	presented := p.Has("client_secret")

	if c.Public {
		// A public client is identified, not authenticated: PKCE is its
		// protection. Presenting a secret is a misconfiguration worth refusing
		// rather than silently ignoring.
		if presented {
			return oauth.Client{}, invalidClientBody("a public client must not present a secret")
		}
		return c, nil
	}
	if c.AuthMethod != MethodPost || !presented {
		return oauth.Client{}, invalidClientBody("client authentication failed")
	}
	if err := s.checkSecret(c, p.Get("client_secret")); err != nil {
		return oauth.Client{}, wrapAuthErr(err, false)
	}
	return c, nil
}

func (s *Service) authenticateBasic(ctx context.Context, header string, p oauth.Params) (oauth.Client, error) {
	scheme, cred, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return oauth.Client{}, oauth.InvalidRequest("unsupported Authorization scheme")
	}
	// RFC 6749 §2.3: no more than one authentication method per request.
	if p.Has("client_secret") {
		return oauth.Client{}, oauth.InvalidRequest("multiple client authentication methods")
	}
	id, sec, err := decodeBasic(strings.TrimSpace(cred))
	if err != nil {
		return oauth.Client{}, oauth.InvalidClient("malformed client credentials", true)
	}
	if bodyID := p.Get("client_id"); bodyID != "" && bodyID != id {
		return oauth.Client{}, oauth.InvalidRequest("client_id disagrees with the authenticated client")
	}
	c, err := s.lookupClient(ctx, id)
	if err != nil {
		return oauth.Client{}, wrapAuthErr(err, true)
	}
	if c.Public || c.AuthMethod != MethodBasic || sec == "" {
		return oauth.Client{}, oauth.InvalidClient("client authentication failed", true)
	}
	if err := s.checkSecret(c, sec); err != nil {
		return oauth.Client{}, wrapAuthErr(err, true)
	}
	return c, nil
}

// decodeBasic parses an RFC 7617 credential whose id and secret were
// form-urlencoded before base64 (RFC 6749 §2.3.1).
func decodeBasic(b64 string) (id, sec string, err error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", err
	}
	rawID, rawSec, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", errors.New("no separator")
	}
	if id, err = url.QueryUnescape(rawID); err != nil {
		return "", "", err
	}
	if sec, err = url.QueryUnescape(rawSec); err != nil {
		return "", "", err
	}
	if id == "" {
		return "", "", errors.New("empty client id")
	}
	return id, sec, nil
}

// errAuthFailed marks an authentication failure that has already been
// decided; wrapAuthErr turns it into the right typed error.
var errAuthFailed = errors.New("authcode: client authentication failed")

func wrapAuthErr(err error, basic bool) error {
	if errors.Is(err, errAuthFailed) {
		if basic {
			return oauth.InvalidClient("client authentication failed", true)
		}
		return invalidClientBody("client authentication failed")
	}
	return err
}

func invalidClientBody(desc string) *oauth.Error {
	return oauth.InvalidClient(desc, false).WithStatus(401)
}

// lookupClient returns the client, or errAuthFailed after burning the time a
// real secret check would take when it does not exist.
func (s *Service) lookupClient(ctx context.Context, id string) (oauth.Client, error) {
	c, err := s.store.Clients().Get(ctx, id)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		_, _ = secret.Verify(s.dummyHash, "x")
		return oauth.Client{}, errAuthFailed
	case err != nil:
		return oauth.Client{}, oauth.ServerError(err)
	}
	return c, nil
}

// checkSecret verifies a confidential client's secret. A confidential client
// without a stored hash can never authenticate.
func (s *Service) checkSecret(c oauth.Client, presented string) error {
	if c.SecretHash == "" || presented == "" {
		_, _ = secret.Verify(s.dummyHash, "x")
		return errAuthFailed
	}
	ok, err := secret.Verify(c.SecretHash, presented)
	if err != nil {
		return oauth.ServerError(err)
	}
	if !ok {
		return errAuthFailed
	}
	return nil
}

// ---- helpers ----

// grantAllowed reports whether the client may use grant. A client that
// registered no grant types gets the RFC 7591 default: authorization_code.
func grantAllowed(c oauth.Client, grant string) bool {
	if len(c.GrantTypes) == 0 {
		return grant == GrantAuthorizationCode
	}
	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

// validateScope checks the syntax of each space-delimited scope token (RFC
// 6749 §3.3) and that the client is registered for every one. A client with
// no registered scopes may request none.
func validateScope(c oauth.Client, scope string) (string, error) {
	if scope == "" {
		return "", nil
	}
	allowed := make(map[string]bool, len(c.Scopes))
	for _, sc := range c.Scopes {
		allowed[sc] = true
	}
	for _, tok := range strings.Split(scope, " ") {
		if tok == "" || !validScopeToken(tok) {
			return "", oauth.InvalidScope("malformed scope")
		}
		if !allowed[tok] {
			return "", oauth.InvalidScope("scope is not permitted for this client")
		}
	}
	return scope, nil
}

// narrowScope validates that every requested scope was already granted to the
// original token. An empty or omitted request returns the original scope.
func narrowScope(original, requested string) (string, error) {
	allowed := make(map[string]bool)
	for _, tok := range strings.Split(original, " ") {
		if tok != "" {
			allowed[tok] = true
		}
	}
	for _, tok := range strings.Split(requested, " ") {
		if tok == "" || !validScopeToken(tok) {
			return "", oauth.InvalidScope("malformed scope")
		}
		if !allowed[tok] {
			return "", oauth.InvalidScope("scope is not permitted")
		}
	}
	return strings.TrimSpace(requested), nil
}

func validScopeToken(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

// ---- resource owner ----

// AuthenticateUser verifies a resource owner's username and password.
func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (oauth.User, error) {
	if username == "" || password == "" {
		return oauth.User{}, ErrInvalidCredentials
	}
	u, err := s.store.Users().GetByUsername(ctx, username)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		_, _ = secret.Verify(s.dummyHash, "x")
		return oauth.User{}, ErrInvalidCredentials
	case err != nil:
		return oauth.User{}, oauth.ServerError(err)
	}
	ok, err := secret.Verify(u.PasswordHash, password)
	if err != nil {
		return oauth.User{}, oauth.ServerError(err)
	}
	if !ok {
		return oauth.User{}, ErrInvalidCredentials
	}
	return u, nil
}

// UserByUsername resolves the user named by a verified session. A user that
// no longer exists is reported as ErrInvalidCredentials so a stale session
// simply sends the browser back to login.
func (s *Service) UserByUsername(ctx context.Context, username string) (oauth.User, error) {
	u, err := s.store.Users().GetByUsername(ctx, username)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return oauth.User{}, ErrInvalidCredentials
	case err != nil:
		return oauth.User{}, oauth.ServerError(err)
	}
	return u, nil
}
