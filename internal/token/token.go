// Package token implements the token-lifecycle slice of the server: issuing
// RFC 9068 access tokens (signed RS256 "at+jwt" JWTs, persisted for revocation
// and introspection), verifying them, RFC 7662 introspection, RFC 7009
// revocation with owner binding, and refresh-token rotation with family replay
// revocation.
//
// It is independent of HTTP: the server package parses requests and renders the
// results. Every failure is a typed *oauth.Error; storage failures surface as
// server_error without leaking detail. Signature/typ verification is delegated
// to the injected oauth.Verifier (the jwt.Verifier enforces typ="at+jwt" when
// constructed with jwt.WithRequiredType); this service adds the RFC 9068 claim
// validation (issuer, expiry, sub/client_id) and the revocation lookup.
package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// DefaultAccessTokenTTL is the lifetime of an issued access token when the
// issue operation does not specify one.
const DefaultAccessTokenTTL = time.Hour

// AccessTokenType is the JOSE typ header for access tokens (RFC 9068 §2.1).
const AccessTokenType = "at+jwt"

// TokenTypeName is the RFC 6749 §7.1 token_type value for a bearer token.
const TokenTypeName = "Bearer"

// TokenTypeDPoP is the token_type of a DPoP-bound access token (RFC 9449 §5).
const TokenTypeDPoP = "DPoP"

// jtiBytes is the entropy of an access-token jti (128 bits).
const jtiBytes = 16

// Signer signs claim sets and reports its active key id.
type Signer interface {
	oauth.Signer
	Kid() string
}

// KeySet exposes the signing key identity and the published public keys for the
// discovery endpoint (RFC 8414). The jwt.KeySet satisfies it.
type KeySet interface {
	KeyID() string
	PublicJWKS() (json.RawMessage, error)
}

// Config configures a Service.
type Config struct {
	// Issuer is the "iss" claim and must be a non-empty absolute http(s) URL.
	Issuer string

	Signer   Signer
	Verifier oauth.Verifier
	Keys     KeySet

	// IDSigner and IDVerifier sign and verify OIDC id_tokens (typ "JWT") with
	// the same key set. Optional: without them IssueIDToken fails closed.
	IDSigner   Signer
	IDVerifier oauth.Verifier

	Store  oauth.Store
	Clock  oauth.Clock
	Random oauth.Random

	// AccessTokenTTL defaults to DefaultAccessTokenTTL when zero.
	AccessTokenTTL time.Duration
}

// Service is the token-lifecycle engine.
type Service struct {
	issuer   string
	signer   Signer
	verifier oauth.Verifier
	keys     KeySet
	idSigner Signer
	idVer    oauth.Verifier
	store    oauth.Store
	clock    oauth.Clock
	rnd      oauth.Random
	ttl      time.Duration
}

// New validates cfg and returns a Service. It fails closed when a required
// dependency or an invalid issuer is missing rather than defaulting one.
func New(cfg Config) (*Service, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("token: issuer is required")
	}
	if cfg.Signer == nil || cfg.Verifier == nil || cfg.Keys == nil {
		return nil, errors.New("token: signer, verifier and key set are required")
	}
	if cfg.Store == nil || cfg.Clock == nil || cfg.Random == nil {
		return nil, errors.New("token: store, clock and random source are required")
	}
	if cfg.Signer.Kid() == "" {
		return nil, errors.New("token: signer key id is empty")
	}
	s := &Service{
		issuer:   cfg.Issuer,
		signer:   cfg.Signer,
		verifier: cfg.Verifier,
		keys:     cfg.Keys,
		idSigner: cfg.IDSigner,
		idVer:    cfg.IDVerifier,
		store:    cfg.Store,
		clock:    cfg.Clock,
		rnd:      cfg.Random,
		ttl:      cfg.AccessTokenTTL,
	}
	if s.ttl <= 0 {
		s.ttl = DefaultAccessTokenTTL
	}
	return s, nil
}

// IssueParams names the subject and scope of an access token.
type IssueParams struct {
	ClientID string
	Subject  string // the resource-owner id, used as the "sub" claim
	Scope    string // space-separated scopes

	// JKT, when set, binds the token to the DPoP proof key with this RFC 7638
	// thumbprint through a cnf.jkt claim (RFC 9449 §6.1) and makes the token
	// type DPoP. Empty mints an ordinary bearer token.
	JKT string
}

// AccessToken is an issued access token: the signed JWT value plus the
// lifecycle metadata needed by the caller and the persisted record.
type AccessToken struct {
	Value     string
	TokenType string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Scope     string
}

// Issue mints an access token: it generates a jti, signs the RFC 9068 claim
// set with the server key (iss, sub, client_id, jti, iat, exp, scope and kid),
// and persists the jti and lifecycle metadata so the token can be revoked and
// introspected.
func (s *Service) Issue(ctx context.Context, p IssueParams) (AccessToken, error) {
	if p.ClientID == "" {
		return AccessToken{}, oauth.InvalidRequest("client_id is required")
	}
	if p.Subject == "" {
		return AccessToken{}, oauth.InvalidRequest("subject is required")
	}

	raw, err := s.rnd.Bytes(jtiBytes)
	if err != nil {
		return AccessToken{}, oauth.ServerError(err)
	}
	jti := hex.EncodeToString(raw)

	now := s.clock.Now()
	exp := now.Add(s.ttl)

	claims := map[string]any{
		"iss":       s.issuer,
		"sub":       p.Subject,
		"client_id": p.ClientID,
		"jti":       jti,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"scope":     p.Scope,
		"kid":       s.signer.Kid(),
	}
	tokenType := TokenTypeName
	if p.JKT != "" {
		claims["cnf"] = map[string]any{"jkt": p.JKT}
		tokenType = TokenTypeDPoP
	}
	value, err := s.signer.Sign(ctx, claims)
	if err != nil {
		return AccessToken{}, oauth.ServerError(err)
	}

	rec := oauth.AccessToken{
		JTI:       jti,
		ClientID:  p.ClientID,
		UserID:    p.Subject,
		Scope:     p.Scope,
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	if err := s.store.AccessTokens().Create(ctx, rec); err != nil {
		return AccessToken{}, oauth.ServerError(err)
	}

	return AccessToken{
		Value:     value,
		TokenType: tokenType,
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: exp,
		Scope:     p.Scope,
	}, nil
}

// TokenInfo is the RFC 7662 introspection result. ExpiresAt/IssuedAt are Unix
// seconds; they are zero when unknown (an inactive token).
type TokenInfo struct {
	Active    bool
	Scope     string
	ClientID  string
	Username  string
	Sub       string
	TokenType string
	JTI       string
	Issuer    string
	ExpiresAt int64
	IssuedAt  int64
	// JKT is the DPoP proof-key thumbprint the token is bound to, or empty.
	JKT string
}

// VerifiedToken is the identity carried by a validated access token, for a
// resource server that verified a presented bearer token (RFC 6750/RFC 9068).
type VerifiedToken struct {
	ClientID string
	Subject  string
	Scope    string
	JTI      string
	// JKT is the cnf.jkt binding; non-empty means the token is DPoP-bound and
	// must be presented with a matching proof, never as a bare Bearer.
	JKT string
}

// claims is the validated RFC 9068 claim set.
type claims struct {
	Issuer   string
	Subject  string
	ClientID string
	JTI      string
	Scope    string
	JKT      string
	IssuedAt time.Time
	Expires  time.Time
}

var errInvalidToken = errors.New("token: invalid access token")

// resolve verifies the token's signature and typ (via the injected verifier)
// and validates the RFC 9068 claims against this service's issuer and clock. It
// returns the claims and the persisted token metadata is left to the caller,
// which decides whether an inactive/absent record means "inactive" (introspect)
// or "invalid" (verify).
func (s *Service) resolve(ctx context.Context, token string) (claims, error) {
	if token == "" {
		return claims{}, errInvalidToken
	}
	m, err := s.verifier.Verify(ctx, token)
	if err != nil {
		return claims{}, errInvalidToken
	}

	c := claims{}
	// iss must equal this server's issuer.
	if iss, _ := m["iss"].(string); iss != s.issuer {
		return claims{}, errInvalidToken
	}
	c.Issuer = s.issuer

	sub, _ := m["sub"].(string)
	if sub == "" {
		return claims{}, errInvalidToken
	}
	c.Subject = sub

	cid, _ := m["client_id"].(string)
	if cid == "" {
		return claims{}, errInvalidToken
	}
	c.ClientID = cid

	jti, _ := m["jti"].(string)
	if jti == "" {
		return claims{}, errInvalidToken
	}
	c.JTI = jti

	c.Scope, _ = m["scope"].(string)

	// Sender constraint. A cnf this server did not mint (anything but a
	// non-empty jkt) is refused rather than read as "unbound": treating an
	// unknown confirmation method as absent would downgrade it to a bearer.
	if raw, present := m["cnf"]; present {
		cnf, _ := raw.(map[string]any)
		jkt, _ := cnf["jkt"].(string)
		if jkt == "" {
			return claims{}, errInvalidToken
		}
		c.JKT = jkt
	}

	iat, ok := numClaim(m["iat"])
	if !ok {
		return claims{}, errInvalidToken
	}
	c.IssuedAt = time.Unix(iat, 0)

	exp, ok := numClaim(m["exp"])
	if !ok {
		return claims{}, errInvalidToken
	}
	c.Expires = time.Unix(exp, 0)

	// Expiry is strict: a token valid exactly until now is already expired.
	if !s.clock.Now().Before(c.Expires) {
		return claims{}, errInvalidToken
	}

	// The kid claim, when present, must match the active key. (The signature
	// was already checked against the correct key by the verifier.)
	if kid, ok := m["kid"].(string); ok && s.keys != nil && kid != s.keys.KeyID() {
		return claims{}, errInvalidToken
	}

	return c, nil
}

// numClaim reads an integer-valued JWT numeric claim (JSON numbers decode as
// float64 through the verifier).
func numClaim(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f < 0 {
		return 0, false
	}
	return int64(f), true
}

// VerifyAccessToken validates a presented bearer token and returns its
// identity. Any failure (bad signature, wrong typ/issuer, expired, revoked, or
// unknown) is an error; the HTTP layer maps it to invalid_token (RFC 6750).
func (s *Service) VerifyAccessToken(ctx context.Context, token string) (VerifiedToken, error) {
	c, err := s.resolve(ctx, token)
	if err != nil {
		return VerifiedToken{}, oauth.InvalidToken("the access token is invalid, expired or revoked")
	}
	rec, err := s.store.AccessTokens().GetByJTI(ctx, c.JTI)
	if err != nil || !rec.RevokedAt.IsZero() {
		return VerifiedToken{}, oauth.InvalidToken("the access token is invalid, expired or revoked")
	}
	return VerifiedToken{
		ClientID: c.ClientID,
		Subject:  c.Subject,
		Scope:    c.Scope,
		JTI:      c.JTI,
		JKT:      c.JKT,
	}, nil
}

// Introspect reports the RFC 7662 state of a token. It never fails on an
// unknown, expired, revoked or malformed token: those are all "inactive"
// (active=false), per RFC 7662 §2.2. A storage error still surfaces.
func (s *Service) Introspect(ctx context.Context, token string) (TokenInfo, error) {
	inactive := TokenInfo{Active: false}

	c, err := s.resolve(ctx, token)
	if err != nil {
		return inactive, nil
	}
	rec, err := s.store.AccessTokens().GetByJTI(ctx, c.JTI)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return inactive, nil
	case err != nil:
		return inactive, oauth.ServerError(err)
	}

	active := rec.RevokedAt.IsZero() && s.clock.Now().Before(rec.ExpiresAt)
	if !active {
		return inactive, nil
	}

	tokenType := TokenTypeName
	if c.JKT != "" {
		tokenType = TokenTypeDPoP
	}
	return TokenInfo{
		Active:    true,
		Scope:     rec.Scope,
		ClientID:  rec.ClientID,
		Username:  rec.UserID,
		Sub:       rec.UserID,
		TokenType: tokenType,
		JKT:       c.JKT,
		JTI:       rec.JTI,
		Issuer:    s.issuer,
		ExpiresAt: rec.ExpiresAt.Unix(),
		IssuedAt:  rec.IssuedAt.Unix(),
	}, nil
}

// Revoke revokes a token on behalf of clientID (RFC 7009). The token may be an
// access token (a signed JWT resolved by its jti) or a refresh token (an opaque
// value looked up by its SHA-256 hash, then revoking its whole rotation family).
// tokenTypeHint is only a hint (RFC 7009 §2.1): the caller still searches the
// token by both shapes, so a mismatched hint never hides a token that exists in
// the other family. Owner binding: only the client that holds the token may
// revoke it. A wrong owner, an unknown token, or a malformed token is not an
// error and not a revoke — the endpoint still answers 200 (RFC 7009 §2.1
// forbids leaking whether the token belonged to another client).
func (s *Service) Revoke(ctx context.Context, tokenValue, clientID, tokenTypeHint string) error {
	// Refresh-token path: opaque value looked up by hash, revoking its family.
	// A refresh token is never a JWT, so this lookup is tried for every value
	// regardless of the hint (a wrong access_token hint must still find it).
	if rec, err := s.store.RefreshTokens().GetByHash(ctx, hashRefresh(tokenValue)); err == nil {
		if clientID != "" && rec.ClientID == clientID {
			_, rerr := s.store.RefreshTokens().RevokeFamily(ctx, rec.FamilyID, s.clock.Now())
			if rerr != nil {
				return oauth.ServerError(rerr)
			}
		}
		// Unknown family is not an error; wrong owner is not an error and not a
		// revoke. Either way the endpoint answers 200 without leaking existence.
		return nil
	} else if !errors.Is(err, oauth.ErrNotFound) {
		return oauth.ServerError(err)
	}

	// Access-token path: resolve the JWT and revoke by jti.
	c, err := s.resolve(ctx, tokenValue)
	if err != nil {
		return nil
	}
	if clientID == "" || c.ClientID != clientID {
		return nil
	}
	_, err = s.store.AccessTokens().Revoke(ctx, c.JTI, s.clock.Now())
	if errors.Is(err, oauth.ErrNotFound) {
		return nil
	}
	if err != nil {
		return oauth.ServerError(err)
	}
	return nil
}

// hashRefresh is the SHA-256 (hex) of a refresh-token value, matching the hash
// the issuing flow (authcode.mintRefreshToken) persists, so a presented value
// resolves to its stored record.
func hashRefresh(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// RotateRefresh rotates a refresh token within a known family. On replay
// (ErrAlreadyConsumed) it revokes the whole family — the replay detector this
// service gates — and returns ErrAlreadyConsumed so the caller still refuses the
// grant. Other storage errors are surfaced directly.
func (s *Service) RotateRefresh(ctx context.Context, tokenHash, familyID string) (oauth.RefreshToken, error) {
	t, err := s.store.RefreshTokens().Rotate(ctx, tokenHash, s.clock.Now())
	if errors.Is(err, oauth.ErrAlreadyConsumed) {
		if familyID != "" {
			_, _ = s.store.RefreshTokens().RevokeFamily(ctx, familyID, s.clock.Now())
		}
		return oauth.RefreshToken{}, err
	}
	if err != nil {
		return oauth.RefreshToken{}, oauth.ServerError(err)
	}
	return t, nil
}

// JWKS returns the published public signing keys as raw JSON (RFC 7517),
// for the discovery endpoint (RFC 8414).
func (s *Service) JWKS() (json.RawMessage, error) {
	if s.keys == nil {
		return nil, fmt.Errorf("token: no key set configured")
	}
	return s.keys.PublicJWKS()
}

// IDTokenParams names the subject, audience client and nonce of an id_token.
type IDTokenParams struct {
	ClientID string
	Subject  string
	Nonce    string // echoed verbatim when non-empty (OIDC Core 3.1.3.6)
}

// IssueIDToken signs an OIDC Core 2 id_token: iss, sub, aud, iat, exp and,
// when the authorization request carried one, the nonce.
func (s *Service) IssueIDToken(ctx context.Context, p IDTokenParams) (string, error) {
	if s.idSigner == nil {
		return "", oauth.ServerError(errors.New("token: id_token signer not configured"))
	}
	if p.ClientID == "" || p.Subject == "" {
		return "", oauth.InvalidRequest("client and subject are required")
	}
	now := s.clock.Now()
	claims := map[string]any{
		"iss": s.issuer,
		"sub": p.Subject,
		"aud": p.ClientID,
		"iat": now.Unix(),
		"exp": now.Add(s.ttl).Unix(),
	}
	if p.Nonce != "" {
		claims["nonce"] = p.Nonce
	}
	idt, err := s.idSigner.Sign(ctx, claims)
	if err != nil {
		return "", oauth.ServerError(err)
	}
	return idt, nil
}

// VerifyIDTokenHint validates the signature of an id_token_hint and returns
// its claims. Expiry is deliberately not enforced (RP-Initiated Logout 2).
func (s *Service) VerifyIDTokenHint(ctx context.Context, idt string) (map[string]any, error) {
	if s.idVer == nil {
		return nil, oauth.ServerError(errors.New("token: id_token verifier not configured"))
	}
	claims, err := s.idVer.Verify(ctx, idt)
	if err != nil {
		return nil, oauth.InvalidRequest("id_token_hint is invalid")
	}
	if iss, _ := claims["iss"].(string); iss != s.issuer {
		return nil, oauth.InvalidRequest("id_token_hint issuer mismatch")
	}
	return claims, nil
}
