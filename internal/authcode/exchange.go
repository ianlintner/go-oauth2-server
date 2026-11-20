package authcode

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// RFC 8693 token exchange.
const (
	// GrantTokenExchange is the RFC 8693 §2.1 grant type.
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- public RFC 8693 URN, not a credential

	// TokenTypeAccessToken and TokenTypeJWT are the RFC 8693 §3 token-type
	// identifiers this server accepts as subject/actor token types and
	// issues. Every access token is a JWT, so both name the same artifact.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- public RFC 8693 URN, not a credential
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          // #nosec G101 -- public RFC 8693 URN, not a credential

	// DefaultMaxDelegationDepth is the deepest act chain an exchange may
	// mint, matching the reference implementation's default.
	DefaultMaxDelegationDepth = 4
)

func supportedTokenType(t string) bool {
	return t == TokenTypeAccessToken || t == TokenTypeJWT
}

// tokenExchange handles grant_type=urn:ietf:params:oauth:grant-type:token-exchange
// (RFC 8693). A subject_token (and optional actor_token) are validated and
// reduced to a new access token that is only ever narrowed — never widened —
// in scope and audience. Delegation is recorded in the "act" claim only when
// the client the subject token was issued to has registered the caller as an
// allowed actor; the chain is depth-limited.
//
// Only this server's own access tokens (signed at+jwt, persisted, unrevoked)
// are accepted as subject or actor tokens: refresh tokens, ID tokens and
// foreign assertions are refused, so the grant cannot turn a long-lived
// credential or an unvalidated assertion into a fresh access token.
func (s *Service) tokenExchange(ctx context.Context, client oauth.Client, p oauth.Params) (TokenResponse, error) {
	if s.tokens == nil {
		return TokenResponse{}, oauth.ServerError(errors.New("authcode: token exchange requires the token service"))
	}
	if client.Public {
		return TokenResponse{}, oauth.InvalidClient("public clients cannot use token exchange", false)
	}

	// Request parameters (RFC 8693 §2.1).
	subjectRaw := p.Get("subject_token")
	if subjectRaw == "" {
		return TokenResponse{}, oauth.InvalidRequest("subject_token is required")
	}
	subjectType := p.Get("subject_token_type")
	if subjectType == "" {
		return TokenResponse{}, oauth.InvalidRequest("subject_token_type is required")
	}
	if !supportedTokenType(subjectType) {
		return TokenResponse{}, oauth.InvalidRequest("unsupported subject_token_type")
	}
	var actorRaw string
	if p.Has("actor_token") {
		actorRaw = p.Get("actor_token")
		if actorRaw == "" {
			return TokenResponse{}, oauth.InvalidRequest("actor_token must not be empty")
		}
		actorType := p.Get("actor_token_type")
		if actorType == "" {
			return TokenResponse{}, oauth.InvalidRequest("actor_token_type is required with actor_token")
		}
		if !supportedTokenType(actorType) {
			return TokenResponse{}, oauth.InvalidRequest("unsupported actor_token_type")
		}
	} else if p.Has("actor_token_type") {
		return TokenResponse{}, oauth.InvalidRequest("actor_token_type requires actor_token")
	}
	requestedType := p.Get("requested_token_type")
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	if !supportedTokenType(requestedType) {
		return TokenResponse{}, oauth.InvalidRequest("unsupported requested_token_type")
	}
	if p.Has("authorization_details") {
		return TokenResponse{}, oauth.InvalidRequest("authorization_details is not supported")
	}

	// Resolve the artifacts.
	subject, err := s.resolveExchangeToken(ctx, "subject", subjectRaw)
	if err != nil {
		return TokenResponse{}, err
	}
	var actor *token.VerifiedToken
	if actorRaw != "" {
		a, err := s.resolveExchangeToken(ctx, "actor", actorRaw)
		if err != nil {
			return TokenResponse{}, err
		}
		if a.ClientID != client.ID {
			return TokenResponse{}, oauth.InvalidGrant("actor token was not issued to this client")
		}
		actor = &a
	}

	// Delegation policy: the client the subject token was issued to must have
	// registered the caller. This covers both the actor-token case and a plain
	// cross-client exchange (otherwise any client could launder another
	// client's token into one of its own). A same-client exchange without an
	// actor token is the ordinary narrowing case and needs no consent.
	if actor != nil || subject.ClientID != client.ID {
		if err := s.authorizeExchange(ctx, subject, client); err != nil {
			return TokenResponse{}, err
		}
	}

	// act chain.
	act := subject.Act
	if actor != nil {
		existing, ok := token.ActDepth(subject.Act)
		if !ok {
			return TokenResponse{}, oauth.InvalidGrant("subject_token carries a malformed act claim")
		}
		if existing+1 > s.maxDelegationDepth {
			return TokenResponse{}, oauth.InvalidRequest("delegation chain exceeds the maximum depth")
		}
		level := map[string]any{"sub": actor.Subject, "iss": s.tokens.Issuer()}
		if subject.Act != nil {
			level["act"] = subject.Act
		}
		act = level
	}

	// Scope: a subset of the subject token's, and of the caller's own
	// registration (as client_credentials enforces).
	scope := subject.Scope
	if p.Has("scope") {
		if scope, err = narrowScope(subject.Scope, p.Get("scope")); err != nil {
			return TokenResponse{}, err
		}
	}
	if scope, err = validateScope(client, scope); err != nil {
		return TokenResponse{}, err
	}

	audience, err := s.exchangeAudience(client, subject, p)
	if err != nil {
		return TokenResponse{}, err
	}

	// A sender-constrained subject was already matched to the presented
	// proof; the new token is bound to whatever proof accompanies this
	// request, so a bound subject never becomes a bearer.
	at, err := s.tokens.Issue(ctx, token.IssueParams{
		ClientID: client.ID,
		Subject:  subject.Subject,
		Scope:    scope,
		Audience: audience,
		JKT:      oauth.DPoPKey(ctx),
		Act:      act,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken:     at.Value,
		TokenType:       at.TokenType,
		ExpiresIn:       int64(at.ExpiresAt.Sub(at.IssuedAt) / time.Second),
		Scope:           scope,
		IssuedTokenType: requestedType,
	}, nil
}

// resolveExchangeToken validates a subject or actor token: a live,
// unrevoked access token issued by this server. A sender-constrained token is
// accepted only together with a proof from the key it is bound to
// (RFC 8693 §2.1 with RFC 9449 §7): otherwise the exchange would downgrade it
// to a bearer credential.
func (s *Service) resolveExchangeToken(ctx context.Context, which, raw string) (token.VerifiedToken, error) {
	t, err := s.tokens.VerifyAccessToken(ctx, raw)
	if err != nil {
		return token.VerifiedToken{}, oauth.InvalidGrant(which + "_token is invalid, expired or revoked")
	}
	if t.JKT != "" && subtle.ConstantTimeCompare([]byte(t.JKT), []byte(oauth.DPoPKey(ctx))) != 1 {
		return token.VerifiedToken{}, oauth.InvalidGrant(which + "_token is sender-constrained; a matching DPoP proof is required")
	}
	return t, nil
}

// authorizeExchange requires that the client the subject token was issued to
// lists the caller in its allowed actors.
func (s *Service) authorizeExchange(ctx context.Context, subject token.VerifiedToken, caller oauth.Client) error {
	issuing, err := s.store.Clients().Get(ctx, subject.ClientID)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return oauth.InvalidGrant("subject_token is not bound to a known client")
	case err != nil:
		return oauth.ServerError(err)
	}
	if !issuing.AllowsActor(caller.ID) {
		return oauth.InvalidGrant("client is not authorized to act for or exchange tokens issued to another client")
	}
	return nil
}

// exchangeAudience resolves the audience of the new token. The request's
// resource (RFC 8707) and audience (RFC 8693 §2.1) values are merged; each
// must be an absolute URI the caller may target, and none may exceed the
// subject token's own audience. With neither, the subject's audience is
// inherited.
func (s *Service) exchangeAudience(client oauth.Client, subject token.VerifiedToken, p oauth.Params) ([]string, error) {
	var requested []string
	for _, v := range []string{p.Get("resource"), p.Get("audience")} {
		if v == "" || containsString(requested, v) {
			continue
		}
		requested = append(requested, v)
	}
	if len(requested) == 0 {
		// An inherited audience is still a target: the exchanging client's
		// own registration must permit every one of them.
		inherited := append([]string(nil), subject.Audience...)
		for _, v := range inherited {
			if _, err := s.validateResource(client, v); err != nil {
				return nil, err
			}
		}
		return inherited, nil
	}
	for _, v := range requested {
		if _, err := s.validateResource(client, v); err != nil {
			return nil, err
		}
		if !containsString(subject.Audience, v) {
			return nil, oauth.InvalidTarget("requested audience exceeds the subject token's audience")
		}
	}
	return requested, nil
}

func containsString(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
