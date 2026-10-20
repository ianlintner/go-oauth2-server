package authcode

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// Pushed authorization requests (RFC 9126). The request_uri lifetime is a new
// security parameter proposed for owner review (docs/extended-grants.md).
const (
	// RequestURIPrefix is the RFC 9126 §2.2 request_uri scheme.
	RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

	DefaultPushedRequestTTL = 60 * time.Second
)

// PushedResponse is the RFC 9126 §2.2 response.
type PushedResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// PushAuthorizationRequest validates and stores a pushed authorization
// request. The client authenticates as at the token endpoint. The pushed
// parameters are validated exactly like a front-channel request, so nothing
// that /oauth/authorize would refuse can be stored.
func (s *Service) PushAuthorizationRequest(ctx context.Context, authorization string, p oauth.Params) (PushedResponse, error) {
	// RFC 9126 §2.1: request_uri MUST NOT be pushed; request objects are not
	// supported (ValidateRequest also refuses them).
	if p.Has("request_uri") {
		return PushedResponse{}, oauth.InvalidRequest("request_uri must not be included in a pushed request")
	}
	if authorization == "" && !p.Has("client_id") {
		return PushedResponse{}, oauth.InvalidRequest("client_id is required")
	}
	client, err := s.authenticateClient(ctx, authorization, p)
	if err != nil {
		return PushedResponse{}, err
	}
	uri := p.Get("redirect_uri")
	if uri == "" {
		return PushedResponse{}, oauth.InvalidRequest("redirect_uri is required")
	}
	if !oauth.MatchRedirectURI(client.RedirectURIs, uri, s.insecure) {
		return PushedResponse{}, oauth.InvalidRequest("redirect_uri does not match a registered URI")
	}
	req, err := s.ValidateRequest(client, uri, p)
	if err != nil {
		return PushedResponse{}, err
	}

	raw, err := s.rnd.Bytes(codeBytes)
	if err != nil {
		return PushedResponse{}, oauth.ServerError(err)
	}
	reqURI := RequestURIPrefix + base64.RawURLEncoding.EncodeToString(raw)
	rec := oauth.PushedRequest{
		URIHash:       hashCode(reqURI),
		ClientID:      client.ID,
		RedirectURI:   req.RedirectURI,
		Scope:         req.Scope,
		State:         req.State,
		CodeChallenge: req.CodeChallenge,
		Nonce:         req.Nonce,
		ExpiresAt:     s.clock.Now().Add(DefaultPushedRequestTTL),
	}
	if err := s.store.PushedRequests().Create(ctx, rec); err != nil {
		return PushedResponse{}, oauth.ServerError(err)
	}
	return PushedResponse{RequestURI: reqURI, ExpiresIn: int64(DefaultPushedRequestTTL / time.Second)}, nil
}

// CheckPushed validates a request_uri presented at the authorization endpoint
// without spending it, so an unauthenticated browser can be sent to log in
// first. Every failure is a non-redirectable invalid_request_uri: the pushed
// redirect URI is not trusted until the request is proven to belong to the
// presenting client.
func (s *Service) CheckPushed(ctx context.Context, clientID, requestURI string) error {
	_, err := s.loadPushed(ctx, clientID, requestURI)
	return err
}

func (s *Service) loadPushed(ctx context.Context, clientID, requestURI string) (oauth.PushedRequest, error) {
	bad := func() (oauth.PushedRequest, error) {
		return oauth.PushedRequest{}, oauth.InvalidRequestURI("request_uri is invalid, expired or already used")
	}
	if clientID == "" {
		return oauth.PushedRequest{}, oauth.InvalidRequest("client_id is required")
	}
	if !strings.HasPrefix(requestURI, RequestURIPrefix) {
		return bad()
	}
	rec, err := s.store.PushedRequests().GetByHash(ctx, hashCode(requestURI))
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return bad()
	case err != nil:
		return oauth.PushedRequest{}, oauth.ServerError(err)
	}
	// Client binding: a request_uri is only usable by the client that pushed it.
	if rec.ClientID != clientID || !s.clock.Now().Before(rec.ExpiresAt) {
		return bad()
	}
	return rec, nil
}

// RedeemPushed atomically spends a pushed request and returns the validated
// authorization request it carries. The client binding, expiry and redirect
// URI registration are re-checked at spend time.
func (s *Service) RedeemPushed(ctx context.Context, clientID, requestURI string) (AuthRequest, error) {
	if _, err := s.loadPushed(ctx, clientID, requestURI); err != nil {
		return AuthRequest{}, err
	}
	now := s.clock.Now()
	rec, err := s.store.PushedRequests().Consume(ctx, hashCode(requestURI), now)
	switch {
	case errors.Is(err, oauth.ErrNotFound), errors.Is(err, oauth.ErrAlreadyConsumed):
		return AuthRequest{}, oauth.InvalidRequestURI("request_uri is invalid, expired or already used")
	case err != nil:
		return AuthRequest{}, oauth.ServerError(err)
	}
	if rec.ClientID != clientID || !now.Before(rec.ExpiresAt) {
		return AuthRequest{}, oauth.InvalidRequestURI("request_uri is invalid, expired or already used")
	}
	client, err := s.store.Clients().Get(ctx, rec.ClientID)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return AuthRequest{}, oauth.InvalidRequestURI("request_uri is invalid, expired or already used")
	case err != nil:
		return AuthRequest{}, oauth.ServerError(err)
	}
	if !oauth.MatchRedirectURI(client.RedirectURIs, rec.RedirectURI, s.insecure) {
		return AuthRequest{}, oauth.InvalidRequestURI("request_uri is invalid, expired or already used")
	}
	return AuthRequest{
		Client: client, RedirectURI: rec.RedirectURI, State: rec.State,
		Scope: rec.Scope, CodeChallenge: rec.CodeChallenge, Nonce: rec.Nonce,
	}, nil
}
