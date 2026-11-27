package authcode

import (
	"context"
	"errors"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// CheckUserScope verifies that the resource owner may grant every scope in
// scope. A user record with no scopes configured places no per-user
// restriction (only the client's registered scopes apply); a user with scopes
// may grant only those, and anything else is invalid_scope rather than being
// silently dropped.
func (s *Service) CheckUserScope(u oauth.User, scope string) error {
	if len(u.Scopes) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(u.Scopes))
	for _, sc := range u.Scopes {
		allowed[sc] = true
	}
	for _, tok := range strings.Fields(scope) {
		if !allowed[tok] {
			return oauth.InvalidScope("scope is not permitted for this user")
		}
	}
	return nil
}

// Approved reports whether a stored approval of the client by the user
// covers scope. Only an explicit row approves: a missing row is never
// treated as consent.
func (s *Service) Approved(ctx context.Context, userID, clientID, scope string) (bool, error) {
	a, err := s.store.Approvals().Get(ctx, userID, clientID)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return false, nil
	case err != nil:
		return false, oauth.ServerError(err)
	}
	return a.Covers(scope), nil
}

// RecordApproval stores the resource owner's approval of the client for
// exactly scope, replacing any earlier row for the pair. The caller must have
// obtained the approval through an authenticated, anti-forgery-protected
// request.
func (s *Service) RecordApproval(ctx context.Context, userID, clientID, scope string) error {
	err := s.store.Approvals().Put(ctx, oauth.Approval{
		UserID: userID, ClientID: clientID, Scopes: strings.Fields(scope), GrantedAt: s.clock.Now(),
	})
	if err != nil {
		return oauth.ServerError(err)
	}
	return nil
}
