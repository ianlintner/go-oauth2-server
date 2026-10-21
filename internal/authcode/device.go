package authcode

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// Device grant (RFC 8628) policy. These are new security parameters proposed
// for owner review (see docs/extended-grants.md).
const (
	// GrantDeviceCode is the RFC 8628 §3.4 grant type.
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	DefaultDeviceCodeTTL  = 10 * time.Minute
	DefaultDeviceInterval = 5  // seconds, RFC 8628 §3.2 default
	slowDownStep          = 5  // seconds added on slow_down, RFC 8628 §3.5
	maxDeviceInterval     = 60 // seconds; caps slow_down growth to bound pollback

	// userCodeAlphabet omits vowels and look-alike characters (RFC 8628 §6.1):
	// 20 symbols, 8 characters, ~34.6 bits, shown as XXXX-XXXX.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen      = 8

	// A signed-in user may fail at most maxUserCodeFailures user-code entries
	// per userCodeFailureWindow before further attempts are refused (RFC 8628
	// §5.2 brute-force mitigation).
	maxUserCodeFailures   = 5
	userCodeFailureWindow = 5 * time.Minute
)

// DeviceAuthorization is the RFC 8628 §3.2 response.
type DeviceAuthorization struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// failureLimiter counts recent failed user-code entries per signed-in user.
type failureLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

// reserve atomically reserves a failure slot for key, returning false (with
// the entry already counted) when the user is over the window limit. This is
// one check-and-record so concurrent guesses against the same session cannot
// each observe an under-limit count before any is recorded.
func (l *failureLimiter) reserve(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string][]time.Time{}
	}
	cutoff := now.Add(-userCodeFailureWindow)
	kept := l.m[key][:0]
	for _, t := range l.m[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxUserCodeFailures {
		l.m[key] = kept
		return false
	}
	l.m[key] = append(kept, now)
	return true
}

// release gives back one reserved slot after a successful decision, so only
// failed entries count against the limit.
func (l *failureLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := len(l.m[key]); n > 0 {
		l.m[key] = l.m[key][:n-1]
		if n == 1 {
			delete(l.m, key)
		}
	}
}

// AuthorizeDevice handles the device authorization request (RFC 8628 §3.1).
// The client authenticates exactly as at the token endpoint; a public client
// is identified by client_id alone. verificationURI is the absolute URL of
// the user-facing verification page.
func (s *Service) AuthorizeDevice(ctx context.Context, authorization string, p oauth.Params, verificationURI string) (DeviceAuthorization, error) {
	if authorization == "" && !p.Has("client_id") {
		return DeviceAuthorization{}, oauth.InvalidRequest("client_id is required")
	}
	client, err := s.authenticateClient(ctx, authorization, p)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if !grantAllowed(client, GrantDeviceCode) {
		return DeviceAuthorization{}, oauth.UnauthorizedClient("client may not use the device authorization grant")
	}
	scope, err := validateScope(client, p.Get("scope"))
	if err != nil {
		return DeviceAuthorization{}, err
	}

	for attempt := 0; attempt < 3; attempt++ {
		raw, err := s.rnd.Bytes(codeBytes)
		if err != nil {
			return DeviceAuthorization{}, oauth.ServerError(err)
		}
		deviceCode := base64.RawURLEncoding.EncodeToString(raw)
		userCode, err := s.newUserCode()
		if err != nil {
			return DeviceAuthorization{}, err
		}
		rec := oauth.DeviceCode{
			DeviceCodeHash: hashCode(deviceCode),
			UserCodeHash:   hashCode(userCode),
			ClientID:       client.ID,
			Scope:          scope,
			Status:         oauth.DevicePending,
			ExpiresAt:      s.clock.Now().Add(DefaultDeviceCodeTTL),
			Interval:       DefaultDeviceInterval,
		}
		switch err := s.store.DeviceCodes().Create(ctx, rec); {
		case err == nil:
			return DeviceAuthorization{
				DeviceCode:      deviceCode,
				UserCode:        userCode[:4] + "-" + userCode[4:],
				VerificationURI: verificationURI,
				ExpiresIn:       int64(DefaultDeviceCodeTTL / time.Second),
				Interval:        DefaultDeviceInterval,
			}, nil
		case errors.Is(err, oauth.ErrConflict):
			continue // user-code collision: draw another
		default:
			return DeviceAuthorization{}, oauth.ServerError(err)
		}
	}
	return DeviceAuthorization{}, oauth.ServerError(errors.New("authcode: could not allocate a unique user code"))
}

// newUserCode draws userCodeLen symbols uniformly (rejection sampling avoids
// modulo bias).
func (s *Service) newUserCode() (string, error) {
	var b strings.Builder
	limit := byte(256 - 256%len(userCodeAlphabet))
	for b.Len() < userCodeLen {
		raw, err := s.rnd.Bytes(16)
		if err != nil {
			return "", oauth.ServerError(err)
		}
		for _, c := range raw {
			if c >= limit {
				continue
			}
			b.WriteByte(userCodeAlphabet[int(c)%len(userCodeAlphabet)])
			if b.Len() == userCodeLen {
				break
			}
		}
	}
	return b.String(), nil
}

// normalizeUserCode canonicalizes what a person typed (case, dash, spaces).
// ok is false when the result cannot be a user code.
func normalizeUserCode(in string) (string, bool) {
	in = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(in))
	if len(in) != userCodeLen {
		return "", false
	}
	for i := 0; i < len(in); i++ {
		if strings.IndexByte(userCodeAlphabet, in[i]) < 0 {
			return "", false
		}
	}
	return in, true
}

// DecideDevice records the signed-in user's decision on the authorization
// identified by userCode. Failed entries count against the user's limit; the
// count is reserved up front (check-and-record) so concurrent guesses cannot
// overshoot the cap.
func (s *Service) DecideDevice(ctx context.Context, user oauth.User, userCode string, approve bool) error {
	now := s.clock.Now()
	if !s.failures.reserve(user.ID, now) {
		// Over the per-user failure window: refuse everything, even a correct
		// code, until the window expires.
		return oauth.InvalidRequest("too many failed attempts; try again later").WithStatus(429)
	}
	bad := func() error {
		return oauth.InvalidRequest("the code is unknown, expired or already used")
	}
	norm, ok := normalizeUserCode(userCode)
	if !ok {
		return bad()
	}
	status := oauth.DeviceDenied
	if approve {
		status = oauth.DeviceApproved
	}
	rec, err := s.store.DeviceCodes().Decide(ctx, hashCode(norm), status, user.ID)
	switch {
	case errors.Is(err, oauth.ErrNotFound), errors.Is(err, oauth.ErrAlreadyConsumed):
		return bad()
	case err != nil:
		return oauth.ServerError(err)
	}
	if !now.Before(rec.ExpiresAt) {
		return bad()
	}
	s.failures.release(user.ID) // success: only failures count against the cap
	return nil
}

// deviceToken redeems a device_code (RFC 8628 §3.4-3.5).
func (s *Service) deviceToken(ctx context.Context, client oauth.Client, p oauth.Params) (TokenResponse, error) {
	code := p.Get("device_code")
	if code == "" {
		return TokenResponse{}, oauth.InvalidRequest("device_code is required")
	}
	hash := hashCode(code)
	now := s.clock.Now()
	repo := s.store.DeviceCodes()

	rec, err := repo.GetByHash(ctx, hash)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return TokenResponse{}, oauth.InvalidGrant("device code is invalid")
	case err != nil:
		return TokenResponse{}, oauth.ServerError(err)
	}
	if rec.ClientID != client.ID {
		return TokenResponse{}, oauth.InvalidGrant("device code was not issued to this client")
	}
	if !now.Before(rec.ExpiresAt) {
		return TokenResponse{}, oauth.ExpiredToken()
	}

	// Terminal states answer before any rate limiting: a spent code is simply
	// invalid, and a denied one is access_denied, however fast it is polled.
	if rec.Consumed {
		return TokenResponse{}, oauth.InvalidGrant("device code is invalid or already used")
	}
	switch rec.Status {
	case oauth.DeviceDenied:
		// RFC 8628 §3.5 / RFC 6749 §5.2: access_denied is a 400 error.
		return TokenResponse{}, oauth.AccessDenied("the user denied the authorization").WithStatus(400)
	case oauth.DeviceApproved:
		// Approved and about to be consumed below.
	default:
		// Pending stays pending; fall through to the poll-rate check.
	}

	// Too-fast polling is rejected before the decision is revealed, and the
	// client's interval grows so a misbehaving poller cannot ride the limit.
	if !rec.LastPoll.IsZero() && now.Sub(rec.LastPoll) < time.Duration(rec.Interval)*time.Second {
		if err := repo.RecordPoll(ctx, hash, now, minInt(rec.Interval+slowDownStep, maxDeviceInterval)); err != nil {
			return TokenResponse{}, oauth.ServerError(err)
		}
		return TokenResponse{}, oauth.SlowDown()
	}
	if err := repo.RecordPoll(ctx, hash, now, rec.Interval); err != nil {
		return TokenResponse{}, oauth.ServerError(err)
	}

	if rec.Status == oauth.DevicePending {
		return TokenResponse{}, oauth.AuthorizationPending()
	}

	if _, err := repo.Consume(ctx, hash, now); err != nil {
		if errors.Is(err, oauth.ErrAlreadyConsumed) || errors.Is(err, oauth.ErrNotFound) {
			return TokenResponse{}, oauth.InvalidGrant("device code is invalid or already used")
		}
		return TokenResponse{}, oauth.ServerError(err)
	}
	return s.issueTokens(ctx, client.ID, rec.UserID, rec.Scope, grantAllowed(client, GrantRefreshToken), "")
}
