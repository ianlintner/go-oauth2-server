package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// dpopAlgs is the algs challenge parameter / metadata value (RFC 9449 §5.1,
// §7.1), derived from the verifier's accepted set so they cannot drift.
func dpopAlgs() []string {
	out := make([]string, len(dpop.SigningAlgs))
	for i, a := range dpop.SigningAlgs {
		out[i] = string(a)
	}
	return out
}

// dpopChallenge sets the RFC 9449 §7.1 DPoP challenge for a protected resource.
func dpopChallenge(w http.ResponseWriter, code string) {
	w.Header().Set("WWW-Authenticate", `DPoP error="`+code+`", algs="`+strings.Join(dpopAlgs(), " ")+`"`)
}

// requestURL is the URL a client addressed for r, for htu comparison: the
// configured public issuer origin plus the request path. It is built from
// configuration, never from the Host header or forwarding headers, which a
// client (or a misconfigured proxy) could shape.
func (h *oauthHandlers) requestURL(r *http.Request) string {
	return strings.TrimRight(h.issuer, "/") + r.URL.Path
}

// withTokenEndpointProof verifies the DPoP header of a token request (RFC 9449
// §5) and returns a context carrying the proof key, so issuance binds the
// access token to it. A request without a DPoP header, or a server without a
// verifier, proceeds as an ordinary bearer request. Multiple DPoP headers are
// an error (§4.3 point 1): which one to honor would otherwise be ambiguous.
func (h *oauthHandlers) withTokenEndpointProof(ctx context.Context, r *http.Request) (context.Context, error) {
	proofs := r.Header.Values("DPoP")
	if h.dpop == nil || len(proofs) == 0 {
		return ctx, nil
	}
	if len(proofs) != 1 {
		return ctx, oauth.InvalidDPoPProof()
	}
	jkt, err := h.dpop.Verify(ctx, dpop.Request{Proof: proofs[0], Method: r.Method, URL: h.requestURL(r)})
	if err != nil {
		return ctx, h.proofError(err)
	}
	return oauth.WithDPoPKey(ctx, jkt), nil
}

// proofError maps a verifier failure to the protocol error. A rejected proof
// never reveals which check failed; a full replay store is a transient server
// condition, not the client's fault.
func (h *oauthHandlers) proofError(err error) error {
	switch {
	case errors.Is(err, dpop.ErrInvalidProof):
		return oauth.InvalidDPoPProof()
	case errors.Is(err, dpop.ErrReplayStoreFull):
		h.log.Error("dpop replay store is full; rejecting proof", "error", err)
		return oauth.TemporarilyUnavailable("try again later")
	default:
		return oauth.ServerError(err)
	}
}

// checkResourceProof verifies the DPoP proof presented with a DPoP-bound access
// token at a protected resource and returns the RFC 9449 §7.1 error code to
// answer with, or "" when the request is acceptable.
func (h *oauthHandlers) checkResourceProof(r *http.Request, accessToken, boundJKT string) string {
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return "invalid_dpop_proof"
	}
	jkt, err := h.dpop.Verify(r.Context(), dpop.Request{Proof: proofs[0], Method: r.Method, URL: h.requestURL(r), AccessToken: accessToken})
	switch {
	case errors.Is(err, dpop.ErrInvalidProof):
		return "invalid_dpop_proof"
	case err != nil:
		// Replay store failure: fail closed without exposing the cause.
		h.log.ErrorContext(r.Context(), "dpop verification failed", "error", err)
		return "invalid_dpop_proof"
	}
	// The proof must be made with the key the token is bound to; a valid
	// proof from any other key proves possession of nothing relevant.
	if subtle.ConstantTimeCompare([]byte(jkt), []byte(boundJKT)) != 1 {
		return "invalid_token"
	}
	return ""
}
