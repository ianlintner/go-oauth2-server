package oauth

import "context"

type dpopKeyCtx struct{}

// WithDPoPKey returns ctx carrying the RFC 7638 thumbprint (jkt) of a DPoP
// proof key the token endpoint has already verified for this request. Token
// issuance binds the access token it mints to that key. The value must only
// ever be set by the HTTP layer after dpop.Verifier.Verify succeeded.
func WithDPoPKey(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, dpopKeyCtx{}, jkt)
}

// DPoPKey returns the verified proof-key thumbprint carried by ctx, or "" when
// the request was not DPoP-protected.
func DPoPKey(ctx context.Context) string {
	jkt, _ := ctx.Value(dpopKeyCtx{}).(string)
	return jkt
}
