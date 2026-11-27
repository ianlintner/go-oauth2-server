package oauth

import "context"

type dpopKeyCtx struct{}

// WithDPoPKey returns ctx carrying the RFC 7638 thumbprint (jkt) of a DPoP
// proof key the token endpoint has already verified for this request. Token
// issuance binds the access token it mints to that key. The value must only
// ever be set by the HTTP layer after dpop.Verifier.Check succeeded.
func WithDPoPKey(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, dpopKeyCtx{}, jkt)
}

// DPoPKey returns the verified proof-key thumbprint carried by ctx, or "" when
// the request was not DPoP-protected.
func DPoPKey(ctx context.Context) string {
	jkt, _ := ctx.Value(dpopKeyCtx{}).(string)
	return jkt
}

type dpopRecorderCtx struct{}

// WithDPoPRecorder returns ctx carrying the step that records a verified DPoP
// proof in the replay store. The token service runs it once the client has
// authenticated, so a caller that has not proved who it is cannot consume
// replay capacity. The function returns the protocol error to answer with.
func WithDPoPRecorder(ctx context.Context, record func() error) context.Context {
	return context.WithValue(ctx, dpopRecorderCtx{}, record)
}

// RecordDPoPProof runs the recorder carried by ctx, if any. A context without
// one (no DPoP proof on the request) records nothing and returns nil.
func RecordDPoPProof(ctx context.Context) error {
	if record, _ := ctx.Value(dpopRecorderCtx{}).(func() error); record != nil {
		return record()
	}
	return nil
}
