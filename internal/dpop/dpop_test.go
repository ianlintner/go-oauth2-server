package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
)

const (
	tokenURL = "https://as.example/oauth/token"
	userURL  = "https://as.example/oauth/userinfo"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

type key struct {
	priv *ecdsa.PrivateKey
}

func newKey(t *testing.T) key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key{priv: k}
}

func (k key) jkt(t *testing.T) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: &k.priv.PublicKey}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// proofSpec describes one proof; zero values give a valid token-endpoint proof.
type proofSpec struct {
	key       *key
	typ       string
	alg       jose.SignatureAlgorithm
	htm, htu  string
	iatOffset time.Duration
	jti       string
	omit      []string
	ath       string
	embedPriv bool
}

func (s proofSpec) sign(t *testing.T, now time.Time, k key) string {
	t.Helper()
	if s.key != nil {
		k = *s.key
	}
	typ := s.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	alg := s.alg
	if alg == "" {
		alg = jose.ES256
	}
	claims := map[string]any{"jti": s.jti, "htm": s.htm, "htu": s.htu, "iat": now.Add(s.iatOffset).Unix()}
	if s.jti == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		claims["jti"] = base64.RawURLEncoding.EncodeToString(b[:])
	}
	if s.htm == "" {
		claims["htm"] = "POST"
	}
	if s.htu == "" {
		claims["htu"] = tokenURL
	}
	if s.ath != "" {
		claims["ath"] = s.ath
	}
	for _, name := range s.omit {
		delete(claims, name)
	}
	pub := jose.JSONWebKey{Key: &k.priv.PublicKey}
	var jwkHeader any = pub
	if s.embedPriv {
		jwkHeader = jose.JSONWebKey{Key: k.priv}
	}
	_ = jwkHeader
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if s.embedPriv {
		opts = opts.WithHeader("jwk", jose.JSONWebKey{Key: k.priv})
	} else {
		opts = opts.WithHeader("jwk", pub)
	}
	signingKey := any(k.priv)
	if alg == jose.HS256 {
		signingKey = []byte("0123456789abcdef0123456789abcdef")
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newVerifier(now time.Time) (*dpop.Verifier, *fixedClock) {
	clk := &fixedClock{t: now}
	return dpop.NewVerifier(dpop.Config{Clock: clk, Replay: dpop.NewMemoryReplayStore(clk, 1000)}), clk
}

func TestValidProofReturnsJKT(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v, _ := newVerifier(now)
	k := newKey(t)
	got, err := v.Verify(context.Background(), dpop.Request{Proof: proofSpec{}.sign(t, now, k), Method: "POST", URL: tokenURL})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != k.jkt(t) {
		t.Fatalf("jkt = %q, want %q", got, k.jkt(t))
	}
}

func TestRejectedProofs(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	k := newKey(t)
	other := newKey(t)
	tok := "access-token-value"
	h := sha256.Sum256([]byte(tok))
	goodATH := base64.RawURLEncoding.EncodeToString(h[:])
	cases := []struct {
		name  string
		spec  proofSpec
		token string
	}{
		{"wrong typ", proofSpec{typ: "JWT"}, ""},
		{"htm mismatch", proofSpec{htm: "GET"}, ""},
		{"htu mismatch", proofSpec{htu: "https://as.example/oauth/other"}, ""},
		{"htu missing", proofSpec{omit: []string{"htu"}}, ""},
		{"htm missing", proofSpec{omit: []string{"htm"}}, ""},
		{"jti missing", proofSpec{omit: []string{"jti"}}, ""},
		{"iat missing", proofSpec{omit: []string{"iat"}}, ""},
		{"iat stale", proofSpec{iatOffset: -10 * time.Minute}, ""},
		{"iat in the future", proofSpec{iatOffset: 10 * time.Minute}, ""},
		{"symmetric alg", proofSpec{alg: jose.HS256}, ""},
		{"private key in jwk", proofSpec{embedPriv: true}, ""},
		{"ath missing at resource", proofSpec{}, tok},
		{"ath mismatch at resource", proofSpec{ath: "bm90LXRoZS1oYXNo"}, tok},
		{"ath present but no token", proofSpec{ath: goodATH}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := newVerifier(now)
			_, err := v.Verify(context.Background(), dpop.Request{Proof: tc.spec.sign(t, now, k), Method: "POST", URL: tokenURL, AccessToken: tc.token})
			if !errors.Is(err, dpop.ErrInvalidProof) {
				t.Fatalf("err = %v, want ErrInvalidProof", err)
			}
		})
	}
	t.Run("signature of another key", func(t *testing.T) {
		v, _ := newVerifier(now)
		// Sign with `other` but advertise k's public key in the header.
		tamper := proofSpec{key: &other}.sign(t, now, k)
		tampered := swapJWK(t, tamper, k)
		_, err := v.Verify(context.Background(), dpop.Request{Proof: tampered, Method: "POST", URL: tokenURL})
		if !errors.Is(err, dpop.ErrInvalidProof) {
			t.Fatalf("err = %v, want ErrInvalidProof", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		v, _ := newVerifier(now)
		for _, p := range []string{"", "a.b", "a.b.c", "not a jwt"} {
			if _, err := v.Verify(context.Background(), dpop.Request{Proof: p, Method: "POST", URL: tokenURL}); !errors.Is(err, dpop.ErrInvalidProof) {
				t.Fatalf("proof %q: err = %v", p, err)
			}
		}
	})
}

func swapJWK(t *testing.T, compact string, k key) string {
	t.Helper()
	parts := splitJWT(t, compact)
	var hdr map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(raw, &hdr)
	pub := jose.JSONWebKey{Key: &k.priv.PublicKey}
	b, _ := pub.MarshalJSON()
	var j map[string]any
	_ = json.Unmarshal(b, &j)
	hdr["jwk"] = j
	nh, _ := json.Marshal(hdr)
	return base64.RawURLEncoding.EncodeToString(nh) + "." + parts[1] + "." + parts[2]
}

func splitJWT(t *testing.T, s string) [3]string {
	t.Helper()
	var out [3]string
	n := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if n < 3 {
				out[n] = s[start:i]
			}
			n++
			start = i + 1
		}
	}
	if n != 3 {
		t.Fatalf("not a compact JWT: %d parts", n)
	}
	return out
}

func TestHTUIgnoresQueryAndFragmentOfRequestURL(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v, _ := newVerifier(now)
	k := newKey(t)
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: proofSpec{}.sign(t, now, k), Method: "POST", URL: tokenURL + "?a=b#frag"}); err != nil {
		t.Fatalf("matching htu with a query on the request URL must verify: %v", err)
	}
	// A proof htu that carries a query does not match: htu is compared exactly
	// after the request URL's own query/fragment are stripped.
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: proofSpec{htu: tokenURL + "?a=b"}.sign(t, now, k), Method: "POST", URL: tokenURL}); !errors.Is(err, dpop.ErrInvalidProof) {
		t.Fatalf("htu with query: err = %v, want ErrInvalidProof", err)
	}
}

func TestAccessTokenHashBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v, _ := newVerifier(now)
	k := newKey(t)
	tok := "access-token-value"
	h := sha256.Sum256([]byte(tok))
	ath := base64.RawURLEncoding.EncodeToString(h[:])
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: proofSpec{htm: "GET", htu: userURL, ath: ath}.sign(t, now, k), Method: "GET", URL: userURL, AccessToken: tok}); err != nil {
		t.Fatalf("correct ath must verify: %v", err)
	}
}

func TestReplayedJTIRejectedPerKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v, _ := newVerifier(now)
	k := newKey(t)
	proof := proofSpec{jti: "fixed-jti"}.sign(t, now, k)
	req := dpop.Request{Proof: proof, Method: "POST", URL: tokenURL}
	if _, err := v.Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), req); !errors.Is(err, dpop.ErrInvalidProof) {
		t.Fatalf("replay: err = %v, want ErrInvalidProof", err)
	}
	// The same jti from a different key is a different proof (RFC 9449 §11.1
	// scopes uniqueness to the key), not a replay.
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: proofSpec{jti: "fixed-jti"}.sign(t, now, newKey(t)), Method: "POST", URL: tokenURL}); err != nil {
		t.Fatalf("same jti, other key: %v", err)
	}
}

func TestRejectedProofDoesNotBurnJTI(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v, _ := newVerifier(now)
	k := newKey(t)
	// Wrong htm first; then the correct request with the same jti must pass,
	// because a proof that failed validation never reaches the replay store.
	bad := proofSpec{jti: "j1", htm: "GET"}.sign(t, now, k)
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: bad, Method: "POST", URL: tokenURL}); err == nil {
		t.Fatal("expected rejection")
	}
	good := proofSpec{jti: "j1"}.sign(t, now, k)
	if _, err := v.Verify(context.Background(), dpop.Request{Proof: good, Method: "POST", URL: tokenURL}); err != nil {
		t.Fatalf("good proof after rejected one: %v", err)
	}
}

func TestReplayEntryExpiresWithFreshnessWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clk := &fixedClock{t: now}
	store := dpop.NewMemoryReplayStore(clk, 10)
	ok, err := store.Add("k", now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("first add: %v %v", ok, err)
	}
	if ok, _ := store.Add("k", now.Add(time.Minute)); ok {
		t.Fatal("second add must be a replay")
	}
	clk.t = now.Add(2 * time.Minute)
	if ok, _ := store.Add("k", clk.t.Add(time.Minute)); !ok {
		t.Fatal("expired entry must be reusable")
	}
}

func TestReplayStoreFailsClosedWhenFull(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clk := &fixedClock{t: now}
	store := dpop.NewMemoryReplayStore(clk, 2)
	for _, id := range []string{"a", "b"} {
		if ok, err := store.Add(id, now.Add(time.Minute)); !ok || err != nil {
			t.Fatalf("add %s: %v %v", id, ok, err)
		}
	}
	if _, err := store.Add("c", now.Add(time.Minute)); !errors.Is(err, dpop.ErrReplayStoreFull) {
		t.Fatalf("err = %v, want ErrReplayStoreFull", err)
	}
}

func TestThumbprintOfCnfMatchesProofKey(t *testing.T) {
	// Guards the base64url(SHA-256(RFC 7638 thumbprint)) encoding used for cnf.jkt
	// against an independent computation over the canonical member JSON.
	k := newKey(t)
	point, err := k.priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil || len(point) != 65 {
		t.Fatalf("public key bytes: %v (%d)", err, len(point))
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:])
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if k.jkt(t) != want || !hmac.Equal([]byte(k.jkt(t)), []byte(want)) {
		t.Fatalf("jkt mismatch: %s vs %s", k.jkt(t), want)
	}
}
