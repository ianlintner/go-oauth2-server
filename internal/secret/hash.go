// Package secret hashes and verifies client secrets and user passwords with
// argon2id (golang.org/x/crypto), stored as a PHC string. The primitive is the
// vetted library's; this package only picks parameters and encodes them.
package secret

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"golang.org/x/crypto/argon2"
)

// Parameters follow the OWASP argon2id minimum (19 MiB, t=2, p=1).
const (
	memoryKiB  = 19 * 1024
	iterations = 2
	threads    = 1
	saltLen    = 16
	keyLen     = 32

	// Upper bounds on parameters read back from a stored hash, so a corrupted
	// or hostile row cannot make Verify allocate gigabytes.
	maxMemoryKiB  = 256 * 1024
	maxIterations = 10
	maxThreads    = 16
)

var b64 = base64.RawStdEncoding

// Hash returns the argon2id PHC string for secret, salted from rnd.
func Hash(rnd oauth.Random, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secret: refusing to hash an empty secret")
	}
	salt, err := rnd.Bytes(saltLen)
	if err != nil {
		return "", fmt.Errorf("secret: salt: %w", err)
	}
	key := argon2.IDKey([]byte(secret), salt, iterations, memoryKiB, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iterations, threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether secret matches encoded. A malformed or out-of-bounds
// encoding is an error (never a silent false), so corruption is visible.
func Verify(encoded, secret string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errors.New("secret: not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("secret: unsupported argon2 version")
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errors.New("secret: bad argon2 parameters")
	}
	if m == 0 || m > maxMemoryKiB || t == 0 || t > maxIterations || p == 0 || p > maxThreads {
		return false, errors.New("secret: argon2 parameters out of bounds")
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, errors.New("secret: bad salt")
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errors.New("secret: bad key")
	}
	got := argon2.IDKey([]byte(secret), salt, t, m, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
