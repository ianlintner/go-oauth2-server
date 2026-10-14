package config

import (
	"fmt"
	"log/slog"
)

// redacted is what every formatting path prints in place of a secret value.
const redacted = "[REDACTED]"

// Secret is a string that never prints itself. fmt verbs, JSON and slog all
// render it as [REDACTED]; callers that really need the value convert it
// explicitly with string(s) at the point of use.
type Secret string

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (Secret) GoString() string { return `config.Secret("` + redacted + `")` }

// Format implements fmt.Formatter so no verb (%s, %q, %x, %v, %d...) can
// render the underlying bytes.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, redacted) }

// MarshalText covers encoding/json and text-based log handlers.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
