package oauth

import (
	"net/url"
)

// Params is a set of OAuth request parameters in which every name occurs at
// most once. The only way to obtain one is ParseParams, which refuses
// duplicates before any value can be read, so a handler can never act on
// "the first of several" values (the net/http FormValue behavior), which is the
// root of parser-differential and parameter-pollution attacks.
//
// RFC 6749 §3.1: parameters sent without a value are treated as if they were
// omitted, and a parameter MUST NOT be included more than once.
type Params struct {
	v map[string]string
}

// ParseParams parses a URL-encoded query string or form body. It returns an
// invalid_request error, and an empty Params, when any parameter name appears
// more than once (even with equal or empty values), when the encoding is
// malformed, or when the legacy ';' separator is used. Names are compared
// after percent-decoding, so "client%5Fid" collides with "client_id".
func ParseParams(raw string) (Params, error) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return Params{}, InvalidRequest("malformed request parameters")
	}
	// Reject every duplicate first; nothing is read from vals until the whole
	// set has been checked.
	for name, list := range vals {
		if len(list) > 1 {
			_ = name // the name is deliberately not echoed back
			return Params{}, InvalidRequest("duplicate parameter")
		}
	}
	p := Params{v: make(map[string]string, len(vals))}
	for name, list := range vals {
		if list[0] == "" {
			continue // empty value == omitted
		}
		p.v[name] = list[0]
	}
	return p, nil
}

// Get returns the parameter's value, or "" when it is absent or empty.
func (p Params) Get(name string) string { return p.v[name] }

// Has reports whether the parameter was supplied with a non-empty value.
func (p Params) Has(name string) bool {
	_, ok := p.v[name]
	return ok
}
