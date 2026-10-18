package oauth

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// MatchRedirectURI reports whether requested may be used as a redirect target
// for a client that registered the given URIs.
//
// Matching is exact, byte for byte (RFC 6749 §3.1.2.3, RFC 9700 §4.1): no
// normalization, no prefix or pattern matching, no query or fragment
// tolerance. The single exception is the RFC 8252 §7.3 loopback rule: a
// registration of http://127.0.0.1/path or http://[::1]/path (an IP literal
// with no explicit port) accepts any port at request time, with scheme, host
// family and path still exact. "localhost" gets no wildcard.
//
// A plain-http URI is accepted only for a loopback host unless
// allowInsecureHTTP is set (RFC 9700 §2.6).
func MatchRedirectURI(registered []string, requested string, allowInsecureHTTP bool) bool {
	if requested == "" || strings.Contains(requested, "#") { // §3.1.2: no fragment
		return false
	}
	for _, reg := range registered {
		if reg == "" {
			continue
		}
		if reg == requested {
			if httpAllowed(requested, allowInsecureHTTP) {
				return true
			}
			continue
		}
		if matchLoopbackPort(reg, requested) {
			return true
		}
	}
	return false
}

// httpAllowed enforces the https requirement on an otherwise exact match.
func httpAllowed(uri string, allowInsecure bool) bool {
	if !strings.HasPrefix(uri, "http://") {
		return true // https, private-use scheme, ...
	}
	if allowInsecure {
		return true
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || isLoopbackLiteral(h)
}

// isLoopbackLiteral reports whether host is a canonical IPv4 or IPv6 loopback
// literal (not a name, not a non-canonical spelling).
func isLoopbackLiteral(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && ip.String() == host
}

// matchLoopbackPort implements the RFC 8252 §7.3 any-port rule for one
// registration. It works on the raw strings so the scheme, host spelling and
// path/query are compared exactly (url.Parse would lower-case the scheme).
func matchLoopbackPort(reg, requested string) bool {
	const scheme = "http://"
	if !strings.HasPrefix(reg, scheme) || !strings.HasPrefix(requested, scheme) {
		return false
	}
	u, err := url.Parse(reg)
	if err != nil || u.User != nil || u.Fragment != "" || u.Port() != "" || !isLoopbackLiteral(u.Hostname()) {
		return false
	}
	hostPart := u.Host // "127.0.0.1" or "[::1]", exactly as registered
	if !strings.HasPrefix(reg[len(scheme):], hostPart) {
		return false
	}
	regRest := reg[len(scheme)+len(hostPart):] // path and query, exact
	reqRest, ok := strings.CutPrefix(requested[len(scheme):], hostPart)
	if !ok {
		return false
	}
	if after, hasPort := strings.CutPrefix(reqRest, ":"); hasPort {
		end := strings.IndexAny(after, "/?")
		if end < 0 {
			end = len(after)
		}
		port := after[:end]
		if !validPort(port) {
			return false
		}
		reqRest = after[end:]
	}
	return reqRest == regRest
}

func validPort(s string) bool {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}
