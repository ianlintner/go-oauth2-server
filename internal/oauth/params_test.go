package oauth_test

import (
	"errors"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestParseParamsReadsSingleValues(t *testing.T) {
	p, err := oauth.ParseParams("client_id=abc&state=x%20y&redirect_uri=https%3A%2F%2Fc.example%2Fcb")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Get("client_id"); got != "abc" {
		t.Fatalf("client_id = %q", got)
	}
	if got := p.Get("state"); got != "x y" {
		t.Fatalf("state = %q", got)
	}
	if got := p.Get("redirect_uri"); got != "https://c.example/cb" {
		t.Fatalf("redirect_uri = %q", got)
	}
	if p.Get("absent") != "" || p.Has("absent") {
		t.Fatal("absent parameter must read as empty and not be present")
	}
}

// RFC 6749 §3.1: a parameter sent without a value is treated as omitted.
func TestParseParamsTreatsEmptyValueAsOmitted(t *testing.T) {
	p, err := oauth.ParseParams("state=&client_id=abc")
	if err != nil {
		t.Fatal(err)
	}
	if p.Has("state") || p.Get("state") != "" {
		t.Fatal("empty state must read as omitted")
	}
}

func TestParseParamsRejectsDuplicatesBeforeAnyValueIsRead(t *testing.T) {
	cases := map[string]string{
		"plain duplicate":          "client_id=a&client_id=b",
		"same value twice":         "client_id=a&client_id=a",
		"empty then value":         "state=&state=x",
		"encoded key duplicate":    "client_id=a&client%5Fid=b",
		"duplicate among others":   "response_type=code&redirect_uri=u&state=1&redirect_uri=v",
		"duplicate with plus form": "scope=a+b&scope=c",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := oauth.ParseParams(raw)
			var oe *oauth.Error
			if !errors.As(err, &oe) || oe.Code != oauth.CodeInvalidRequest {
				t.Fatalf("err = %v, want invalid_request", err)
			}
			if p.Has("client_id") || p.Get("client_id") != "" {
				t.Fatal("no value may be readable from a rejected parameter set")
			}
		})
	}
}

func TestParseParamsRejectsMalformedEncoding(t *testing.T) {
	for _, raw := range []string{"a=%zz", "a=1;b=2"} {
		_, err := oauth.ParseParams(raw)
		var oe *oauth.Error
		if !errors.As(err, &oe) || oe.Code != oauth.CodeInvalidRequest {
			t.Fatalf("ParseParams(%q) err = %v, want invalid_request", raw, err)
		}
	}
}

func TestParseParamsEmptyInput(t *testing.T) {
	p, err := oauth.ParseParams("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Has("client_id") {
		t.Fatal("empty input has no parameters")
	}
}
