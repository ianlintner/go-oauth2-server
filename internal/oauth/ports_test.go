package oauth_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestSystemClockIsUTC(t *testing.T) {
	now := oauth.SystemClock{}.Now()
	if now.Location() != time.UTC {
		t.Fatalf("location = %v, want UTC", now.Location())
	}
	if d := time.Since(now); d < 0 || d > time.Minute {
		t.Fatalf("clock off by %v", d)
	}
}

func TestCryptoRandomReturnsRequestedLength(t *testing.T) {
	a, err := oauth.CryptoRandom{}.Bytes(32)
	if err != nil || len(a) != 32 {
		t.Fatalf("Bytes = %d, %v", len(a), err)
	}
	b, _ := oauth.CryptoRandom{}.Bytes(32)
	if bytes.Equal(a, b) {
		t.Fatal("two reads returned identical bytes")
	}
}

func TestCryptoRandomFailsClosed(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := (oauth.CryptoRandom{}).Bytes(n); err == nil {
			t.Errorf("Bytes(%d) succeeded", n)
		}
	}
	short := oauth.CryptoRandom{Reader: strings.NewReader("abc")}
	if _, err := short.Bytes(8); err == nil {
		t.Fatal("short read returned bytes")
	}
	broken := oauth.CryptoRandom{Reader: iotest.ErrReader(errors.New("entropy gone"))}
	if _, err := broken.Bytes(8); err == nil {
		t.Fatal("failed read returned bytes")
	}
}
