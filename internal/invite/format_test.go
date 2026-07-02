package invite

import (
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour).Unix()
	p := Payload{
		Version:       1,
		ServerURL:     "https://agentkms.example.com:8443",
		CAFingerprint: "abc123",
		Token:         "deadbeef",
		ExpiresAt:     exp,
	}
	code, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if code[:6] != "kpmi1_" {
		t.Fatalf("prefix: %q", code[:6])
	}
	got, err := Decode(code)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != p.ServerURL || got.Token != p.Token || got.CAFingerprint != p.CAFingerprint {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestDecodeExpired(t *testing.T) {
	code, err := Encode(Payload{
		Version:       1,
		ServerURL:     "https://x",
		CAFingerprint: "fp",
		Token:         "tok",
		ExpiresAt:     time.Now().Add(-time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(code); err == nil {
		t.Fatal("expected expired error")
	}
}
