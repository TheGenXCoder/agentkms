package credentials_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// ── stub KVReader ─────────────────────────────────────────────────────────────

type stubKV struct {
	data map[string]map[string]string
	err  error
}

func (s *stubKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.data[path]
	if !ok {
		return nil, credentials.ErrCredentialNotFound
	}
	return v, nil
}

func newStubKV(provider, apiKey string) *stubKV {
	return &stubKV{
		data: map[string]map[string]string{
			"kv/data/llm/" + provider: {"api_key": apiKey},
		},
	}
}

// ── happy path ────────────────────────────────────────────────────────────────

func TestVend_Success(t *testing.T) {
	kv := newStubKV("anthropic", "sk-ant-test-key-abcdef")
	v := credentials.NewVender(kv, "kv")

	cred, err := v.Vend(context.Background(), "anthropic")
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if cred.Provider != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", cred.Provider)
	}
	if cred.APIKey != "sk-ant-test-key-abcdef" {
		t.Errorf("APIKey mismatch")
	}
	if cred.TTLSeconds != int(credentials.CredentialTTL.Seconds()) {
		t.Errorf("TTLSeconds = %d, want %d", cred.TTLSeconds, int(credentials.CredentialTTL.Seconds()))
	}
	if cred.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}
	// ExpiresAt must be ~60 minutes from now
	delta := time.Until(cred.ExpiresAt)
	if delta < 59*time.Minute || delta > 61*time.Minute {
		t.Errorf("ExpiresAt delta %v is not ~60 minutes", delta)
	}
}

func TestVend_AllSupportedProviders(t *testing.T) {
	for provider := range credentials.SupportedProviders {
		kv := newStubKV(provider, "test-key-for-"+provider)
		v := credentials.NewVender(kv, "kv")
		cred, err := v.Vend(context.Background(), provider)
		if err != nil {
			t.Errorf("Vend(%q): %v", provider, err)
			continue
		}
		if cred.Provider != provider {
			t.Errorf("Vend(%q): Provider = %q", provider, cred.Provider)
		}
	}
}

// ── error paths ───────────────────────────────────────────────────────────────

func TestVend_UnsupportedProvider(t *testing.T) {
	v := credentials.NewVender(&stubKV{}, "kv")
	_, err := v.Vend(context.Background(), "grok-unknown")
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !errors.Is(err, credentials.ErrProviderNotSupported) {
		t.Errorf("expected ErrProviderNotSupported, got: %v", err)
	}
}

func TestVend_CredentialNotFound(t *testing.T) {
	kv := &stubKV{data: map[string]map[string]string{}} // empty KV
	v := credentials.NewVender(kv, "kv")
	_, err := v.Vend(context.Background(), "anthropic")
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
	if !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestVend_PlaceholderKeyRejected(t *testing.T) {
	kv := newStubKV("openai", "REPLACE_WITH_REAL_KEY")
	v := credentials.NewVender(kv, "kv")
	_, err := v.Vend(context.Background(), "openai")
	if err == nil {
		t.Fatal("expected error for placeholder key")
	}
	if !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestVend_MissingAPIKeyField(t *testing.T) {
	kv := &stubKV{
		data: map[string]map[string]string{
			"kv/data/llm/anthropic": {"other_field": "something"},
		},
	}
	v := credentials.NewVender(kv, "kv")
	_, err := v.Vend(context.Background(), "anthropic")
	if err == nil {
		t.Fatal("expected error for missing api_key field")
	}
	if !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestVend_KVError_PropagatesError(t *testing.T) {
	kvErr := errors.New("kv: connection refused")
	kv := &stubKV{err: kvErr}
	v := credentials.NewVender(kv, "kv")
	_, err := v.Vend(context.Background(), "anthropic")
	if err == nil {
		t.Fatal("expected error from KV failure")
	}
	if !errors.Is(err, kvErr) {
		t.Errorf("expected wrapped kvErr, got: %v", err)
	}
}

// ── ADVERSARIAL — API key never in error messages ─────────────────────────────

func TestAdversarial_VendError_NoKeyInMessage(t *testing.T) {
	// Even when something goes wrong after the key is fetched, it must not
	// appear in any error message.
	//
	// This test verifies the placeholder case returns ErrCredentialNotFound
	// without echoing the placeholder value into the error text in a way
	// that could carry a real key if the placeholder were replaced.
	const sensitiveKey = "sk-ant-realproductionkey-AAABBBCCC"
	kv := newStubKV("anthropic", sensitiveKey)
	// Swap the key for a placeholder to trigger the rejection path
	kv.data["kv/data/llm/anthropic"]["api_key"] = "REPLACE_WITH_REAL_KEY"
	v := credentials.NewVender(kv, "kv")

	_, err := v.Vend(context.Background(), "anthropic")
	if err == nil {
		t.Fatal("expected error")
	}
	if contains(err.Error(), sensitiveKey) {
		t.Fatalf("ADVERSARIAL: error message contains API key: %q", err.Error())
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) &&
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}()
}
