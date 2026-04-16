package credentials_test

// Bucket A — credential vending forensics fields.
//
// Exercises the vend path contract introduced alongside the audit schema
// migration (2026-04-16):
//
//   - Vender.Vend returns a unique UUID per issuance
//   - Vender.Vend stamps Type = TypeLLMSession
//   - Vender.Vend records ProviderTokenHash = sha256(api_key)
//   - Vender.VendGeneric equivalents
//
// These are the credentials-side invariants that make forensic reverse
// lookup possible at v0.3 ("hash this leaked token, find the issuance").

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/agentkms/agentkms/internal/credentials"
)

// ── UUID uniqueness ───────────────────────────────────────────────────────────

// TestBucketA_Vend_UUIDUnique confirms that a burst of vends produces
// distinct UUIDs.  A collision would break the credential → audit-event
// join on CredentialUUID, silently merging independent issuances.
func TestBucketA_Vend_UUIDUnique(t *testing.T) {
	const issuances = 1000
	kv := newStubKV("anthropic", "sk-ant-uuid-test")
	v := credentials.NewVender(kv, "kv")

	seen := make(map[string]struct{}, issuances)
	for i := 0; i < issuances; i++ {
		cred, err := v.Vend(context.Background(), "anthropic")
		if err != nil {
			t.Fatalf("Vend #%d: %v", i, err)
		}
		if cred.UUID == "" {
			t.Fatalf("Vend #%d returned empty UUID", i)
		}
		if _, dup := seen[cred.UUID]; dup {
			t.Fatalf("UUID collision at issuance #%d: %q", i, cred.UUID)
		}
		seen[cred.UUID] = struct{}{}
	}
	if len(seen) != issuances {
		t.Errorf("expected %d unique UUIDs, got %d", issuances, len(seen))
	}
}

func TestBucketA_VendGeneric_UUIDUnique(t *testing.T) {
	const issuances = 500
	kv := &stubKV{data: map[string]map[string]string{
		"kv/data/generic/svc": {"token": "ghp_unique-test"},
	}}
	v := credentials.NewVender(kv, "kv")

	seen := make(map[string]struct{}, issuances)
	for i := 0; i < issuances; i++ {
		cred, err := v.VendGeneric(context.Background(), "svc")
		if err != nil {
			t.Fatalf("VendGeneric #%d: %v", i, err)
		}
		if cred.UUID == "" {
			t.Fatalf("VendGeneric #%d returned empty UUID", i)
		}
		if _, dup := seen[cred.UUID]; dup {
			t.Fatalf("UUID collision at issuance #%d: %q", i, cred.UUID)
		}
		seen[cred.UUID] = struct{}{}
	}
}

// ── Credential type / class ───────────────────────────────────────────────────

func TestBucketA_Vend_TypeIsLLMSession(t *testing.T) {
	kv := newStubKV("openai", "sk-test-type")
	v := credentials.NewVender(kv, "kv")
	cred, err := v.Vend(context.Background(), "openai")
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	if cred.Type != credentials.TypeLLMSession {
		t.Errorf("Type = %q, want %q", cred.Type, credentials.TypeLLMSession)
	}
}

func TestBucketA_VendGeneric_TypeIsGenericVend(t *testing.T) {
	kv := &stubKV{data: map[string]map[string]string{
		"kv/data/generic/github": {"token": "ghp_type-check"},
	}}
	v := credentials.NewVender(kv, "kv")
	cred, err := v.VendGeneric(context.Background(), "github")
	if err != nil {
		t.Fatalf("VendGeneric: %v", err)
	}
	if cred.Type != credentials.TypeGenericVend {
		t.Errorf("Type = %q, want %q", cred.Type, credentials.TypeGenericVend)
	}
}

// ── Provider token hash ───────────────────────────────────────────────────────

// TestBucketA_Vend_ProviderTokenHashMatches — the load-bearing invariant
// for forensics reverse lookup.  Hashing the leaked token with raw SHA-256
// must yield the hash recorded in the audit event.  If this breaks, a
// provider leak report cannot be traced to its issuance.
func TestBucketA_Vend_ProviderTokenHashMatches(t *testing.T) {
	const token = "sk-ant-known-test-token-for-hash"
	kv := newStubKV("anthropic", token)
	v := credentials.NewVender(kv, "kv")
	cred, err := v.Vend(context.Background(), "anthropic")
	if err != nil {
		t.Fatalf("Vend: %v", err)
	}
	want := sha256.Sum256([]byte(token))
	wantHex := hex.EncodeToString(want[:])
	if cred.ProviderTokenHash != wantHex {
		t.Errorf("ProviderTokenHash = %q, want %q",
			cred.ProviderTokenHash, wantHex)
	}
}

// TestBucketA_Vend_ProviderTokenHashNeverContainsToken — adversarial:
// verifies the raw token never leaks into the hash field regardless of
// token shape.
func TestBucketA_Vend_ProviderTokenHashNeverContainsToken(t *testing.T) {
	tokens := []string{
		"sk-ant-looks-like-secret",
		"ghp_token-with-underscores",
		"AKIAabcdef0123456789",
	}
	for _, token := range tokens {
		// Each provider is vended from a distinct stub.
		kv := newStubKV("anthropic", token)
		v := credentials.NewVender(kv, "kv")
		cred, err := v.Vend(context.Background(), "anthropic")
		if err != nil {
			t.Fatalf("Vend: %v", err)
		}
		if contains(cred.ProviderTokenHash, token) {
			t.Fatalf(
				"ADVERSARIAL: hash %q contains raw token %q",
				cred.ProviderTokenHash, token,
			)
		}
	}
}

// TestBucketA_VendGeneric_ProviderTokenHashIsStable — generic credentials
// canonicalise the secret bundle before hashing, so the same set of
// fields (regardless of insertion order) must always produce the same
// hash.  This is what allows a leak of the underlying secret to be
// joined back to a generic-vend audit event.
func TestBucketA_VendGeneric_ProviderTokenHashIsStable(t *testing.T) {
	fields := map[string]string{
		"GITHUB_TOKEN": "ghp_stable",
		"NPM_TOKEN":    "npm_stable",
	}
	kv1 := &stubKV{data: map[string]map[string]string{
		"kv/data/generic/ci": fields,
	}}
	kv2 := &stubKV{data: map[string]map[string]string{
		"kv/data/generic/ci": fields, // same content
	}}
	v1 := credentials.NewVender(kv1, "kv")
	v2 := credentials.NewVender(kv2, "kv")
	c1, err := v1.VendGeneric(context.Background(), "ci")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := v2.VendGeneric(context.Background(), "ci")
	if err != nil {
		t.Fatal(err)
	}
	if c1.ProviderTokenHash != c2.ProviderTokenHash {
		t.Errorf("hash not stable for identical inputs: %q vs %q",
			c1.ProviderTokenHash, c2.ProviderTokenHash)
	}
}

// TestBucketA_Vend_UUIDLooksLikeUUIDv4 — the forensics UX assumes UUIDs
// in the canonical 8-4-4-4-12 format; check we produce that shape.
func TestBucketA_Vend_UUIDLooksLikeUUIDv4(t *testing.T) {
	kv := newStubKV("anthropic", "sk-format")
	v := credentials.NewVender(kv, "kv")
	cred, err := v.Vend(context.Background(), "anthropic")
	if err != nil {
		t.Fatal(err)
	}
	// Format: 8-4-4-4-12 lowercase hex (36 chars incl. dashes).
	if len(cred.UUID) != 36 {
		t.Errorf("UUID length = %d, want 36 (%q)", len(cred.UUID), cred.UUID)
	}
	for i, c := range cred.UUID {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				t.Errorf("expected '-' at position %d, got %q", i, c)
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("non-hex character %q at position %d in UUID %q",
					c, i, cred.UUID)
			}
		}
	}
	// Version-4 marker: position 14 is the first char of the third group.
	if cred.UUID[14] != '4' {
		t.Errorf("UUID version nibble = %q, want '4' (UUID v4)", cred.UUID[14])
	}
	// RFC 4122 variant: position 19 must be one of 8, 9, a, b.
	switch cred.UUID[19] {
	case '8', '9', 'a', 'b':
		// ok
	default:
		t.Errorf("UUID variant nibble = %q, want one of 8/9/a/b",
			cred.UUID[19])
	}
}
