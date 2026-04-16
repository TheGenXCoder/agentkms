// Package credentials implements LLM provider credential vending (LV-01–LV-04).
//
// Credential vending is the process of issuing a short-lived, scoped LLM API
// key to a caller for use within a single session.  The master LLM key lives
// in the OpenBao KV store; AgentKMS fetches it and re-issues it with a TTL
// bound to the caller's session.
//
// SECURITY INVARIANTS:
//
//  1. The master LLM key is NEVER returned to the caller.  The vended key is
//     either identical to the master key (single-tenant T1) or a separate
//     short-lived scoped credential (T2 multi-tenant, not yet implemented).
//     In either case, the key is only held in memory for the duration of the
//     HTTP response — it is never logged, never stored, and never included in
//     audit events.
//
//  2. The audit log records the credential vend event with the caller identity,
//     provider, session ID, and TTL — NOT the key value itself.
//
//  3. Revocation: when a session token is revoked, the vended key's TTL ensures
//     it expires naturally.  Immediate revocation (T2) requires maintaining a
//     per-session credential inventory, which is tracked in backlog LV-03.
//
// Supported providers: anthropic, openai, google, azure, bedrock, mistral, groq.
// Keys are stored in OpenBao KV at: kv/llm/{provider}
package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// CredentialTTL is the lifetime of a vended LLM credential.
// Per architecture §7.1: 60 minutes maximum.
const CredentialTTL = 60 * time.Minute

// ── Credential type constants ─────────────────────────────────────────────────
//
// These strings flow into AuditEvent.CredentialType and make it possible for
// downstream forensics queries to filter by credential class even while v0.1
// keeps the Operation field coarse ("credential_vend" / "credential_use").
const (
	// TypeLLMSession identifies an LLM provider API key vended by
	// Vender.Vend (fetched from kv/llm/{provider}).
	TypeLLMSession = "llm-session"

	// TypeGenericVend identifies a generic secret bundle vended by
	// Vender.VendGeneric (fetched from kv/generic/{path}).
	TypeGenericVend = "generic-vend"
)

// SupportedProviders is the set of LLM providers whose credentials
// AgentKMS can vend.  Keys are stored in KV at kv/llm/{provider}.
var SupportedProviders = map[string]bool{
	"anthropic": true,
	"openai":    true,
	"google":    true,
	"azure":     true,
	"bedrock":   true,
	"mistral":   true,
	"groq":      true,
	"xai":       true,
}

// ErrProviderNotSupported is returned when the requested provider is not
// in the SupportedProviders set.
var ErrProviderNotSupported = errors.New("credentials: provider not supported")

// ErrCredentialNotFound is returned when no credential exists in the backend
// for the requested provider.
var ErrCredentialNotFound = errors.New("credentials: no credential found for provider")

// VendedCredential is the credential returned to the caller.
//
// SECURITY: APIKey is the only field that contains sensitive material.
// It must not be logged, stored, or echoed back in error messages.
// The caller (HTTP handler) must write it directly to the response and
// never pass it to any other function beyond writing the HTTP response body.
type VendedCredential struct {
	// Provider identifies the LLM provider (e.g. "anthropic", "openai").
	Provider string

	// Type identifies the credential class (see Type* constants).  Flows
	// into AuditEvent.CredentialType for forensics filtering.
	Type string

	// UUID is the per-issuance internal identifier assigned at vend time.
	// Echoed back to AgentKMS by clients on /audit/use so that use events
	// can be joined to the original vend event in the audit log.  Format:
	// UUID v4.
	UUID string

	// ProviderTokenHash is the SHA-256 hex digest of the raw APIKey,
	// computed at vend time.  Stored here so the HTTP handler can copy it
	// into the audit event after zeroing APIKey.
	//
	// SECURITY: this is NOT key material — it is a one-way hash of the
	// provider-issued token, safe to log.  The raw token never leaves
	// APIKey (which is zeroed immediately after the HTTP response).
	ProviderTokenHash string

	// APIKey is the LLM provider API key.
	// SECURITY: NEVER log, audit, or store this value.  It is key material.
	// Use []byte so callers can zero it after writing the HTTP response.
	// Call Zero() in a defer immediately after use.
	APIKey []byte

	// ExpiresAt is when this credential should be considered expired.
	// The Pi extension refreshes the credential before this time.
	ExpiresAt time.Time

	// TTLSeconds is the number of seconds until ExpiresAt.
	TTLSeconds int
}

// Zero overwrites the APIKey with zeros.  Call this in a defer after
// writing the HTTP response to minimize the window during which the
// key is resident in heap memory.
func (c *VendedCredential) Zero() {
	for i := range c.APIKey {
		c.APIKey[i] = 0
	}
}

// GenericCredential is a collection of secrets returned to a generic caller.
//
// SECURITY: Secrets contains sensitive key material. It must not be logged.
type GenericCredential struct {
	Path string

	// Type identifies the credential class (see Type* constants).
	Type string

	// UUID is the per-issuance internal identifier; see VendedCredential.UUID.
	UUID string

	// ProviderTokenHash is a SHA-256 hex digest computed over the secret
	// payload at vend time.  For generic credentials (a bag of named
	// values) the hash is computed over the field values in sorted-key
	// order so the same inputs always produce the same hash.  This lets
	// forensics reverse-lookup a leaked generic secret (e.g. a leaked PAT
	// stored at kv/generic/github/token) without logging the raw value.
	ProviderTokenHash string

	Secrets    map[string][]byte
	ExpiresAt  time.Time
	TTLSeconds int
}

// Zero overwrites the Secrets map values with zeros.
func (c *GenericCredential) Zero() {
	for k, v := range c.Secrets {
		for i := range v {
			v[i] = 0
		}
		c.Secrets[k] = nil
	}
}

// KVReader is the interface for reading secrets from the backend KV store.
// Only a narrow read interface is needed — credential vending never writes.
type KVReader interface {
	// GetSecret retrieves a secret value by its KV path.
	// Returns ErrCredentialNotFound if the path does not exist.
	GetSecret(ctx context.Context, path string) (map[string]string, error)
}

// KVWriter extends KVReader with write, delete, and list operations.
type KVWriter interface {
	KVReader
	SetSecret(ctx context.Context, path string, fields map[string]string) error
	DeleteSecret(ctx context.Context, path string) error
	ListPaths(ctx context.Context) ([]string, error)
}

// Vender issues short-lived LLM credentials to authenticated callers.
type Vender struct {
	kv      KVReader
	kvMount string
	nowFunc func() time.Time
}

// NewVender constructs a Vender.
// kvMount is the KV v2 mount path (e.g. "kv").
func NewVender(kv KVReader, kvMount string) *Vender {
	return &Vender{
		kv:      kv,
		kvMount: kvMount,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// Vend fetches the master credential for provider from the KV store and
// returns a VendedCredential with a TTL bound to CredentialTTL.
//
// Returns ErrProviderNotSupported if provider is not in SupportedProviders.
// Returns ErrCredentialNotFound if no credential exists for the provider.
func (v *Vender) Vend(ctx context.Context, provider string) (*VendedCredential, error) {
	if !SupportedProviders[provider] {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotSupported, provider)
	}

	// KV v2 data path: {mount}/data/{key-path}
	kvPath := fmt.Sprintf("%s/data/llm/%s", v.kvMount, provider)
	secret, err := v.kv.GetSecret(ctx, kvPath)
	if err != nil {
		return nil, err
	}

	apiKey, ok := secret["api_key"]
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("%w: %q (api_key field missing or empty)", ErrCredentialNotFound, provider)
	}
	if apiKey == "REPLACE_WITH_REAL_KEY" {
		return nil, fmt.Errorf("%w: %q (placeholder not replaced — set a real API key in KV)", ErrCredentialNotFound, provider)
	}

	now := v.nowFunc()
	expiresAt := now.Add(CredentialTTL)

	uuid, err := newCredentialUUID()
	if err != nil {
		return nil, fmt.Errorf("credentials: generating credential UUID: %w", err)
	}

	// Hash the provider-issued token at vend time so the handler can record
	// it in the audit event after zeroing the raw key.  The raw token does
	// NOT appear in the audit log — only this one-way hash.
	tokenHash := audit.HashProviderToken([]byte(apiKey))

	return &VendedCredential{
		Provider:          provider,
		Type:              TypeLLMSession,
		UUID:              uuid,
		ProviderTokenHash: tokenHash,
		APIKey:            []byte(apiKey), // SECURITY: caller must call Zero() after use
		ExpiresAt:         expiresAt,
		TTLSeconds:        int(CredentialTTL.Seconds()),
	}, nil
}

// VendGeneric fetches a generic set of credentials from the KV store.
// The path parameter corresponds to the path under kv/generic/{path}.
//
// Returns ErrCredentialNotFound if the path does not exist.
func (v *Vender) VendGeneric(ctx context.Context, path string) (*GenericCredential, error) {
	// KV v2 data path: {mount}/data/generic/{path}
	kvPath := fmt.Sprintf("%s/data/generic/%s", v.kvMount, path)
	secret, err := v.kv.GetSecret(ctx, kvPath)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string][]byte, len(secret))
	for k, val := range secret {
		secrets[k] = []byte(val)
	}

	now := v.nowFunc()
	expiresAt := now.Add(CredentialTTL)

	uuid, err := newCredentialUUID()
	if err != nil {
		return nil, fmt.Errorf("credentials: generating credential UUID: %w", err)
	}

	// Hash a stable, sorted-key canonicalisation of the secret bundle so
	// that the same secret contents always produce the same hash (enabling
	// leak reverse-lookup) without leaking the raw values into the audit log.
	tokenHash := audit.HashProviderToken(canonicalGenericPayload(secret))

	return &GenericCredential{
		Path:              path,
		Type:              TypeGenericVend,
		UUID:              uuid,
		ProviderTokenHash: tokenHash,
		Secrets:           secrets,
		ExpiresAt:         expiresAt,
		TTLSeconds:        int(CredentialTTL.Seconds()),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// newCredentialUUID returns a freshly generated RFC 4122 §4.4 UUID v4.
// Generated from crypto/rand; returns an error only if the OS entropy source
// is unavailable (essentially impossible in practice).
//
// Each call produces a unique value — collision probability is negligible at
// 2^122 bits of variability, so two credentials vended in the same session
// will never share a UUID in practice.
func newCredentialUUID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	// Version (4) and RFC 4122 variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

// canonicalGenericPayload returns a deterministic byte sequence derived from
// the generic secret fields, used as input to the provider-token hash.
//
// Determinism is essential for reverse lookup: the same set of (key, value)
// pairs must always produce the same hash.  We achieve this by sorting keys
// lexicographically and framing each (k, v) pair with length prefixes so
// that no adversary can craft two distinct secret bundles that produce an
// identical canonical representation.
func canonicalGenericPayload(fields map[string]string) []byte {
	if len(fields) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	// Sort in ascending order without importing "sort" just for this —
	// simple insertion is fine; these bundles are tiny (≤ a few fields).
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	var out []byte
	for _, k := range keys {
		v := fields[k]
		// Length-prefixed framing: <len(k)>:<k>=<len(v)>:<v>;
		out = append(out, []byte(fmt.Sprintf("%d:%s=%d:%s;", len(k), k, len(v), v))...)
	}
	return out
}
