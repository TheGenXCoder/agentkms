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
	"errors"
	"fmt"
	"time"
)

// CredentialTTL is the lifetime of a vended LLM credential.
// Per architecture §7.1: 60 minutes maximum.
const CredentialTTL = 60 * time.Minute

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

// KVReader is the interface for reading secrets from the backend KV store.
// Only a narrow read interface is needed — credential vending never writes.
type KVReader interface {
	// GetSecret retrieves a secret value by its KV path.
	// Returns ErrCredentialNotFound if the path does not exist.
	GetSecret(ctx context.Context, path string) (map[string]string, error)
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

	return &VendedCredential{
		Provider:   provider,
		APIKey:     []byte(apiKey), // SECURITY: caller must call Zero() after use
		ExpiresAt:  expiresAt,
		TTLSeconds: int(CredentialTTL.Seconds()),
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

	return &GenericCredential{
		Path:       path,
		Secrets:    secrets,
		ExpiresAt:  expiresAt,
		TTLSeconds: int(CredentialTTL.Seconds()),
	}, nil
}
