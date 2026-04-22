package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Core types ──────────────────────────────────────────────────────────────

// Scope describes the effective permissions of a vended credential.
// Captured at vend time, stored in the audit log, and returned to the
// caller alongside the credential value.
type Scope struct {
	// Kind discriminates the structural shape of Params.  Core knows
	// "llm-session" and "generic-vend" (wrapping v0.1 behaviour).
	// Plugins register additional Kinds (e.g. "aws-sts", "github-pat").
	Kind string `json:"kind"`

	// Params holds Kind-specific structured scope data.  Its shape is
	// defined by the plugin that owns the Kind.  Core treats it as
	// opaque JSON during serialization.
	Params map[string]any `json:"params,omitempty"`

	// TTL is the effective lifetime from issuance.
	TTL time.Duration `json:"ttl"`

	// IssuedAt is the wall-clock time the scope became valid.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is IssuedAt + TTL.  Stored explicitly so audit queries
	// don't have to reconstruct.
	ExpiresAt time.Time `json:"expires_at"`
}

// VendRequest is the input to the scoped credential vending pipeline.
type VendRequest struct {
	// Identity of the caller (from mTLS cert).
	Identity identity.Identity

	// DesiredScope describes what the caller wants.  The pipeline
	// narrows this against policy bounds and plugin validators.
	// Empty Kind means legacy llm-session vend (back-compat).
	DesiredScope Scope

	// AgentSession is the opaque session ID for audit correlation.
	AgentSession string
}

// ScopeBounds is the maximum scope a policy rule allows for a given
// (identity, operation) pair.  Intersection semantics are Kind-specific
// and delegated to the registered ScopeValidator.
type ScopeBounds struct {
	Kind      string         `json:"kind,omitempty"`
	MaxParams map[string]any `json:"max_params,omitempty"`
	MaxTTL    time.Duration  `json:"max_ttl,omitempty"`
}

// ── Plugin interfaces ───────────────────────────────────────────────────────

// ScopeValidator validates structural correctness and performs policy
// narrowing for a specific Kind.  Required per-Kind.
// //blog:part-5 references this interface in the dynamic-secrets architecture section.
// //blog:part-7 references this interface in the "plugin API" section.
type ScopeValidator interface {
	// Kind returns the discriminator this validator owns.
	Kind() string

	// Validate checks that s has a well-formed Params shape.
	// Must not mutate s.
	Validate(ctx context.Context, s Scope) error

	// Narrow intersects a requested Scope with policy bounds and
	// returns the effective Scope.  Returns an error if bounds are
	// incompatible with the request.
	Narrow(ctx context.Context, requested Scope, bounds ScopeBounds) (Scope, error)
}

// ScopeAnalyzer assesses risk at vend time.  Optional per-Kind.
// Flags anomalies recorded in audit but does not block vending.
// //blog:part-7 references this interface in the "plugin API" section.
type ScopeAnalyzer interface {
	Kind() string

	// Analyze returns anomalies describing risky scope aspects.
	Analyze(ctx context.Context, s Scope) []ScopeAnomaly
}

// ScopeAnomaly is a single risk signal from a ScopeAnalyzer.
type ScopeAnomaly struct {
	Level   AnomalyLevel `json:"level"`
	Code    string       `json:"code"`
	Message string       `json:"message"`
}

// AnomalyLevel indicates severity.
type AnomalyLevel string

const (
	AnomalyInfo  AnomalyLevel = "info"
	AnomalyWarn  AnomalyLevel = "warn"
	AnomalyAlert AnomalyLevel = "alert"
)

// ScopeSerializer converts a Scope to the provider-native request format.
// Required per-Kind that vends real upstream credentials.
// //blog:part-7 references this interface in the "plugin API" section.
type ScopeSerializer interface {
	Kind() string

	// ProviderRequest converts s to the provider-native format
	// (AWS IAM policy document, GitHub permissions object, etc.).
	// Core never inspects or logs the serialised bytes.
	ProviderRequest(ctx context.Context, s Scope) ([]byte, error)
}

// CredentialVender issues real upstream credentials given a serialized scope.
// Optional per-Kind — only needed for plugins that call upstream provider APIs.
// The CredentialVender pipeline step is wired in v0.3.2; this interface lands
// in v0.3.1 so all four services are subprocess-connectable.
type CredentialVender interface {
	// Kind returns the discriminator this vender owns.
	Kind() string

	// Vend issues a short-lived credential scoped to s.
	// Returns a VendedCredential with secret bytes, UUID, hash, and TTL.
	Vend(ctx context.Context, s Scope) (*VendedCredential, error)
}

// ── Canonical hash ──────────────────────────────────────────────────────────

// ScopeHash returns the SHA-256 hex digest of the canonical JSON
// encoding of s.  Two structurally identical Scopes produce identical
// hashes.  Used for audit correlation between vend and use events.
func ScopeHash(s Scope) string {
	b, _ := canonicalScopeJSON(s)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

// canonicalScopeJSON produces the canonical form of a Scope for
// hashing.  Keys sorted lexicographically at every level; no
// whitespace; no trailing newline.
func canonicalScopeJSON(s Scope) ([]byte, error) {
	// Build an ordered map for deterministic output.
	m := map[string]any{
		"kind":       s.Kind,
		"ttl":        s.TTL.String(),
		"issued_at":  s.IssuedAt.UTC().Format(time.RFC3339Nano),
		"expires_at": s.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	if len(s.Params) > 0 {
		m["params"] = sortedParams(s.Params)
	}
	return json.Marshal(m)
}

// sortedParams returns a copy of params with all map keys sorted.
// Handles one level of nested maps (sufficient for scope params).
func sortedParams(params map[string]any) map[string]any {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]any, len(params))
	for _, k := range keys {
		v := params[k]
		if nested, ok := v.(map[string]any); ok {
			v = sortedParams(nested)
		}
		out[k] = v
	}
	return out
}
