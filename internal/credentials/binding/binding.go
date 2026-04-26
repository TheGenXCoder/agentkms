// Package binding defines the CredentialBinding data model, validation, and
// storage interface for AgentKMS.
//
// A CredentialBinding links:
//   - a credential source (provider_kind + provider_params + scope)
//   - one or more delivery destinations (kind + target_id + params)
//   - a rotation policy (TTL hint, manual-only flag)
//
// Bindings are the persistent state consumed by the rotation orchestrator (T5).
// This package is OSS-only: no scheduling, no automatic rotation triggers.
package binding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// namePattern matches valid binding names: lowercase, starts with a letter,
// alphanumeric + hyphen, max 63 characters.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// kindPattern matches valid destination kind strings (same shape as name).
var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ── Core types ────────────────────────────────────────────────────────────────

// CredentialBinding links a credential provider to N destinations and a
// rotation policy.  It is the unit of state consumed by the rotation
// orchestrator.
//
// JSON field names are stable API surface — do not rename without a migration.
type CredentialBinding struct {
	// Name is the unique, human-friendly identifier for this binding.
	// Validation: matches ^[a-z][a-z0-9-]{0,62}$
	Name string `json:"name"`

	// ProviderKind identifies the credential provider plugin kind.
	// Examples: "github-app-token", "anthropic-api-key", "aws-sts".
	ProviderKind string `json:"provider_kind"`

	// ProviderParams holds provider-specific configuration (opaque to the
	// binding layer).  The provider plugin interprets these.
	// Examples: {"app_name": "agentkms-blog-audit"}.
	ProviderParams map[string]any `json:"provider_params,omitempty"`

	// Scope is the effective permissions scope requested from the provider.
	// Uses the existing credentials.Scope type.
	Scope credentials.Scope `json:"scope"`

	// Destinations is the ordered list of delivery targets.
	// At least one entry is required.
	Destinations []DestinationSpec `json:"destinations"`

	// RotationPolicy controls rotation behaviour.
	RotationPolicy RotationPolicy `json:"rotation_policy"`

	// Metadata holds server-managed operational fields.
	Metadata BindingMetadata `json:"metadata"`
}

// DestinationSpec describes a single credential delivery target.
type DestinationSpec struct {
	// Kind is the destination plugin kind (e.g. "github-secret", "k8s-secret").
	// Validation: matches ^[a-z][a-z0-9-]{0,62}$
	Kind string `json:"kind"`

	// TargetID is the opaque kind-scoped identifier for the specific secret slot.
	// Format is kind-specific; see the destination plugin interface spec §7.3.
	// Examples: "owner/repo:SECRET_NAME", "namespace/secret:key".
	TargetID string `json:"target_id"`

	// Params holds kind-specific delivery parameters (visibility, namespace, etc.).
	Params map[string]any `json:"params,omitempty"`
}

// RotationPolicy controls when/how rotation occurs.
type RotationPolicy struct {
	// TTLHintSeconds is the desired credential lifetime in seconds.
	// Zero means "use provider default".
	TTLHintSeconds int64 `json:"ttl_hint_seconds,omitempty"`

	// ManualOnly flags this binding for manual-only rotation.
	// When true, the rotation orchestrator (T5) will not schedule automatic
	// rotation.  All OSS-tier bindings are manual-only.
	ManualOnly bool `json:"manual_only"`
}

// BindingMetadata holds server-managed operational fields written by the server,
// never by the client.
type BindingMetadata struct {
	// CreatedAt is the wall-clock time this binding was first registered (RFC 3339).
	CreatedAt string `json:"created_at"`

	// LastRotatedAt is the wall-clock time of the most recent successful
	// rotation (RFC 3339).  Empty until the first rotation completes.
	LastRotatedAt string `json:"last_rotated_at,omitempty"`

	// LastGeneration is the monotonically increasing rotation counter.
	// Zero until the first rotation.  Increments on each successful rotate.
	LastGeneration uint64 `json:"last_generation"`

	// Tags is a free-form list of labels for filtering.
	Tags []string `json:"tags,omitempty"`

	// LastCredentialUUID is the UUID of the most recently vended credential
	// for this binding. Used by the rotation orchestrator (Pro) to identify
	// which credential to revoke at the provider after the grace period.
	// Empty until the first successful rotation.
	LastCredentialUUID string `json:"last_credential_uuid,omitempty"`

	// BindingState reflects the operational state of the binding from the
	// rotation orchestrator's perspective. Possible values:
	//   "ok"             — last rotation succeeded against all destinations
	//   "degraded"       — last rotation partial-failure (some destinations live, some stale)
	//   "rotation_failed"— last rotation failed before any destination was updated
	//   ""               — no rotation has yet occurred (initial state for a fresh binding)
	//
	// Written by the Pro rotation orchestrator via SaveBindingMetadata.
	// Empty on bindings managed only by manual one-shot rotation.
	BindingState string `json:"binding_state,omitempty"`
}

// ── DestinationResult ─────────────────────────────────────────────────────────

// DestinationResult captures the per-destination outcome of a rotate call.
type DestinationResult struct {
	Kind        string `json:"kind"`
	TargetID    string `json:"target_id"`
	Success     bool   `json:"success"`
	IsTransient bool   `json:"is_transient,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ── BindingSummary ────────────────────────────────────────────────────────────

// BindingSummary is the lightweight shape returned by the list endpoint.
type BindingSummary struct {
	Name             string `json:"name"`
	ProviderKind     string `json:"provider_kind"`
	DestinationCount int    `json:"destination_count"`
	LastRotatedAt    string `json:"last_rotated_at,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// Summary returns a BindingSummary from the receiver.
func (b *CredentialBinding) Summary() BindingSummary {
	return BindingSummary{
		Name:             b.Name,
		ProviderKind:     b.ProviderKind,
		DestinationCount: len(b.Destinations),
		LastRotatedAt:    b.Metadata.LastRotatedAt,
		Tags:             b.Metadata.Tags,
	}
}

// ── Validation ────────────────────────────────────────────────────────────────

// ErrInvalidName is returned when the binding name does not match the required
// pattern.
var ErrInvalidName = errors.New("binding: name must match ^[a-z][a-z0-9-]{0,62}$")

// ErrMissingProviderKind is returned when provider_kind is empty.
var ErrMissingProviderKind = errors.New("binding: provider_kind is required")

// ErrNoDestinations is returned when the destinations list is empty.
var ErrNoDestinations = errors.New("binding: at least one destination is required")

// ErrInvalidDestination is returned when a destination entry fails validation.
var ErrInvalidDestination = errors.New("binding: invalid destination")

// Validate checks that the binding has all required fields in valid formats.
// It does NOT validate provider_params or destination.params contents (opaque).
func (b *CredentialBinding) Validate() error {
	if !namePattern.MatchString(b.Name) {
		return fmt.Errorf("%w: got %q", ErrInvalidName, b.Name)
	}
	if b.ProviderKind == "" {
		return ErrMissingProviderKind
	}
	if len(b.Destinations) == 0 {
		return ErrNoDestinations
	}
	for i, d := range b.Destinations {
		if !kindPattern.MatchString(d.Kind) {
			return fmt.Errorf("%w [%d]: kind %q must match ^[a-z][a-z0-9-]{0,62}$", ErrInvalidDestination, i, d.Kind)
		}
		if d.TargetID == "" {
			return fmt.Errorf("%w [%d]: target_id is required", ErrInvalidDestination, i)
		}
	}
	return nil
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// MarshalJSON returns the canonical JSON encoding of the binding.
func (b CredentialBinding) MarshalJSON() ([]byte, error) {
	type Alias CredentialBinding
	return json.Marshal((Alias)(b))
}

// UnmarshalJSON decodes the canonical JSON encoding of the binding.
func (b *CredentialBinding) UnmarshalJSON(data []byte) error {
	type Alias CredentialBinding
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*b = (CredentialBinding)(a)
	return nil
}

// ── BindingStore interface ─────────────────────────────────────────────────────

// BindingStore is the storage interface for credential bindings.
// All implementations must be safe for concurrent use.
type BindingStore interface {
	// Save creates or replaces the binding identified by b.Name.
	Save(ctx context.Context, b CredentialBinding) error

	// Get retrieves the binding by name.
	// Returns ErrNotFound if no binding with that name exists.
	Get(ctx context.Context, name string) (*CredentialBinding, error)

	// List returns all stored bindings.
	List(ctx context.Context) ([]CredentialBinding, error)

	// Delete removes the binding by name.
	// Returns ErrNotFound if no binding with that name exists.
	Delete(ctx context.Context, name string) error
}

// ErrNotFound is returned by BindingStore.Get and BindingStore.Delete when
// no binding with the given name exists.
var ErrNotFound = errors.New("binding: not found")

// ── KVBindingStore ────────────────────────────────────────────────────────────

// kvBindingStore implements BindingStore on top of a credentials.KVWriter.
//
// Storage layout (all paths in the shared EncryptedKV file):
//
//	bindings/<name>  →  {"binding": "<JSON of CredentialBinding>"}
//
// The "bindings/" prefix is structurally isolated from "kv/data/secrets/" and
// "kv/data/metadata/", so existing path-filtering logic is unaffected.
type kvBindingStore struct {
	kv credentials.KVWriter
}

const bindingsPrefix = "bindings/"

// NewKVBindingStore constructs a BindingStore backed by the given KVWriter.
func NewKVBindingStore(kv credentials.KVWriter) BindingStore {
	return &kvBindingStore{kv: kv}
}

func bindingKVPath(name string) string {
	return bindingsPrefix + name
}

func (s *kvBindingStore) Save(ctx context.Context, b CredentialBinding) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("binding store: marshal: %w", err)
	}
	return s.kv.SetSecret(ctx, bindingKVPath(b.Name), map[string]string{"binding": string(data)})
}

func (s *kvBindingStore) Get(ctx context.Context, name string) (*CredentialBinding, error) {
	fields, err := s.kv.GetSecret(ctx, bindingKVPath(name))
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("binding store: get %q: %w", name, err)
	}
	raw, ok := fields["binding"]
	if !ok {
		return nil, fmt.Errorf("binding store: corrupt record at %q: missing \"binding\" field", name)
	}
	var b CredentialBinding
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, fmt.Errorf("binding store: unmarshal %q: %w", name, err)
	}
	return &b, nil
}

func (s *kvBindingStore) List(ctx context.Context) ([]CredentialBinding, error) {
	paths, err := s.kv.ListPaths(ctx)
	if err != nil {
		return nil, fmt.Errorf("binding store: list paths: %w", err)
	}
	var out []CredentialBinding
	for _, p := range paths {
		if len(p) <= len(bindingsPrefix) {
			continue
		}
		if p[:len(bindingsPrefix)] != bindingsPrefix {
			continue
		}
		name := p[len(bindingsPrefix):]
		b, err := s.Get(ctx, name)
		if err != nil {
			continue // skip corrupt entries
		}
		out = append(out, *b)
	}
	return out, nil
}

func (s *kvBindingStore) Delete(ctx context.Context, name string) error {
	// Verify existence first so we can return ErrNotFound accurately.
	if _, err := s.Get(ctx, name); err != nil {
		return err
	}
	return s.kv.DeleteSecret(ctx, bindingKVPath(name))
}

// isNotFound returns true when err indicates a missing key.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// credentials.ErrCredentialNotFound carries "not found" in its message.
	return errors.Is(err, credentials.ErrCredentialNotFound) ||
		containsNotFound(err.Error())
}

func containsNotFound(s string) bool {
	return len(s) >= 9 && containsSubstring(s, "not found")
}

func containsSubstring(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ── NowFunc helper ────────────────────────────────────────────────────────────

// NowUTC returns the current time in UTC formatted as RFC 3339.
// Used by handlers to stamp metadata fields.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
