// Package policy implements the AgentKMS policy engine.
//
// Every operation is evaluated against policy before it reaches the Backend.
// The engine is deny-by-default: an empty policy denies ALL operations.
// Policy dimensions: identity, key scope, operation type, rate, time window.
//
// Backlog: P-01 to P-08.
package policy

// EffectAllow is the policy rule effect that permits an operation.
const EffectAllow = "allow"

// EffectDeny is the policy rule effect that explicitly denies an operation.
const EffectDeny = "deny"

// Operation constants — must match audit.Operation* values.
// Duplicated here to avoid a circular import between audit ↔ policy.
const (
	OperationSign           = "sign"
	OperationEncrypt        = "encrypt"
	OperationDecrypt        = "decrypt"
	OperationCredentialVend = "credential_vend"
	OperationCredRefresh    = "credential_refresh"
	OperationListKeys       = "list_keys"
	OperationRotateKey      = "rotate_key"
	OperationKeyCreate      = "key_create"
)

// Rule defines a single policy entry.
//
// Evaluation model: first-match-wins (firewall semantics).
// Rules are evaluated in declaration order.  The first rule that matches all
// four dimensions (identity, team, operation, key prefix) has its Effect
// applied.  If no rule matches, the request is denied by default.
//
// Wildcards:
//   - "*" in Identities, Teams, or Operations matches any value.
//   - ""  in KeyPrefixes is a prefix that matches ALL key IDs (the empty
//     string is a prefix of every string).  "*" also matches all key IDs.
type Rule struct {
	// ID uniquely identifies this rule within the policy file.  Required.
	ID string `yaml:"id"`

	// Description is a human-readable explanation of the rule's purpose.
	Description string `yaml:"description,omitempty"`

	// Identities is the list of CallerIDs this rule applies to.
	// Use "*" to match any caller.
	Identities []string `yaml:"identities"`

	// Teams is the list of TeamIDs this rule applies to.
	// Use "*" to match any team.
	Teams []string `yaml:"teams"`

	// Operations is the list of operation names this rule applies to.
	// Use "*" to match any operation.
	// Valid values: "sign", "encrypt", "decrypt", "credential_vend",
	//   "credential_refresh", "list_keys", "rotate_key", "key_create".
	Operations []string `yaml:"operations"`

	// KeyPrefixes is the list of key ID prefixes this rule applies to.
	// A key is matched if its ID starts with any listed prefix.
	// Use "" or "*" to match all key IDs.
	KeyPrefixes []string `yaml:"key_prefixes"`

	// Effect is the action to take when this rule matches.
	// Valid values: "allow", "deny".  Required.
	Effect string `yaml:"effect"`
}

// PolicyFile is the top-level structure of a YAML policy file.
// See architecture §4.5 and backlog P-01, D-04.
//
// Example (minimal dev policy that allows the enrolled developer to do
// everything on all keys):
//
//	version: 1
//	environment: dev
//	rules:
//	  - id: dev-allow-all
//	    identities: ["*"]
//	    teams: ["*"]
//	    operations: ["*"]
//	    key_prefixes: [""]
//	    effect: "allow"
type PolicyFile struct {
	// Version is the policy file format version.  Currently only 1 is valid.
	Version int `yaml:"version"`

	// Environment is the target deployment tier: "dev", "staging", "production".
	// Informational only; not enforced by the engine.
	Environment string `yaml:"environment"`

	// Rules is the ordered list of policy rules.
	// Evaluated in declaration order; first match wins.
	Rules []Rule `yaml:"rules"`
}
