package policy

import (
	"fmt"
	"os"

	// gopkg.in/yaml.v3: YAML parsing for the policy file format specified in
	// architecture §4.6 and backlog D-04.  No transitive dependencies.
	// No equivalent in the Go standard library.
	"gopkg.in/yaml.v3"
)

// LoadFromFile reads and parses the YAML policy file at path.
//
// Returns an error if:
//   - The file does not exist or cannot be read
//   - The file cannot be parsed as valid YAML
//   - The policy format version is not 1
//   - Any rule fails structural validation (empty ID, unknown effect, etc.)
//
// The returned *PolicyFile is ready to be passed to NewEngine.
func LoadFromFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %q: %w", path, err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse %q: %w", path, err)
	}

	if pf.Version != 1 {
		return nil, fmt.Errorf("policy: %q: unsupported version %d (only version 1 is supported)", path, pf.Version)
	}

	if err := validatePolicyFile(&pf); err != nil {
		return nil, fmt.Errorf("policy: %q: %w", path, err)
	}

	return &pf, nil
}

// DefaultDevPolicy returns a PolicyFile that allows the named developer
// identity to perform all operations on all keys.  It is written to disk by
// `agentkms-dev enroll` when no policy file exists yet.
func DefaultDevPolicy(callerID, teamID string) *PolicyFile {
	return &PolicyFile{
		Version:     1,
		Environment: "dev",
		Rules: []Rule{
			{
				ID:          "dev-default-allow",
				Description: fmt.Sprintf("Allow %s to perform all operations in local dev mode", callerID),
				Identities:  []string{callerID},
				Teams:       []string{teamID},
				Operations: []string{
					OperationSign,
					OperationEncrypt,
					OperationDecrypt,
					OperationCredentialVend,
					OperationCredRefresh,
					OperationListKeys,
					OperationRotateKey,
					OperationKeyCreate,
				},
				KeyPrefixes: []string{""},
				Effect:      EffectAllow,
			},
		},
	}
}

// MarshalYAML serialises a PolicyFile back to YAML bytes.
// Used by `agentkms-dev enroll` to write the default policy file.
func MarshalYAML(pf *PolicyFile) ([]byte, error) {
	out, err := yaml.Marshal(pf)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal: %w", err)
	}
	return out, nil
}

// ── Validation ────────────────────────────────────────────────────────────────

func validatePolicyFile(pf *PolicyFile) error {
	seen := make(map[string]bool, len(pf.Rules))
	for i, r := range pf.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule[%d]: id must not be empty", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule[%d]: duplicate rule id %q", i, r.ID)
		}
		seen[r.ID] = true

		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("rule %q: effect must be %q or %q, got %q", r.ID, EffectAllow, EffectDeny, r.Effect)
		}
		if len(r.Identities) == 0 {
			return fmt.Errorf("rule %q: identities must not be empty", r.ID)
		}
		if len(r.Teams) == 0 {
			return fmt.Errorf("rule %q: teams must not be empty", r.ID)
		}
		if len(r.Operations) == 0 {
			return fmt.Errorf("rule %q: operations must not be empty", r.ID)
		}
		if len(r.KeyPrefixes) == 0 {
			return fmt.Errorf("rule %q: key_prefixes must not be empty", r.ID)
		}
	}
	return nil
}
