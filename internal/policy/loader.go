package policy

// loader.go — P-02: Load a Policy from a local YAML file or byte slice.
//
// Dependency: gopkg.in/yaml.v3
// Justification: Go's standard library has no YAML support.  gopkg.in/yaml.v3
// is the canonical Go YAML library — widely audited, zero transitive
// dependencies of its own, and stable API.  It is used only here; all other
// policy package files import only the standard library.
//
// SECURITY NOTE: the loader calls Policy.Validate() after unmarshalling.
// A Policy that fails validation is never returned to the caller.  This
// prevents a malformed policy file from silently bypassing security controls
// by, for example, expressing an unknown effect value.
//
// Signed-bundle load path (Task 3): LoadPolicyFromPath prefers a verified
// policy.bundle.json (or an explicit .json path) when signatures are required
// or when a sibling bundle is present with a TrustStore. Unsigned YAML is only
// accepted when RequireSignature is false (dev escape hatch).

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig controls signature enforcement for policy load paths.
type LoadConfig struct {
	// RequireSignature, when true, rejects raw unsigned YAML. Production
	// default is true; local/dev may set false (AGENTKMS_POLICY_ALLOW_UNSIGNED).
	RequireSignature bool

	// Trust holds public keys used to verify signed bundles. Required when
	// RequireSignature is true or when loading a .json bundle path.
	Trust *TrustStore
}

// LoadFromFile reads and parses a YAML policy file at the given path.
// The file must be readable and contain a valid policy document.
//
// Returns an error if the file cannot be read, the YAML is malformed, or
// Policy.Validate() reports structural problems.
func LoadFromFile(path string) (*Policy, error) {
	f, err := os.Open(path) // #nosec G304 — path is caller-supplied; callers must sanitise
	if err != nil {
		return nil, fmt.Errorf("policy: opening file %q: %w", path, err)
	}
	defer f.Close()

	p, err := LoadFromReader(f)
	if err != nil {
		// Wrap with the file path so the caller knows which file failed.
		return nil, fmt.Errorf("policy: loading %q: %w", path, err)
	}
	return p, nil
}

// LoadFromBytes parses a YAML policy document from a byte slice.
// Returns an error if the YAML is malformed, contains unknown fields,
// or validation fails.
//
// SECURITY: KnownFields(true) is set on the decoder so that any unknown or
// misspelled YAML key is rejected with an error rather than silently
// discarded.  Without this, a typo in a field name (e.g. "matche" instead
// of "match") would cause that dimension to silently fall back to its
// zero value — which is "match everything" — potentially widening a rule
// far beyond the author's intent.
func LoadFromBytes(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: unmarshalling YAML: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFromReader parses a YAML policy document from r.
// Returns an error if reading fails, the YAML is malformed, or validation
// fails.
func LoadFromReader(r io.Reader) (*Policy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("policy: reading policy data: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadPolicyFromPath loads policy with signed-bundle preference:
//
//  1. If path ends in .json, treat it as a Bundle envelope and verify.
//  2. If a sibling policy.bundle.json exists next to a .yaml/.yml path, verify
//     and load that bundle (preferred over raw YAML).
//  3. If RequireSignature is true, raw YAML alone is rejected.
//  4. If RequireSignature is false, fall through to LoadFromFile (dev path).
//
// Fail-closed: a present but invalid bundle never falls through to unsigned YAML.
func LoadPolicyFromPath(path string, cfg LoadConfig) (*Policy, error) {
	if path == "" {
		return nil, fmt.Errorf("policy: empty policy path")
	}

	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".json") {
		return loadVerifiedBundleFile(path, cfg.Trust)
	}

	// Prefer sibling policy.bundle.json when present.
	if bundlePath := siblingBundlePath(path); bundlePath != "" {
		if st, err := os.Stat(bundlePath); err == nil && !st.IsDir() {
			return loadVerifiedBundleFile(bundlePath, cfg.Trust)
		}
	}

	if cfg.RequireSignature {
		hint := siblingBundlePath(path)
		if hint == "" {
			hint = "policy.bundle.json"
		}
		return nil, fmt.Errorf("policy: unsigned YAML at %q rejected (signature required); provide a signed bundle at %q", path, hint)
	}
	return LoadFromFile(path)
}

// siblingBundlePath returns the preferred signed-bundle path next to a YAML
// policy file: <dir>/policy.bundle.json.
func siblingBundlePath(yamlPath string) string {
	dir := filepath.Dir(yamlPath)
	if dir == "" || dir == "." {
		return "policy.bundle.json"
	}
	return filepath.Join(dir, "policy.bundle.json")
}

func loadVerifiedBundleFile(path string, trust *TrustStore) (*Policy, error) {
	if trust == nil || trust.Len() == 0 {
		return nil, fmt.Errorf("policy: cannot verify bundle %q: no trust keys configured", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 — path is caller-supplied config
	if err != nil {
		return nil, fmt.Errorf("policy: reading bundle %q: %w", path, err)
	}
	p, err := ParseAndVerify(data, trust)
	if err != nil {
		return nil, fmt.Errorf("policy: verifying bundle %q: %w", path, err)
	}
	return p, nil
}
