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

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

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
