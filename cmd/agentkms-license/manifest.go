// Package main implements the agentkms-license issuance CLI.
//
// manifest.go defines the canonical LicenseManifest struct, JSON
// marshaling/unmarshaling helpers, and the two-line license file
// encode/decode functions.
//
// File format (§3.2 of the design spec) is byte-precise:
//
//	<base64url-no-pad(manifestJSON)>\n<base64url-no-pad(signature)>\n
//
// The bytes signed are the raw UTF-8 manifest JSON (the same bytes
// that are base64url-encoded into line 1).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxLicenseFileBytes is the hard cap enforced by DecodeFile to prevent
// memory exhaustion from a malformed or malicious input (spec §3.2).
const maxLicenseFileBytes = 4 * 1024 // 4 KB

// LicenseManifest is the canonical representation of a signed license.
// Field order matches the spec §3.1 canonical JSON serialization order;
// encoding/json honors struct field declaration order when marshaling.
type LicenseManifest struct {
	LicenseID     string    `json:"license_id"`
	Customer      string    `json:"customer"`
	Email         string    `json:"email"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Features      []string  `json:"features"`
	SchemaVersion int       `json:"schema_version"`
}

// marshaledManifest is a private type used during JSON marshaling to produce
// RFC 3339 UTC timestamps (always ending in Z) without custom MarshalJSON on
// the public struct.
type marshaledManifest struct {
	LicenseID     string   `json:"license_id"`
	Customer      string   `json:"customer"`
	Email         string   `json:"email"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	Features      []string `json:"features"`
	SchemaVersion int      `json:"schema_version"`
}

// MarshalManifest serializes m to canonical JSON per spec §3.1:
//   - No whitespace outside string values
//   - RFC 3339 UTC timestamps ending in Z
//   - Field order: license_id, customer, email, issued_at, expires_at, features, schema_version
//
// A round-trip parse is performed after serialization to catch any encoding
// anomaly before the bytes are signed.
func MarshalManifest(m LicenseManifest) ([]byte, error) {
	wire := marshaledManifest{
		LicenseID:     m.LicenseID,
		Customer:      m.Customer,
		Email:         m.Email,
		IssuedAt:      m.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     m.ExpiresAt.UTC().Format(time.RFC3339),
		Features:      m.Features,
		SchemaVersion: m.SchemaVersion,
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	// Mandatory round-trip self-check (spec §3.1).
	var check marshaledManifest
	if err := json.Unmarshal(b, &check); err != nil {
		return nil, fmt.Errorf("manifest self-check parse failed: %w", err)
	}
	return b, nil
}

// UnmarshalManifest parses JSON-encoded manifest bytes into a LicenseManifest.
func UnmarshalManifest(data []byte) (LicenseManifest, error) {
	var wire marshaledManifest
	if err := json.Unmarshal(data, &wire); err != nil {
		return LicenseManifest{}, fmt.Errorf("unmarshal manifest: %w", err)
	}
	issuedAt, err := time.Parse(time.RFC3339, wire.IssuedAt)
	if err != nil {
		return LicenseManifest{}, fmt.Errorf("parse issued_at %q: %w", wire.IssuedAt, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, wire.ExpiresAt)
	if err != nil {
		return LicenseManifest{}, fmt.Errorf("parse expires_at %q: %w", wire.ExpiresAt, err)
	}
	return LicenseManifest{
		LicenseID:     wire.LicenseID,
		Customer:      wire.Customer,
		Email:         wire.Email,
		IssuedAt:      issuedAt.UTC(),
		ExpiresAt:     expiresAt.UTC(),
		Features:      wire.Features,
		SchemaVersion: wire.SchemaVersion,
	}, nil
}

// b64url is the base64url encoding without padding, per RFC 4648 §5.
var b64url = base64.RawURLEncoding

// EncodeFile produces the two-line license file content:
//
//	<base64url-no-pad(manifestJSON)>\n<base64url-no-pad(signature)>\n
//
// Both lines use base64url without padding per spec §3.2.
func EncodeFile(manifestBytes []byte, signature []byte) []byte {
	line1 := b64url.EncodeToString(manifestBytes)
	line2 := b64url.EncodeToString(signature)
	return []byte(line1 + "\n" + line2 + "\n")
}

// DecodeFile parses the two-line license file format.
// Returns:
//   - manifest:      parsed LicenseManifest
//   - signatureBytes: raw Ed25519 signature (64 bytes)
//   - manifestBytes:  raw UTF-8 manifest JSON (the bytes that were signed)
//   - error
//
// Enforces the 4 KB hard cap (spec §3.2).
func DecodeFile(data []byte) (manifest LicenseManifest, signatureBytes []byte, manifestBytes []byte, err error) {
	if len(data) > maxLicenseFileBytes {
		return LicenseManifest{}, nil, nil,
			fmt.Errorf("license file exceeds 4 KB limit (%d bytes)", len(data))
	}

	// Strip a single trailing newline if present, then split on the separator.
	// The canonical format is LINE1\nLINE2\n, so after stripping the trailing
	// newline we get LINE1\nLINE2 and exactly one internal newline.
	content := string(data)
	content = strings.TrimRight(content, "\n")
	parts := strings.Split(content, "\n")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return LicenseManifest{}, nil, nil,
			fmt.Errorf("invalid license format: expected exactly 2 non-empty lines, got %d", countNonEmpty(parts))
	}

	manifestBytes, err = b64url.DecodeString(parts[0])
	if err != nil {
		return LicenseManifest{}, nil, nil,
			fmt.Errorf("base64url decode manifest line: %w", err)
	}

	signatureBytes, err = b64url.DecodeString(parts[1])
	if err != nil {
		return LicenseManifest{}, nil, nil,
			fmt.Errorf("base64url decode signature line: %w", err)
	}

	manifest, err = UnmarshalManifest(manifestBytes)
	if err != nil {
		return LicenseManifest{}, nil, nil, err
	}

	return manifest, signatureBytes, manifestBytes, nil
}

// countNonEmpty counts non-empty strings in a slice, used for error messages.
func countNonEmpty(parts []string) int {
	n := 0
	for _, p := range parts {
		if p != "" {
			n++
		}
	}
	return n
}
