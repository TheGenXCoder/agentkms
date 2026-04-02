package api

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/agentkms/agentkms/internal/backend"
)

const (
	// maxKeyIDLength is the maximum permitted length of a key identifier.
	// Key IDs are path-like strings (e.g., "payments/signing-key") stored
	// in the backend index; an upper bound prevents abuse.
	maxKeyIDLength = 256

	// maxRequestBodyBytes is the maximum accepted HTTP request body size.
	// Sign/encrypt/decrypt requests are compact JSON; 1 MB is generous.
	maxRequestBodyBytes = 1 << 20 // 1 MiB
)

// isValidKeyID reports whether keyID is a well-formed AgentKMS key identifier.
//
// Valid key IDs:
//   - Non-empty, at most maxKeyIDLength bytes.
//   - One or more path segments separated by forward slashes.
//   - Each segment: one or more lowercase letters, digits, hyphens, or
//     underscores.  No empty segments, no "." or ".." segments.
//   - No leading or trailing slash.
//
// Examples of valid IDs: "payments/signing-key", "ml/model-v2", "audit/key".
// Examples of invalid IDs: "", "/payments", "payments/", "../secret",
// "Payments/Key" (uppercase).
func isValidKeyID(keyID string) bool {
	if keyID == "" || len(keyID) > maxKeyIDLength {
		return false
	}
	parts := strings.Split(keyID, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !isValidKeyIDRune(c) {
				return false
			}
		}
	}
	return true
}

// isValidKeyIDRune reports whether c is a permitted character inside a key ID
// path segment.
func isValidKeyIDRune(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}

// parsePayloadHash validates and decodes a payload_hash field.
//
// The accepted format is: "sha256:<64 lowercase hex characters>".
// The returned byte slice is exactly 32 bytes (the raw SHA-256 digest).
//
// SECURITY: This function only decodes and validates the format.  It does not
// log or echo the hash value in any error message to prevent accumulation of
// payload fingerprints in server-side logs.
func parsePayloadHash(s string) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return nil, errors.New("payload_hash must start with \"sha256:\"")
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return nil, fmt.Errorf(
			"payload_hash hex digest must be 64 characters (32 bytes), got %d characters",
			len(hexPart),
		)
	}
	b, err := hex.DecodeString(hexPart)
	if err != nil {
		// Do not include the bad input in the error: it might be large or
		// contain characters that are confusing in logs.
		return nil, errors.New("payload_hash contains invalid hexadecimal characters")
	}
	return b, nil
}

// isValidTeamID reports whether teamID is a well-formed team identifier.
//
// Valid team IDs consist of one or more lowercase letters, digits, hyphens,
// or underscores.  Maximum length: 128 bytes.  Same character rules as a
// single key ID path segment.
func isValidTeamID(teamID string) bool {
	if teamID == "" || len(teamID) > 128 {
		return false
	}
	for _, c := range teamID {
		if !isValidKeyIDRune(c) {
			return false
		}
	}
	return true
}

// isValidSigningAlgorithm reports whether alg is a recognised signing
// algorithm supported by the Backend interface.
func isValidSigningAlgorithm(alg string) bool {
	switch backend.Algorithm(alg) {
	case backend.AlgorithmES256, backend.AlgorithmRS256, backend.AlgorithmEdDSA:
		return true
	}
	return false
}
