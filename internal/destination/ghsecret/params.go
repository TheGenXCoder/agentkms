// Package ghsecret implements the destination plugin for GitHub Actions
// repository secrets.
//
// # Target identifier format
//
// target_id must be of the form "owner/repo:SECRET_NAME". The colon separates
// the repository path from the GitHub secret name. For example:
//
//	my-org/my-repo:DATABASE_URL
//
// Organization-level secrets are not supported in v1. An attempt to target an
// org secret will receive a 404 from GitHub (TARGET_NOT_FOUND).
//
// # Authentication
//
// params["writer_token"] must contain a GitHub Personal Access Token (PAT)
// or a GitHub App installation access token with secrets:write permission on
// the target repository. The token is passed as-is in the Authorization header
// and is never logged.
//
// # Encryption
//
// GitHub Actions secrets use libsodium sealed-box encryption (Curve25519 +
// XSalsa20-Poly1305). This plugin uses golang.org/x/crypto/nacl/box.SealAnonymous
// — a pure-Go, CGo-free implementation that is interoperable with libsodium.
// No new dependencies are required; golang.org/x/crypto is already in go.mod.
package ghsecret

import "fmt"

// params holds the typed, validated parameters for a single GitHub Secret
// delivery operation. Constructed by parseParams from the raw map[string]any.
type params struct {
	// writerToken is the GitHub PAT or installation token with secrets:write
	// permission on the target repository. SECURITY: never log this field.
	writerToken string
}

// parseParams extracts and validates the typed parameters from the raw params
// map passed in DeliverRequest.Params or ValidateDestinationRequest.Params.
//
// Returns a permanent error if required fields are absent or invalid.
func parseParams(raw map[string]any) (params, error) {
	var p params

	tok, ok := raw["writer_token"]
	if !ok {
		return p, fmt.Errorf("ghsecret: [permanent] missing required param \"writer_token\"")
	}
	tokStr, ok := tok.(string)
	if !ok || tokStr == "" {
		return p, fmt.Errorf("ghsecret: [permanent] param \"writer_token\" must be a non-empty string")
	}
	p.writerToken = tokStr
	return p, nil
}
