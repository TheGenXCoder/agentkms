// Package githubapp provides server-side storage and retrieval of GitHub App
// configurations. Each App is identified by a human-friendly name and stores
// the App ID, Installation ID, and RSA private key PEM bytes.
//
// SECURITY: Private key PEM bytes are stored encrypted via the existing KV
// layer (EncryptedKV / OpenBaoKV). They are NEVER written to the filesystem by
// any AgentKMS code path, and NEVER appear in audit log fields.
//
// KV path layout:
//
//	github-apps/<name>  →  {"app_id":"<int>", "installation_id":"<int>", "private_key_pem":"<pem>"}
package githubapp

// GithubApp is the complete, server-side representation of a registered
// GitHub App. All fields are required.
type GithubApp struct {
	// Name is the human-friendly identifier (e.g. "agentkms-blog-audit-rotator").
	Name string

	// AppID is the GitHub App ID visible in the GitHub App settings page.
	AppID int64

	// InstallationID is the installation ID for the target account/organisation.
	InstallationID int64

	// PrivateKeyPEM contains the RSA private key PEM bytes used to mint
	// short-lived GitHub App installation tokens.
	//
	// SECURITY: these bytes MUST NOT appear in any audit log field, HTTP
	// response to external callers, or log line. They are only forwarded to
	// the GitHub plugin via the in-process gRPC broker.
	PrivateKeyPEM []byte
}

// Summary is a redacted view of GithubApp suitable for list and inspect
// responses that must never expose the private key.
type Summary struct {
	Name           string `json:"name"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
}
