package webhooks

import "time"

// GitHubSecretAlert represents a parsed GitHub secret scanning webhook alert.
type GitHubSecretAlert struct {
	TokenHash   string    // SHA-256 of the leaked secret
	SecretType  string    // e.g., "github_personal_access_token"
	Repository  string    // e.g., "acmecorp/legacy-tool"
	AlertNumber int
	DetectedAt  time.Time
}

// GitHubWebhookHandler handles GitHub secret scanning webhook payloads.
type GitHubWebhookHandler struct {
	webhookSecret string
}

// NewGitHubWebhookHandler creates a new handler with the given webhook secret
// used for HMAC-SHA256 signature validation.
func NewGitHubWebhookHandler(webhookSecret string) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{webhookSecret: webhookSecret}
}

// ParseAlert parses and validates a GitHub secret scanning webhook payload.
// Returns error if signature is invalid or payload is malformed.
func (h *GitHubWebhookHandler) ParseAlert(body []byte, signatureHeader string) (*GitHubSecretAlert, error) {
	return nil, nil
}
