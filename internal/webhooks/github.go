package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
	orchestrator  *AlertOrchestrator
}

// NewGitHubWebhookHandler creates a new handler with the given webhook secret
// used for HMAC-SHA256 signature validation.
func NewGitHubWebhookHandler(webhookSecret string) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{webhookSecret: webhookSecret}
}

// githubWebhookPayload represents the JSON structure of a GitHub secret scanning webhook.
type githubWebhookPayload struct {
	Action string `json:"action"`
	Alert  struct {
		Number     int    `json:"number"`
		SecretType string `json:"secret_type"`
		Secret     string `json:"secret"`
	} `json:"alert"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// ParseAlert parses and validates a GitHub secret scanning webhook payload.
// Returns error if signature is invalid or payload is malformed.
func (h *GitHubWebhookHandler) ParseAlert(body []byte, signatureHeader string) (*GitHubSecretAlert, error) {
	// Validate signature header is present
	if signatureHeader == "" {
		return nil, errors.New("empty signature header")
	}

	// Validate signature format
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return nil, fmt.Errorf("malformed signature header: missing sha256= prefix")
	}

	// Extract hex signature
	sigHex := strings.TrimPrefix(signatureHeader, "sha256=")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("malformed signature header: invalid hex: %w", err)
	}

	// Compute expected HMAC
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(sigBytes, expectedMAC) != 1 {
		return nil, errors.New("signature verification failed")
	}

	// Parse JSON payload
	var payload githubWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JSON payload: %w", err)
	}

	// Validate required field
	if payload.Alert.Secret == "" {
		return nil, errors.New("alert.secret is missing or empty")
	}

	// Compute token hash
	tokenHashBytes := sha256.Sum256([]byte(payload.Alert.Secret))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	return &GitHubSecretAlert{
		TokenHash:   tokenHash,
		SecretType:  payload.Alert.SecretType,
		Repository:  payload.Repository.FullName,
		AlertNumber: payload.Alert.Number,
		DetectedAt:  time.Now().UTC(),
	}, nil
}
