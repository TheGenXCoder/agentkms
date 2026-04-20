package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

const testWebhookSecret = "test-webhook-secret-key"

// validPayload returns a well-formed GitHub secret scanning webhook JSON body.
func validPayload() []byte {
	return []byte(`{
  "action": "created",
  "alert": {
    "number": 42,
    "secret_type": "github_personal_access_token",
    "secret": "ghp_ABCxyz123",
    "resolution": null
  },
  "repository": {
    "full_name": "acmecorp/legacy-tool"
  }
}`)
}

// signPayload generates a valid HMAC-SHA256 signature header for the given body.
func signPayload(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestGitHubWebhook_ParseAlert_ValidPayload(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := validPayload()
	sig := signPayload(body, testWebhookSecret)

	alert, err := handler.ParseAlert(body, sig)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if alert == nil {
		t.Fatal("expected non-nil alert, got nil")
	}
	if alert.SecretType != "github_personal_access_token" {
		t.Errorf("SecretType = %q, want %q", alert.SecretType, "github_personal_access_token")
	}
	if alert.AlertNumber != 42 {
		t.Errorf("AlertNumber = %d, want 42", alert.AlertNumber)
	}
	if alert.Repository != "acmecorp/legacy-tool" {
		t.Errorf("Repository = %q, want %q", alert.Repository, "acmecorp/legacy-tool")
	}
	if alert.TokenHash == "" {
		t.Error("TokenHash should not be empty")
	}
	if alert.DetectedAt.IsZero() {
		t.Error("DetectedAt should not be zero")
	}
	// DetectedAt should be recent (within last 5 seconds)
	if time.Since(alert.DetectedAt) > 5*time.Second {
		t.Errorf("DetectedAt = %v, expected recent time", alert.DetectedAt)
	}
}

func TestGitHubWebhook_ParseAlert_InvalidSignature(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := validPayload()
	wrongSig := signPayload(body, "wrong-secret")

	_, err := handler.ParseAlert(body, wrongSig)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
}

func TestGitHubWebhook_ParseAlert_MalformedJSON(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := []byte(`{not valid json!!!`)
	sig := signPayload(body, testWebhookSecret)

	_, err := handler.ParseAlert(body, sig)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestGitHubWebhook_ParseAlert_MissingSecret(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := []byte(`{
  "action": "created",
  "alert": {
    "number": 42,
    "secret_type": "github_personal_access_token",
    "resolution": null
  },
  "repository": {
    "full_name": "acmecorp/legacy-tool"
  }
}`)
	sig := signPayload(body, testWebhookSecret)

	_, err := handler.ParseAlert(body, sig)
	if err == nil {
		t.Fatal("expected error for missing secret field, got nil")
	}
}

func TestGitHubWebhook_ParseAlert_TokenHashCorrect(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := validPayload()
	sig := signPayload(body, testWebhookSecret)

	alert, err := handler.ParseAlert(body, sig)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if alert == nil {
		t.Fatal("expected non-nil alert, got nil")
	}

	expectedHash := sha256Hex("ghp_ABCxyz123")
	if alert.TokenHash != expectedHash {
		t.Errorf("TokenHash = %q, want SHA-256 of secret = %q", alert.TokenHash, expectedHash)
	}
}

func TestGitHubWebhook_ParseAlert_ExtractsRepository(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := []byte(`{
  "action": "created",
  "alert": {
    "number": 7,
    "secret_type": "slack_token",
    "secret": "xoxb-something",
    "resolution": null
  },
  "repository": {
    "full_name": "myorg/my-repo"
  }
}`)
	sig := signPayload(body, testWebhookSecret)

	alert, err := handler.ParseAlert(body, sig)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if alert == nil {
		t.Fatal("expected non-nil alert, got nil")
	}
	if alert.Repository != "myorg/my-repo" {
		t.Errorf("Repository = %q, want %q", alert.Repository, "myorg/my-repo")
	}
}

func TestGitHubWebhook_ParseAlert_EmptySignatureHeader(t *testing.T) {
	handler := NewGitHubWebhookHandler(testWebhookSecret)
	body := validPayload()

	_, err := handler.ParseAlert(body, "")
	if err == nil {
		t.Fatal("expected error for empty signature header, got nil")
	}
}
