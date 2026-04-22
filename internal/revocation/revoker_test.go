package revocation_test

// revoker_test.go — Failing unit tests for per-provider Revoker implementations.
//
// These tests define the contract for each concrete Revoker:
//
//   GitHubPATRevoker  — calls GitHub's token revocation endpoint; handles 204,
//                       404 (idempotent), and network errors.
//   AWSSTSRevoker     — always returns ErrRevocationUnsupported; SupportsRevocation()=false.
//   NoopRevoker       — always returns ErrRevocationUnsupported; SupportsRevocation()=false.
//
// All tests MUST fail until the revocation package is implemented.
// Do NOT write implementation code — that is the implementation agent's job.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/revocation"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// sampleRecord returns a representative CredentialRecord for tests.
func sampleRecord(credType string) revocation.CredentialRecord {
	return revocation.CredentialRecord{
		CredentialUUID:    "550e8400-e29b-41d4-a716-446655440010",
		ProviderTokenHash: "aabbcc112233445566778899aabbcc112233445566778899aabbcc1122334455",
		CredentialType:    credType,
		IssuedAt:          time.Now().Add(-2 * time.Hour),
		InvalidatedAt:     time.Time{}, // still live
		CallerID:          "frank@acmecorp",
		RuleID:            "rule-gh-001",
	}
}

// ── GitHubPATRevoker tests ────────────────────────────────────────────────────

// TestGitHubPATRevoker_SupportsRevocation verifies the capability flag is true.
func TestGitHubPATRevoker_SupportsRevocation(t *testing.T) {
	r := revocation.NewGitHubPATRevoker("https://api.github.com", http.DefaultClient)
	if !r.SupportsRevocation() {
		t.Error("GitHubPATRevoker.SupportsRevocation() should return true")
	}
}

// TestGitHubPATRevoker_Revoke_Success verifies that a 204 from the GitHub API
// maps to RevokeResult{Revoked: true}.
func TestGitHubPATRevoker_Revoke_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GitHub fine-grained PAT revocation: DELETE /installation/token
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent) // 204 = revoked
	}))
	defer srv.Close()

	revoker := revocation.NewGitHubPATRevoker(srv.URL, srv.Client())
	record := sampleRecord("github-pat")

	result, err := revoker.Revoke(context.Background(), record)
	if err != nil {
		t.Fatalf("Revoke returned unexpected error: %v", err)
	}
	if !result.Revoked {
		t.Error("RevokeResult.Revoked should be true on 204 response")
	}
}

// TestGitHubPATRevoker_Revoke_Idempotent verifies that a 404 (already revoked
// or never existed) does not return an error — revocation is idempotent.
func TestGitHubPATRevoker_Revoke_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // 404 = token already gone
	}))
	defer srv.Close()

	revoker := revocation.NewGitHubPATRevoker(srv.URL, srv.Client())
	record := sampleRecord("github-pat")

	result, err := revoker.Revoke(context.Background(), record)
	if err != nil {
		t.Fatalf("Revoke should not error on 404 (idempotent): %v", err)
	}
	// Revoked = true because the token is gone either way.
	if !result.Revoked {
		t.Error("RevokeResult.Revoked should be true when token is already gone (404)")
	}
}

// TestGitHubPATRevoker_Revoke_APIError verifies that a 5xx from GitHub
// surfaces as a non-nil ProviderError in the result.
func TestGitHubPATRevoker_Revoke_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	revoker := revocation.NewGitHubPATRevoker(srv.URL, srv.Client())
	record := sampleRecord("github-pat")

	result, err := revoker.Revoke(context.Background(), record)
	// Revoke itself should not return a fatal err — it populates ProviderError.
	_ = err
	if result.Revoked {
		t.Error("RevokeResult.Revoked should be false on 5xx")
	}
	if result.ProviderError == nil {
		t.Error("RevokeResult.ProviderError should be set on 5xx from provider")
	}
}

// TestGitHubPATRevoker_Revoke_NetworkFailure verifies that a connection
// refusal surfaces in ProviderError without panicking.
func TestGitHubPATRevoker_Revoke_NetworkFailure(t *testing.T) {
	// Point at a port that is not listening.
	revoker := revocation.NewGitHubPATRevoker("http://127.0.0.1:1", http.DefaultClient)
	record := sampleRecord("github-pat")

	result, err := revoker.Revoke(context.Background(), record)
	_ = err
	if result.Revoked {
		t.Error("RevokeResult.Revoked should be false on network failure")
	}
	if result.ProviderError == nil {
		t.Error("RevokeResult.ProviderError should be set on network failure")
	}
}

// TestGitHubPATRevoker_Revoke_RequestHasAuthHeader verifies that the HTTP
// request sent to GitHub includes an Authorization header.
func TestGitHubPATRevoker_Revoke_RequestHasAuthHeader(t *testing.T) {
	var capturedAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	revoker := revocation.NewGitHubPATRevoker(srv.URL, srv.Client())
	record := sampleRecord("github-pat")

	_, err := revoker.Revoke(context.Background(), record)
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}
	if capturedAuthHeader == "" {
		t.Error("request to GitHub should include Authorization header")
	}
}

// ── AWSSTSRevoker tests ───────────────────────────────────────────────────────

// TestAWSSTSRevoker_SupportsRevocation verifies the capability flag is false.
func TestAWSSTSRevoker_SupportsRevocation(t *testing.T) {
	r := revocation.NewAWSSTSRevoker()
	if r.SupportsRevocation() {
		t.Error("AWSSTSRevoker.SupportsRevocation() should return false")
	}
}

// TestAWSSTSRevoker_Revoke_ReturnsUnsupported verifies that calling Revoke
// returns ErrRevocationUnsupported and never makes an HTTP call.
func TestAWSSTSRevoker_Revoke_ReturnsUnsupported(t *testing.T) {
	r := revocation.NewAWSSTSRevoker()
	record := sampleRecord("aws-sts")

	_, err := r.Revoke(context.Background(), record)
	if !errors.Is(err, revocation.ErrRevocationUnsupported) {
		t.Errorf("error = %v, want ErrRevocationUnsupported", err)
	}
}

// TestAWSSTSRevoker_Revoke_RevokedIsFalse verifies RevokeResult.Revoked is false.
func TestAWSSTSRevoker_Revoke_RevokedIsFalse(t *testing.T) {
	r := revocation.NewAWSSTSRevoker()
	record := sampleRecord("aws-sts")

	result, _ := r.Revoke(context.Background(), record)
	if result.Revoked {
		t.Error("AWSSTSRevoker should never set Revoked=true")
	}
}

// ── NoopRevoker tests ─────────────────────────────────────────────────────────

// TestNoopRevoker_SupportsRevocation verifies the capability flag is false.
func TestNoopRevoker_SupportsRevocation(t *testing.T) {
	r := revocation.NewNoopRevoker()
	if r.SupportsRevocation() {
		t.Error("NoopRevoker.SupportsRevocation() should return false")
	}
}

// TestNoopRevoker_Revoke_ReturnsUnsupported verifies ErrRevocationUnsupported.
func TestNoopRevoker_Revoke_ReturnsUnsupported(t *testing.T) {
	r := revocation.NewNoopRevoker()
	record := sampleRecord("slack-webhook")

	_, err := r.Revoke(context.Background(), record)
	if !errors.Is(err, revocation.ErrRevocationUnsupported) {
		t.Errorf("error = %v, want ErrRevocationUnsupported", err)
	}
}

// ── RevokerRegistry tests ─────────────────────────────────────────────────────

// TestRevokerRegistry_GitHubPAT_Dispatches verifies the registry returns a
// GitHubPATRevoker for CredentialType "github-pat".
func TestRevokerRegistry_GitHubPAT_Dispatches(t *testing.T) {
	reg := revocation.NewDefaultRegistry()
	r := reg.For("github-pat")
	if !r.SupportsRevocation() {
		t.Error("registry should return a revoker that SupportsRevocation for github-pat")
	}
}

// TestRevokerRegistry_AWSSTS_Dispatches verifies the registry returns an
// AWSSTSRevoker (no revocation support) for "aws-sts".
func TestRevokerRegistry_AWSSTS_Dispatches(t *testing.T) {
	reg := revocation.NewDefaultRegistry()
	r := reg.For("aws-sts")
	if r.SupportsRevocation() {
		t.Error("registry should return a revoker with SupportsRevocation=false for aws-sts")
	}
}

// TestRevokerRegistry_Unknown_FallsBackToNoop verifies the registry returns a
// NoopRevoker for an unrecognised credential type.
func TestRevokerRegistry_Unknown_FallsBackToNoop(t *testing.T) {
	reg := revocation.NewDefaultRegistry()
	r := reg.For("some-unknown-provider-xyz")
	if r == nil {
		t.Fatal("registry should never return nil")
	}
	if r.SupportsRevocation() {
		t.Error("unknown credential type should fall back to NoopRevoker (SupportsRevocation=false)")
	}
}
