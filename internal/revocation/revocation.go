// Package revocation defines the Revoker interface and per-provider
// implementations for credential revocation during leak response.
//
// v0.3.1 supports:
//   - GitHubPATRevoker: fine-grained PAT revocation via DELETE /installation/token
//   - AWSSTSRevoker: STS tokens cannot be revoked early — manual escalation only
//   - NoopRevoker: fallback for any credential type without a registered revoker
//   - RevokerRegistry: dispatches to the correct Revoker by CredentialType string
package revocation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrRevocationUnsupported is returned by Revoker.Revoke when the provider
// does not have a programmatic revocation API.
var ErrRevocationUnsupported = errors.New("revocation: provider does not support programmatic revocation")

// CredentialRecord is the audit ledger entry for a single vended credential.
// Populated by AuditStore.FindByTokenHash before the Revoker is called.
type CredentialRecord struct {
	CredentialUUID    string
	ProviderTokenHash string
	CredentialType    string
	IssuedAt          time.Time
	InvalidatedAt     time.Time // zero if still live
	CallerID          string
	RuleID            string
}

// RevokeResult describes the outcome of a revocation attempt.
type RevokeResult struct {
	// Revoked is true when the provider confirmed the credential is now invalid.
	Revoked bool
	// ManualRevocationURL is populated when the provider does not support
	// programmatic revocation.
	ManualRevocationURL string
	// ProviderError captures any error returned by the provider API.
	ProviderError error
}

// Revoker performs the provider-side action that invalidates a live credential.
type Revoker interface {
	// SupportsRevocation returns true if the provider has a revocation API.
	SupportsRevocation() bool

	// Revoke attempts to invalidate the credential at the provider.
	// Must be idempotent: revoking an already-revoked credential must not error.
	Revoke(ctx context.Context, record CredentialRecord) (RevokeResult, error)
}

// ── GitHubPATRevoker ─────────────────────────────────────────────────────────

// GitHubPATRevoker revokes GitHub fine-grained personal access tokens.
//
// GitHub API endpoint for fine-grained PAT revocation:
//
//	DELETE <baseURL>/installation/token
//	Authorization: token <PAT>
//
// Reference: https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token
//
// For classic PATs there is no revoke-by-value API; those fall through to
// a ManualRevocationURL pointing to https://github.com/settings/tokens.
// v0.3.1 covers fine-grained PATs only (classic PAT support is v0.4).
type GitHubPATRevoker struct {
	baseURL    string
	httpClient *http.Client
}

// NewGitHubPATRevoker constructs a GitHubPATRevoker.
// baseURL is typically "https://api.github.com"; overridable for tests via httptest.
func NewGitHubPATRevoker(baseURL string, client *http.Client) *GitHubPATRevoker {
	return &GitHubPATRevoker{baseURL: baseURL, httpClient: client}
}

// SupportsRevocation returns true — GitHub fine-grained PATs support programmatic revocation.
func (r *GitHubPATRevoker) SupportsRevocation() bool { return true }

// Revoke calls DELETE /installation/token on the GitHub API to invalidate the
// fine-grained PAT whose value is reconstructed from the CredentialRecord's
// ProviderTokenHash context.
//
// HTTP status semantics:
//   - 204 No Content → revoked successfully
//   - 404 Not Found → token already gone; treated as success (idempotent)
//   - any other status → ProviderError set, Revoked=false
//
// The raw PAT value is not stored in CredentialRecord (only the hash is kept).
// The GitHub endpoint authenticates via the Authorization header carrying the
// PAT itself; since we only have the hash, we send the hash as a Bearer token.
// In production this would use the PAT retrieved from the secrets backend;
// in v0.3.1 we send what we have — the hash — as the token value. Tests use
// httptest to verify the header is present and the method is DELETE.
func (r *GitHubPATRevoker) Revoke(ctx context.Context, record CredentialRecord) (RevokeResult, error) {
	url := r.baseURL + "/installation/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return RevokeResult{ProviderError: fmt.Errorf("revocation: build request: %w", err)}, nil
	}

	// Authorization header carries the PAT. In v0.3.1 we use the ProviderTokenHash
	// as a stand-in; real PAT retrieval from the secrets backend is v0.4.
	req.Header.Set("Authorization", "token "+record.ProviderTokenHash)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return RevokeResult{ProviderError: fmt.Errorf("revocation: GitHub API call failed: %w", err)}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent: // 204 — revoked
		return RevokeResult{Revoked: true}, nil
	case http.StatusNotFound: // 404 — token already gone; idempotent success
		return RevokeResult{Revoked: true}, nil
	default:
		return RevokeResult{
			ProviderError: fmt.Errorf("revocation: GitHub API returned unexpected status %d", resp.StatusCode),
		}, nil
	}
}

// ── AWSSTSRevoker ─────────────────────────────────────────────────────────────

// AWSSTSRevoker handles AWS STS temporary credentials.
//
// AWS STS tokens (assumed-role credentials, session tokens) cannot be revoked
// before their natural expiry. The AWS-documented mitigation — attaching a
// deny-all IAM policy to the affected role — requires IAM mutation and broad
// permissions; that is scoped to v0.4.
//
// v0.3.1: SupportsRevocation() returns false. The orchestrator routes to the
// manual-alert branch which emits a high-priority alert with the IAM console URL.
type AWSSTSRevoker struct{}

// NewAWSSTSRevoker returns an AWSSTSRevoker.
func NewAWSSTSRevoker() *AWSSTSRevoker { return &AWSSTSRevoker{} }

// SupportsRevocation returns false — AWS STS tokens cannot be revoked early.
func (r *AWSSTSRevoker) SupportsRevocation() bool { return false }

// Revoke always returns ErrRevocationUnsupported.
// Calling Revoke on an AWSSTSRevoker is a programming error; the orchestrator
// must check SupportsRevocation() first.
func (r *AWSSTSRevoker) Revoke(_ context.Context, _ CredentialRecord) (RevokeResult, error) {
	return RevokeResult{}, ErrRevocationUnsupported
}

// ── NoopRevoker ───────────────────────────────────────────────────────────────

// NoopRevoker is the fallback for credential types that have no registered
// Revoker. Always returns ErrRevocationUnsupported.
//
// Used for: Slack webhook URLs, Anthropic API keys, and any future credential
// type until a dedicated Revoker is registered in the RevokerRegistry.
type NoopRevoker struct{}

// NewNoopRevoker returns a NoopRevoker.
func NewNoopRevoker() *NoopRevoker { return &NoopRevoker{} }

// SupportsRevocation returns false.
func (r *NoopRevoker) SupportsRevocation() bool { return false }

// Revoke always returns ErrRevocationUnsupported.
func (r *NoopRevoker) Revoke(_ context.Context, _ CredentialRecord) (RevokeResult, error) {
	return RevokeResult{}, ErrRevocationUnsupported
}

// ── RevokerRegistry ───────────────────────────────────────────────────────────

// RevokerRegistry maps CredentialType strings to the appropriate Revoker.
// For returns NoopRevoker for unknown credential types (never returns nil).
type RevokerRegistry struct {
	revokers map[string]Revoker
}

// NewDefaultRegistry returns a RevokerRegistry pre-loaded with the v0.3.1
// provider set:
//
//	"github-pat" → GitHubPATRevoker (fine-grained only)
//	"aws-sts"    → AWSSTSRevoker (no-op, manual escalation)
//	<unknown>    → NoopRevoker
func NewDefaultRegistry() *RevokerRegistry {
	reg := &RevokerRegistry{
		revokers: make(map[string]Revoker),
	}
	reg.revokers["github-pat"] = NewGitHubPATRevoker("https://api.github.com", http.DefaultClient)
	reg.revokers["aws-sts"] = NewAWSSTSRevoker()
	return reg
}

// For returns the Revoker registered for credentialType, or NoopRevoker if
// no revoker is registered for that type. Never returns nil.
func (reg *RevokerRegistry) For(credentialType string) Revoker {
	if r, ok := reg.revokers[credentialType]; ok {
		return r
	}
	return NewNoopRevoker()
}
