package github_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
	github "github.com/agentkms/agentkms/internal/dynsecrets/github"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// validPEM returns a well-formed RSA private key in PEM format,
// suitable for GitHub App authentication.
func validPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// newPlugin creates a Plugin with a valid key for tests that don't
// exercise key validation.
func newPlugin(t *testing.T) *github.Plugin {
	t.Helper()
	p, err := github.New(12345, validPEM(t), 67890)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return p
}

// validScope returns a well-formed github-pat Scope.
func validScope() credentials.Scope {
	return credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"repositories": []any{"acmecorp/web", "acmecorp/api"},
			"permissions":  map[string]any{"contents": "write", "pull_requests": "read"},
		},
		TTL: 30 * time.Minute,
	}
}

// ── TestGitHubPlugin_Kind ───────────────────────────────────────────────────

func TestGitHubPlugin_Kind(t *testing.T) {
	p := newPlugin(t)
	if got := p.Kind(); got != "github-pat" {
		t.Errorf("Kind() = %q, want %q", got, "github-pat")
	}
}

// ── TestGitHubPlugin_Validate ───────────────────────────────────────────────

func TestGitHubPlugin_Validate_ValidScope(t *testing.T) {
	p := newPlugin(t)
	if err := p.Validate(context.Background(), validScope()); err != nil {
		t.Errorf("Validate(validScope): unexpected error: %v", err)
	}
}

func TestGitHubPlugin_Validate_MissingRepositories(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	delete(s.Params, "repositories")

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(missing repositories): expected error, got nil")
	}
}

func TestGitHubPlugin_Validate_EmptyRepositories(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.Params["repositories"] = []any{}

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(empty repositories): expected error, got nil")
	}
}

func TestGitHubPlugin_Validate_InvalidPermission(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.Params["permissions"] = map[string]any{
		"contents":       "write",
		"totally_bogus":  "read", // unknown permission key
	}

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(invalid permission key): expected error, got nil")
	}
}

func TestGitHubPlugin_Validate_TTLExceedsMax(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.TTL = 2 * time.Hour // GitHub max is 1 hour for installation tokens

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(TTL > 1h): expected error, got nil")
	}
}

func TestGitHubPlugin_Validate_ZeroTTL(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.TTL = 0

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(TTL == 0): expected error, got nil")
	}
}

// ── TestGitHubPlugin_Narrow ─────────────────────────────────────────────────

func TestGitHubPlugin_Narrow_RepoIntersection(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.Params["repositories"] = []any{"owner/a", "owner/b", "owner/c"}
	requested.Params["permissions"] = map[string]any{"contents": "write"}
	requested.TTL = 30 * time.Minute

	bounds := credentials.ScopeBounds{
		Kind: "github-pat",
		MaxParams: map[string]any{
			"repositories": []any{"owner/a", "owner/c", "owner/d"},
			"permissions":  map[string]any{"contents": "write"},
		},
		MaxTTL: time.Hour,
	}

	narrowed, err := p.Narrow(ctx, requested, bounds)
	if err != nil {
		t.Fatalf("Narrow: unexpected error: %v", err)
	}

	repos, ok := narrowed.Params["repositories"].([]any)
	if !ok {
		t.Fatalf("narrowed repositories: expected []any, got %T", narrowed.Params["repositories"])
	}

	want := map[string]bool{"owner/a": true, "owner/c": true}
	if len(repos) != len(want) {
		t.Fatalf("narrowed repos len = %d, want %d", len(repos), len(want))
	}
	for _, r := range repos {
		rs, _ := r.(string)
		if !want[rs] {
			t.Errorf("unexpected repo in narrowed set: %q", rs)
		}
	}
}

func TestGitHubPlugin_Narrow_TTLCapped(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.TTL = 2 * time.Hour // exceeds bounds

	bounds := credentials.ScopeBounds{
		Kind: "github-pat",
		MaxParams: map[string]any{
			"repositories": []any{"acmecorp/web", "acmecorp/api"},
			"permissions":  map[string]any{"contents": "write", "pull_requests": "read"},
		},
		MaxTTL: 30 * time.Minute,
	}

	narrowed, err := p.Narrow(ctx, requested, bounds)
	if err != nil {
		t.Fatalf("Narrow: unexpected error: %v", err)
	}

	if narrowed.TTL != 30*time.Minute {
		t.Errorf("narrowed TTL = %v, want %v", narrowed.TTL, 30*time.Minute)
	}
}

func TestGitHubPlugin_Narrow_NoOverlap(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.Params["repositories"] = []any{"owner/x", "owner/y"}

	bounds := credentials.ScopeBounds{
		Kind: "github-pat",
		MaxParams: map[string]any{
			"repositories": []any{"owner/a", "owner/b"},
			"permissions":  map[string]any{"contents": "write"},
		},
		MaxTTL: time.Hour,
	}

	_, err := p.Narrow(ctx, requested, bounds)
	if err == nil {
		t.Error("Narrow(no repo overlap): expected error, got nil")
	}
}

func TestGitHubPlugin_Narrow_PermissionIntersection(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.Params["repositories"] = []any{"owner/repo"}
	requested.Params["permissions"] = map[string]any{
		"contents": "write",
		"issues":   "read",
	}

	bounds := credentials.ScopeBounds{
		Kind: "github-pat",
		MaxParams: map[string]any{
			"repositories": []any{"owner/repo"},
			"permissions":  map[string]any{"contents": "write"}, // issues not allowed
		},
		MaxTTL: time.Hour,
	}

	narrowed, err := p.Narrow(ctx, requested, bounds)
	if err != nil {
		t.Fatalf("Narrow: unexpected error: %v", err)
	}

	perms, ok := narrowed.Params["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("narrowed permissions: expected map[string]any, got %T", narrowed.Params["permissions"])
	}

	if len(perms) != 1 {
		t.Errorf("narrowed permissions count = %d, want 1", len(perms))
	}
	if perms["contents"] != "write" {
		t.Errorf("narrowed permissions[contents] = %v, want %q", perms["contents"], "write")
	}
	if _, exists := perms["issues"]; exists {
		t.Error("narrowed permissions should not contain 'issues'")
	}
}

// ── TestGitHubPlugin_New ────────────────────────────────────────────────────

func TestGitHubPlugin_New_InvalidKey(t *testing.T) {
	// Garbage bytes that are not a valid PEM-encoded RSA private key.
	badKey := []byte("this-is-not-a-valid-private-key")

	_, err := github.New(12345, badKey, 67890)
	if err == nil {
		t.Error("New(invalid key): expected error, got nil")
	}
}

func TestGitHubPlugin_New_WrongKeyType(t *testing.T) {
	// Valid PEM but wrong algorithm (ECDSA instead of RSA).
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})

	_, err = github.New(12345, ecPEM, 67890)
	if err == nil {
		t.Error("New(ECDSA key): expected error for non-RSA key, got nil")
	}
}
