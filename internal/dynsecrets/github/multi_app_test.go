package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/agentkms/agentkms/internal/credentials"
	github "github.com/agentkms/agentkms/internal/dynsecrets/github"
)

// ── key helpers ──────────────────────────────────────────────────────────────

// generateTestKey returns a fresh 2048-bit RSA key pair.
func generateTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, pemBytes
}

// ── mock server helpers ──────────────────────────────────────────────────────

type mockTokenServer struct {
	// installID → token to return
	tokens map[int64]string
	// installID → expiry to return (defaults to now+1h)
	expiries map[int64]time.Time

	// call counts per installation ID
	mintCalls map[int64]int

	// suspendCalls and unsuspendCalls track installation IDs for suspend ops
	suspendCalls   map[int64]int
	unsuspendCalls map[int64]int

	// if set, return 403 with rate-limit-exhausted headers
	rateLimitExhausted bool

	// if set, return 500 on token mint
	serverError bool
}

func newMockServer(t *testing.T) *mockTokenServer {
	t.Helper()
	return &mockTokenServer{
		tokens:         make(map[int64]string),
		expiries:       make(map[int64]time.Time),
		mintCalls:      make(map[int64]int),
		suspendCalls:   make(map[int64]int),
		unsuspendCalls: make(map[int64]int),
	}
}

// addApp registers an expected installation with a token to return.
func (m *mockTokenServer) addApp(installID int64, token string, expiresAt time.Time) {
	m.tokens[installID] = token
	m.expiries[installID] = expiresAt
}

// serve returns an httptest.Server that handles GitHub App API requests.
func (m *mockTokenServer) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// POST /app/installations/{id}/access_tokens
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		// parse the installation ID from the path
		var installID int64
		path := strings.TrimPrefix(r.URL.Path, "/app/installations/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 1 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if _, err := fmt.Sscanf(parts[0], "%d", &installID); err != nil {
			http.Error(w, "bad install id", http.StatusBadRequest)
			return
		}

		op := ""
		if len(parts) == 2 {
			op = parts[1]
		}

		switch {
		case r.Method == http.MethodPost && op == "access_tokens":
			m.handleMintToken(w, r, installID)
		case r.Method == http.MethodPut && op == "suspended":
			m.suspendCalls[installID]++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && op == "suspended":
			m.unsuspendCalls[installID]++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	return httptest.NewServer(mux)
}

func (m *mockTokenServer) handleMintToken(w http.ResponseWriter, _ *http.Request, installID int64) {
	m.mintCalls[installID]++

	if m.rateLimitExhausted {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(30*time.Minute).Unix()))
		http.Error(w, `{"message":"rate limited"}`, http.StatusForbidden)
		return
	}

	if m.serverError {
		http.Error(w, `{"message":"internal error"}`, http.StatusInternalServerError)
		return
	}

	token, ok := m.tokens[installID]
	if !ok {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		return
	}

	expiresAt := m.expiries[installID]
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(time.Hour)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// injectBaseURL sets the base URL on the plugin's internal clients via the
// exported test hook. Since we can't reach private fields directly, we use
// the test-only WithBaseURL option.
//
// Instead we register apps and then patch via a helper that the test package
// uses. Because the client is internal, we use an alternative: we expose a
// test-only method SetClientBaseURL on Plugin.

// ── T1: Register 3 distinct Apps and list them ───────────────────────────────

func TestMultiApp_RegisterAndList(t *testing.T) {
	_, pemA := generateTestKey(t)
	_, pemB := generateTestKey(t)
	_, pemC := generateTestKey(t)

	p := github.NewMulti()
	if err := p.RegisterApp("alpha", 1001, 2001, pemA); err != nil {
		t.Fatalf("RegisterApp alpha: %v", err)
	}
	if err := p.RegisterApp("beta", 1002, 2002, pemB); err != nil {
		t.Fatalf("RegisterApp beta: %v", err)
	}
	if err := p.RegisterApp("gamma", 1003, 2003, pemC); err != nil {
		t.Fatalf("RegisterApp gamma: %v", err)
	}

	apps := p.ListApps()
	if len(apps) != 3 {
		t.Fatalf("ListApps: got %d apps, want 3", len(apps))
	}

	byName := make(map[string]github.AppInfo, len(apps))
	for _, a := range apps {
		byName[a.Name] = a
	}
	for _, tc := range []struct {
		name    string
		appID   int64
		instID  int64
	}{
		{"alpha", 1001, 2001},
		{"beta", 1002, 2002},
		{"gamma", 1003, 2003},
	} {
		a, ok := byName[tc.name]
		if !ok {
			t.Errorf("app %q not in ListApps", tc.name)
			continue
		}
		if a.AppID != tc.appID {
			t.Errorf("app %q: AppID=%d, want %d", tc.name, a.AppID, tc.appID)
		}
		if a.InstallationID != tc.instID {
			t.Errorf("app %q: InstallationID=%d, want %d", tc.name, a.InstallationID, tc.instID)
		}
	}
}

// ── T2: Mint token for App A — correct JWT key, correct installation ID ──────

func TestMultiApp_MintTokenAppA_CorrectJWTAndInstallation(t *testing.T) {
	keyA, pemA := generateTestKey(t)
	_, pemB := generateTestKey(t)

	mock := newMockServer(t)
	mock.addApp(2001, "token-for-alpha", time.Now().UTC().Add(time.Hour))
	mock.addApp(2002, "token-for-beta", time.Now().UTC().Add(time.Hour))

	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	if err := p.RegisterApp("alpha", 1001, 2001, pemA); err != nil {
		t.Fatalf("RegisterApp alpha: %v", err)
	}
	if err := p.RegisterApp("beta", 1002, 2002, pemB); err != nil {
		t.Fatalf("RegisterApp beta: %v", err)
	}
	p.SetTestBaseURL("alpha", srv.URL)
	p.SetTestBaseURL("beta", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "alpha",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	cred, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend alpha: %v", err)
	}
	defer cred.Zero()

	if string(cred.APIKey) != "token-for-alpha" {
		t.Errorf("APIKey = %q, want %q", string(cred.APIKey), "token-for-alpha")
	}
	if mock.mintCalls[2001] != 1 {
		t.Errorf("mint calls for install 2001: got %d, want 1", mock.mintCalls[2001])
	}
	if mock.mintCalls[2002] != 0 {
		t.Errorf("mint calls for install 2002: got %d, want 0 (cross-contamination)", mock.mintCalls[2002])
	}

	// Verify the JWT that was sent was signed by keyA (not keyB).
	// We do this by checking that the Authorization header's JWT can be
	// verified with keyA's public key. Since we can't intercept the header
	// from inside the mock handler easily, we verify indirectly: the server
	// returned token-for-alpha for installation 2001, which means the request
	// hit the right path. JWT key verification is done in TestJWTSigning.
	_ = keyA // used in TestJWTSigning
}

// ── T3: Mint token for App B — distinct token, no cross-contamination ────────

func TestMultiApp_MintTokenAppB_NoCrossContamination(t *testing.T) {
	_, pemA := generateTestKey(t)
	_, pemB := generateTestKey(t)

	mock := newMockServer(t)
	mock.addApp(2001, "token-alpha-unique", time.Now().UTC().Add(time.Hour))
	mock.addApp(2002, "token-beta-unique", time.Now().UTC().Add(time.Hour))

	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("alpha", 1001, 2001, pemA)
	_ = p.RegisterApp("beta", 1002, 2002, pemB)
	p.SetTestBaseURL("alpha", srv.URL)
	p.SetTestBaseURL("beta", srv.URL)

	ctx := context.Background()

	makeScope := func(appName string) credentials.Scope {
		return credentials.Scope{
			Kind: "github-pat",
			Params: map[string]any{
				"app_name":     appName,
				"repositories": []any{"org/repo"},
				"permissions":  map[string]any{"contents": "read"},
			},
			TTL: 30 * time.Minute,
		}
	}

	credA, err := p.Vend(ctx, makeScope("alpha"))
	if err != nil {
		t.Fatalf("Vend alpha: %v", err)
	}
	defer credA.Zero()

	credB, err := p.Vend(ctx, makeScope("beta"))
	if err != nil {
		t.Fatalf("Vend beta: %v", err)
	}
	defer credB.Zero()

	if string(credA.APIKey) == string(credB.APIKey) {
		t.Errorf("cross-contamination: alpha and beta returned the same token %q", string(credA.APIKey))
	}
	if string(credA.APIKey) != "token-alpha-unique" {
		t.Errorf("alpha token = %q, want %q", string(credA.APIKey), "token-alpha-unique")
	}
	if string(credB.APIKey) != "token-beta-unique" {
		t.Errorf("beta token = %q, want %q", string(credB.APIKey), "token-beta-unique")
	}
}

// ── T4: Token caching — second mint within TTL returns cached token ───────────

func TestMultiApp_TokenCaching(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	// Token expires well in the future so cache hit is guaranteed.
	mock.addApp(3001, "cached-token", time.Now().UTC().Add(55*time.Minute))

	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("cache-test", 5001, 3001, pemA)
	p.SetTestBaseURL("cache-test", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "cache-test",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	// First call — should hit API.
	cred1, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend 1: %v", err)
	}
	defer cred1.Zero()

	if mock.mintCalls[3001] != 1 {
		t.Errorf("after first Vend: mint calls = %d, want 1", mock.mintCalls[3001])
	}

	// Second call within TTL — should return cached token without API call.
	cred2, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend 2: %v", err)
	}
	defer cred2.Zero()

	if mock.mintCalls[3001] != 1 {
		t.Errorf("after second Vend (cache hit): mint calls = %d, want 1 (no new call)", mock.mintCalls[3001])
	}
	if string(cred2.APIKey) != "cached-token" {
		t.Errorf("cached token = %q, want %q", string(cred2.APIKey), "cached-token")
	}
}

// ── T5: Token cache expiry — re-mints after expiry ───────────────────────────

func TestMultiApp_TokenCacheExpiry(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("expiry-test", 6001, 4001, pemA)
	p.SetTestBaseURL("expiry-test", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "expiry-test",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	// First mint: token that expires in the past (already expired).
	mock.addApp(4001, "first-token", time.Now().UTC().Add(-10*time.Minute))

	cred1, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend 1: %v", err)
	}
	defer cred1.Zero()

	if mock.mintCalls[4001] != 1 {
		t.Errorf("after first Vend: mint calls = %d, want 1", mock.mintCalls[4001])
	}

	// Update mock to return a new token; the second Vend should re-mint
	// because the cached token has already expired.
	mock.addApp(4001, "second-token", time.Now().UTC().Add(time.Hour))

	cred2, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend 2: %v", err)
	}
	defer cred2.Zero()

	if mock.mintCalls[4001] != 2 {
		t.Errorf("after second Vend (expired cache): mint calls = %d, want 2", mock.mintCalls[4001])
	}
	if string(cred2.APIKey) != "second-token" {
		t.Errorf("second token = %q, want %q", string(cred2.APIKey), "second-token")
	}
}

// ── T6: Suspension — correct installation ID, correct HTTP method ─────────────

func TestMultiApp_Suspend(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("suspendable", 7001, 5001, pemA)
	p.SetTestBaseURL("suspendable", srv.URL)

	ctx := context.Background()
	if err := p.Suspend(ctx, "suspendable"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}

	if mock.suspendCalls[5001] != 1 {
		t.Errorf("suspend calls for install 5001: got %d, want 1", mock.suspendCalls[5001])
	}
	if mock.unsuspendCalls[5001] != 0 {
		t.Errorf("unsuspend calls for install 5001: got %d, want 0", mock.unsuspendCalls[5001])
	}
}

func TestMultiApp_Unsuspend(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("suspendable", 7001, 5001, pemA)
	p.SetTestBaseURL("suspendable", srv.URL)

	ctx := context.Background()
	if err := p.Unsuspend(ctx, "suspendable"); err != nil {
		t.Fatalf("Unsuspend: %v", err)
	}

	if mock.unsuspendCalls[5001] != 1 {
		t.Errorf("unsuspend calls for install 5001: got %d, want 1", mock.unsuspendCalls[5001])
	}
	if mock.suspendCalls[5001] != 0 {
		t.Errorf("suspend calls for install 5001: got %d, want 0", mock.suspendCalls[5001])
	}
}

// ── T7: Rate limit — 403 with exhausted rate limit returns transient error ───

func TestMultiApp_RateLimitExhausted(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	mock.rateLimitExhausted = true
	mock.addApp(6001, "wont-be-returned", time.Now().UTC().Add(time.Hour))

	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("rate-limited", 8001, 6001, pemA)
	p.SetTestBaseURL("rate-limited", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "rate-limited",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	_, err := p.Vend(ctx, scope)
	if err == nil {
		t.Fatal("Vend with rate limit exhausted: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[transient]") {
		t.Errorf("expected [transient] in error message, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rate") {
		t.Errorf("expected 'rate' in error message, got: %v", err)
	}
}

// ── T8: JWT signing — JWT verifies against App's own public key ───────────────

func TestMultiApp_JWTSigningVerifiesWithCorrectKey(t *testing.T) {
	keyA, pemA := generateTestKey(t)
	keyB, pemB := generateTestKey(t)

	// We intercept the Authorization header by wrapping the mock server.
	var capturedJWT string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			capturedJWT = strings.TrimPrefix(authHeader, "Bearer ")
		}
		// Return a valid token response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := map[string]any{
			"token":      "jwt-verified-token",
			"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(captureHandler)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("app-a", 1001, 2001, pemA)
	_ = p.RegisterApp("app-b", 1002, 2002, pemB)
	p.SetTestBaseURL("app-a", srv.URL)
	p.SetTestBaseURL("app-b", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "app-a",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	cred, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend app-a: %v", err)
	}
	defer cred.Zero()

	if capturedJWT == "" {
		t.Fatal("no JWT captured from Authorization header")
	}

	// Parse and verify the JWT using keyA's public key.
	parsed, err := jwt.Parse(capturedJWT, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return &keyA.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("JWT verification with keyA failed: %v", err)
	}
	if !parsed.Valid {
		t.Error("JWT parsed as invalid")
	}

	// Verify it does NOT verify with keyB.
	_, errB := jwt.Parse(capturedJWT, func(tok *jwt.Token) (any, error) {
		return &keyB.PublicKey, nil
	})
	if errB == nil {
		t.Error("JWT verified with keyB — this should not happen (key cross-use)")
	}
}

// ── T9: Missing App — returns permanent error ─────────────────────────────────

func TestMultiApp_UnknownAppReturnsPermanentError(t *testing.T) {
	_, pemA := generateTestKey(t)

	p := github.NewMulti()
	_ = p.RegisterApp("real-app", 1001, 2001, pemA)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "does-not-exist",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	_, err := p.Vend(ctx, scope)
	if err == nil {
		t.Fatal("Vend with unknown app_name: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[permanent]") {
		t.Errorf("expected [permanent] in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("expected app name in error, got: %v", err)
	}
}

// ── T10: Empty app_name falls back to "default" ──────────────────────────────

func TestMultiApp_EmptyAppNameUsesDefault(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	mock.addApp(2001, "default-token", time.Now().UTC().Add(time.Hour))

	srv := mock.serve(t)
	defer srv.Close()

	// Use New() which registers as "default".
	p, err := github.New(1001, pemA, 2001)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.SetTestBaseURL("default", srv.URL)

	ctx := context.Background()
	// Scope with no app_name — should use "default".
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	cred, err := p.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend (no app_name): %v", err)
	}
	defer cred.Zero()

	if string(cred.APIKey) != "default-token" {
		t.Errorf("token = %q, want %q", string(cred.APIKey), "default-token")
	}
}

// ── T11: Validate rejects unknown app_name ────────────────────────────────────

func TestMultiApp_ValidateRejectsUnknownAppName(t *testing.T) {
	_, pemA := generateTestKey(t)

	p := github.NewMulti()
	_ = p.RegisterApp("known-app", 1001, 2001, pemA)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "unknown-app",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	if err := p.Validate(ctx, scope); err == nil {
		t.Error("Validate with unknown app_name: expected error, got nil")
	}
}

// ── T12: Validate accepts valid scope without app_name ────────────────────────

func TestMultiApp_ValidateAcceptsNoAppName(t *testing.T) {
	_, pemA := generateTestKey(t)

	p := github.NewMulti()
	_ = p.RegisterApp("app", 1001, 2001, pemA)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	if err := p.Validate(ctx, scope); err != nil {
		t.Errorf("Validate(no app_name): unexpected error: %v", err)
	}
}

// ── T13: RegisterApp rejects empty name ───────────────────────────────────────

func TestMultiApp_RegisterAppRejectsEmptyName(t *testing.T) {
	_, pemA := generateTestKey(t)

	p := github.NewMulti()
	if err := p.RegisterApp("", 1001, 2001, pemA); err == nil {
		t.Error("RegisterApp(empty name): expected error, got nil")
	}
}

// ── T14: Suspend unknown app returns permanent error ──────────────────────────

func TestMultiApp_SuspendUnknownApp(t *testing.T) {
	p := github.NewMulti()
	ctx := context.Background()

	err := p.Suspend(ctx, "no-such-app")
	if err == nil {
		t.Fatal("Suspend(unknown app): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[permanent]") {
		t.Errorf("expected [permanent] in error, got: %v", err)
	}
}

// ── T15: Server error returns transient error ─────────────────────────────────

func TestMultiApp_ServerErrorIsTransient(t *testing.T) {
	_, pemA := generateTestKey(t)

	mock := newMockServer(t)
	mock.serverError = true
	mock.addApp(9001, "wont-see-this", time.Now().UTC().Add(time.Hour))

	srv := mock.serve(t)
	defer srv.Close()

	p := github.NewMulti()
	_ = p.RegisterApp("flaky", 9001, 9001, pemA)
	p.SetTestBaseURL("flaky", srv.URL)

	ctx := context.Background()
	scope := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"app_name":     "flaky",
			"repositories": []any{"org/repo"},
			"permissions":  map[string]any{"contents": "read"},
		},
		TTL: 30 * time.Minute,
	}

	_, err := p.Vend(ctx, scope)
	if err == nil {
		t.Fatal("Vend with server error: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[transient]") {
		t.Errorf("expected [transient] in error, got: %v", err)
	}
}
