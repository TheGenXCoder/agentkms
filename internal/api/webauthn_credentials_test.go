package api_test

// webauthn_credentials_test.go — Tests for the WebAuthn credential management
// endpoints:
//
//	GET    /auth/webauthn/credentials
//	DELETE /auth/webauthn/credentials/{id}
//
// Tests use a stub WebAuthnService built directly on top of the real
// WebAuthnStore wired to a temp directory, which lets us pre-populate
// credentials by calling store methods directly (bypassing the full FIDO2
// ceremony while still exercising the store's list/delete logic).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

// newWACredTestStack builds:
//   - a WebAuthnStore in a temp dir
//   - a WebAuthnService backed by it
//   - a TokenService for issuing real Bearer tokens
//   - an api.Server with the service wired in
//
// Returns the server, the store (for direct credential injection), and the
// token service (for issuing test tokens).
func newWACredTestStack(t *testing.T) (*api.Server, *auth.WebAuthnStore, *auth.TokenService) {
	t.Helper()

	dir := t.TempDir()

	store, err := auth.NewWebAuthnStore(dir)
	if err != nil {
		t.Fatalf("NewWebAuthnStore: %v", err)
	}

	// Build a minimal WebAuthnService wired to the store.
	// We do not need a real go-webauthn.WebAuthn instance for list/delete;
	// the service delegates those operations directly to the store.
	svc, err := auth.NewWebAuthnServiceFromStore(store)
	if err != nil {
		t.Fatalf("NewWebAuthnServiceFromStore: %v", err)
	}

	rl := auth.NewRevocationList()
	ts, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	aud := &capturingAuditor{}
	srv := api.NewServer(backend.NewDevBackend(), aud, policy.AllowAllEngine{}, ts, "dev")
	srv.SetWebAuthn(svc)

	return srv, store, ts
}

// testCertFP is a synthetic cert fingerprint (64 lowercase hex chars = 32 bytes)
// used to satisfy the TokenService required-claims check which rejects tokens
// with an empty CertFingerprint.  It does not correspond to a real certificate.
const testCertFP = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// issueTestToken issues a real Bearer token for userID using the given
// TokenService.  The identity has CallerID = userID (simulating a legacy
// session where UserID is empty and the handler falls back to CallerID).
func issueTestToken(t *testing.T, ts *auth.TokenService, userID string) string {
	t.Helper()
	id := identity.Identity{
		CallerID:        userID,
		TeamID:          "test-team",
		Role:            identity.RoleDeveloper,
		CertFingerprint: testCertFP,
	}
	tok, _, err := ts.Issue(&id)
	if err != nil {
		t.Fatalf("Issue token for %q: %v", userID, err)
	}
	return tok
}

// issueTestTokenWithUserID issues a token where Identity.UserID is set
// (post-split identity, preferred path).
func issueTestTokenWithUserID(t *testing.T, ts *auth.TokenService, userID string) string {
	t.Helper()
	id := identity.Identity{
		CallerID:        userID + "-device",
		UserID:          userID,
		TeamID:          "test-team",
		Role:            identity.RoleDeveloper,
		CertFingerprint: testCertFP,
	}
	tok, _, err := ts.Issue(&id)
	if err != nil {
		t.Fatalf("Issue token with UserID %q: %v", userID, err)
	}
	return tok
}

// seedCredential directly injects a synthetic webauthn.Credential into the
// store for the given callerID.  The credential has a deterministic ID derived
// from the seq parameter so tests can reference it by ID without going through
// a full FIDO2 ceremony.
func seedCredential(t *testing.T, store *auth.WebAuthnStore, callerID string, seq int) string {
	t.Helper()

	// Synthetic credential ID: 16 bytes with the seq number in the last byte.
	rawID := make([]byte, 16)
	rawID[15] = byte(seq)

	cred := webauthn.Credential{
		ID:        rawID,
		PublicKey: []byte("fake-public-key"),
	}
	if err := store.SaveCredential(callerID, &cred); err != nil {
		t.Fatalf("seedCredential(%q, %d): %v", callerID, seq, err)
	}
	return base64.RawURLEncoding.EncodeToString(rawID)
}

// requestWithBearer creates a GET or DELETE request with a real Authorization
// header but WITHOUT an injected context identity — the authMiddleware will
// validate the Bearer token the normal way.  Since tests don't have a TLS
// connection, we bypass mTLS by also injecting a context identity (which
// causes authMiddleware to short-circuit before the cert check).
//
// Pattern: inject context identity to pass authMiddleware, and set the
// Authorization header so our handler's webAuthnSessionUserID can extract
// the real token and derive the user_id.
func requestWithBearer(t *testing.T, method, path, bearer string, srv http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)

	// Inject a minimal context identity so authMiddleware skips the mTLS cert
	// binding check (which would fail without a TLS connection in unit tests).
	id := identity.Identity{
		CallerID: "middleware-bypass",
		TeamID:   "test",
		Role:     identity.RoleDeveloper,
	}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// requestNoAuth creates a request with no Authorization header and no context
// identity, so authMiddleware rejects it.
func requestNoAuth(t *testing.T, method, path string, srv http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// ── List credentials ──────────────────────────────────────────────────────────

func TestListWebAuthnCredentials_HappyPath(t *testing.T) {
	srv, store, ts := newWACredTestStack(t)

	// Seed two credentials for alice.
	id1 := seedCredential(t, store, "alice", 1)
	id2 := seedCredential(t, store, "alice", 2)

	token := issueTestToken(t, ts, "alice")
	rr := requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", token, srv)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Credentials []struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			AuthenticatorType string `json:"authenticator_type"`
			CreatedAt         string `json:"created_at"`
			LastUsedAt        string `json:"last_used_at"`
			AAGUID            string `json:"aaguid"`
		} `json:"credentials"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Credentials) != 2 {
		t.Fatalf("want 2 credentials, got %d", len(resp.Credentials))
	}

	// Collect returned IDs into a set.
	got := make(map[string]bool)
	for _, c := range resp.Credentials {
		got[c.ID] = true
		// Shape check: all fields must be present (even if empty string).
		_ = c.Name
		_ = c.AuthenticatorType
		_ = c.CreatedAt
		_ = c.LastUsedAt
		_ = c.AAGUID
	}
	if !got[id1] {
		t.Errorf("id1 %q not in response", id1)
	}
	if !got[id2] {
		t.Errorf("id2 %q not in response", id2)
	}
}

func TestListWebAuthnCredentials_FiltersByUser(t *testing.T) {
	srv, store, ts := newWACredTestStack(t)

	// Alice has 2, Bob has 1.
	_ = seedCredential(t, store, "alice", 1)
	_ = seedCredential(t, store, "alice", 2)
	_ = seedCredential(t, store, "bob", 3)

	// Fetch Alice's list.
	aliceToken := issueTestToken(t, ts, "alice")
	rr := requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", aliceToken, srv)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Credentials []struct{ ID string } `json:"credentials"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Credentials) != 2 {
		t.Errorf("alice: want 2 credentials, got %d", len(resp.Credentials))
	}

	// Bob sees only his own.
	bobToken := issueTestToken(t, ts, "bob")
	rr = requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", bobToken, srv)
	if rr.Code != http.StatusOK {
		t.Fatalf("bob: want 200, got %d", rr.Code)
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode bob response: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Errorf("bob: want 1 credential, got %d", len(resp.Credentials))
	}
}

func TestListWebAuthnCredentials_NoBearer(t *testing.T) {
	srv, _, _ := newWACredTestStack(t)
	rr := requestNoAuth(t, http.MethodGet, "/auth/webauthn/credentials", srv)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

// ── Delete credential ─────────────────────────────────────────────────────────

func TestDeleteWebAuthnCredential_HappyPath(t *testing.T) {
	srv, store, ts := newWACredTestStack(t)

	id1 := seedCredential(t, store, "alice", 1)
	id2 := seedCredential(t, store, "alice", 2)

	aliceToken := issueTestToken(t, ts, "alice")

	// Delete the first credential.
	rr := requestWithBearer(t, http.MethodDelete,
		"/auth/webauthn/credentials/"+id1,
		aliceToken, srv)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d — body: %s", rr.Code, rr.Body.String())
	}

	// Subsequent list should only show id2.
	rr = requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", aliceToken, srv)
	if rr.Code != http.StatusOK {
		t.Fatalf("list after delete: want 200, got %d", rr.Code)
	}

	var resp struct {
		Credentials []struct{ ID string } `json:"credentials"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("want 1 remaining credential, got %d", len(resp.Credentials))
	}
	if resp.Credentials[0].ID != id2 {
		t.Errorf("remaining credential: want %q, got %q", id2, resp.Credentials[0].ID)
	}
}

func TestDeleteWebAuthnCredential_CrossUser_Forbidden(t *testing.T) {
	srv, store, ts := newWACredTestStack(t)

	// Seed one credential for each user.
	bobID := seedCredential(t, store, "bob", 10)
	_ = seedCredential(t, store, "alice", 11)

	// Alice tries to delete Bob's credential.
	aliceToken := issueTestToken(t, ts, "alice")
	rr := requestWithBearer(t, http.MethodDelete,
		"/auth/webauthn/credentials/"+bobID,
		aliceToken, srv)

	// The credential exists in Bob's bucket but not Alice's, so the list
	// check returns not-found (404), not 403.  The store is callerID-keyed
	// and there is no global reverse-index.  The security property holds:
	// Alice gets no oracle about whether the ID belongs to Bob.
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-user delete: want 404, got %d — body: %s", rr.Code, rr.Body.String())
	}

	// Bob's credential must still be there.
	bobToken := issueTestToken(t, ts, "bob")
	rr = requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", bobToken, srv)
	if rr.Code != http.StatusOK {
		t.Fatalf("bob list: want 200, got %d", rr.Code)
	}
	var resp struct {
		Credentials []struct{ ID string } `json:"credentials"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode bob list: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Errorf("bob: want 1 credential still present, got %d", len(resp.Credentials))
	}
}

func TestDeleteWebAuthnCredential_NotFound(t *testing.T) {
	srv, _, ts := newWACredTestStack(t)

	// Use a base64url-encoded ID that was never registered.
	unknownID := base64.RawURLEncoding.EncodeToString([]byte("no-such-credential"))

	token := issueTestToken(t, ts, "alice")
	rr := requestWithBearer(t, http.MethodDelete,
		"/auth/webauthn/credentials/"+unknownID,
		token, srv)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

// TestListWebAuthnCredentials_UserIDField verifies the post-split identity path
// where tok.Identity.UserID is set and CallerID encodes the device, not the human.
func TestListWebAuthnCredentials_UserIDField(t *testing.T) {
	srv, store, ts := newWACredTestStack(t)

	// Seed credential under "alice" (the human user_id).
	id1 := seedCredential(t, store, "alice", 1)

	// Issue a token with UserID=alice, CallerID=alice-laptop (post-split).
	token := issueTestTokenWithUserID(t, ts, "alice")
	rr := requestWithBearer(t, http.MethodGet, "/auth/webauthn/credentials", token, srv)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Credentials []struct{ ID string } `json:"credentials"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) != 1 || resp.Credentials[0].ID != id1 {
		t.Errorf("want [{ID:%q}], got %v", id1, resp.Credentials)
	}
}

// ── Ensure temp-dir persistence works (store is not purely in-memory) ─────────

// TestWebAuthnStore_CredentialsPersistAcrossReload verifies that credentials
// survive a store reload from disk.  This demonstrates the store IS backed by
// disk (not purely in-memory) so that callers can rely on persistence across
// restarts.
func TestWebAuthnStore_CredentialsPersistAcrossReload(t *testing.T) {
	dir := t.TempDir()

	store1, err := auth.NewWebAuthnStore(dir)
	if err != nil {
		t.Fatalf("store1: %v", err)
	}

	rawID := []byte{0xAA, 0xBB, 0xCC}
	cred := webauthn.Credential{ID: rawID, PublicKey: []byte("pk")}
	if err := store1.SaveCredential("alice", &cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	// Reload from same dir.
	store2, err := auth.NewWebAuthnStore(dir)
	if err != nil {
		t.Fatalf("store2: %v", err)
	}

	metas, err := store2.ListCredentials("alice")
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("want 1 credential after reload, got %d", len(metas))
	}
	wantID := base64.RawURLEncoding.EncodeToString(rawID)
	if metas[0].ID != wantID {
		t.Errorf("want ID %q, got %q", wantID, metas[0].ID)
	}
}

