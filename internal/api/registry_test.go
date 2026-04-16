package api_test

// registry_test.go — comprehensive unit tests for registry.go endpoints.
//
// Security invariants tested:
//   1. Secret values NEVER appear in metadata, list, or history responses.
//   2. Policy enforcement (deny → 403) is tested for every operation.
//   3. Audit events contain caller/operation/path but NEVER secret values.
//   4. stripSensitiveFields: any field whose name contains "value" or "secret" is stripped.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	iauth "github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── In-memory KVWriter for tests ──────────────────────────────────────────────

// memKV is a thread-safe in-memory implementation of credentials.KVWriter.
// GetSecret returns credentials.ErrCredentialNotFound (wrapped) for missing paths
// so that isNotFound() in registry.go returns true.
type memKV struct {
	data map[string]map[string]string
	// errOn causes SetSecret to return an error for paths containing errOn.
	errOn string
	// getErrOn causes GetSecret to return an error for paths containing getErrOn.
	getErrOn string
	// deleteErrOn causes DeleteSecret to return an error for paths containing deleteErrOn.
	deleteErrOn string
	// listErr causes ListPaths to return an error.
	listErr error
}

func newMemKV() *memKV {
	return &memKV{data: make(map[string]map[string]string)}
}

func (m *memKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	if m.getErrOn != "" && strings.Contains(path, m.getErrOn) {
		return nil, fmt.Errorf("simulated get error for path %q", path)
	}
	v, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("%w: path %q not found", credentials.ErrCredentialNotFound, path)
	}
	// return a copy
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out, nil
}

func (m *memKV) SetSecret(_ context.Context, path string, fields map[string]string) error {
	if m.errOn != "" && strings.Contains(path, m.errOn) {
		return fmt.Errorf("simulated write error for path %q", path)
	}
	if m.data == nil {
		m.data = make(map[string]map[string]string)
	}
	copied := make(map[string]string, len(fields))
	for k, v := range fields {
		copied[k] = v
	}
	m.data[path] = copied
	return nil
}

func (m *memKV) DeleteSecret(_ context.Context, path string) error {
	if m.deleteErrOn != "" && strings.Contains(path, m.deleteErrOn) {
		return fmt.Errorf("simulated delete error for path %q", path)
	}
	if _, ok := m.data[path]; !ok {
		return fmt.Errorf("%w: path %q not found", credentials.ErrCredentialNotFound, path)
	}
	delete(m.data, path)
	return nil
}

func (m *memKV) ListPaths(_ context.Context) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	paths := make([]string, 0, len(m.data))
	for p := range m.data {
		paths = append(paths, p)
	}
	return paths, nil
}

// ── errorPolicyEngine returns an error from Evaluate ─────────────────────────

type errorPolicyEngine struct{}

func (errorPolicyEngine) Evaluate(_ context.Context, _ identity.Identity, _, _ string) (policy.Decision, error) {
	return policy.Decision{}, fmt.Errorf("policy engine failure")
}
func (errorPolicyEngine) GetPolicy() policy.Policy { return policy.Policy{Version: "1"} }
func (errorPolicyEngine) Reload(_ policy.Policy) error {
	return fmt.Errorf("errorPolicyEngine: reload not supported")
}

// ── Registry server constructors ──────────────────────────────────────────────

func newRegistryServer(t *testing.T, kv credentials.KVWriter, p policy.EngineI) (*api.Server, *capturingAuditor) {
	t.Helper()
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	rl := iauth.NewRevocationList()
	ts, _ := iauth.NewTokenService(rl)
	srv := api.NewServer(b, aud, p, ts, "test")
	if kv != nil {
		srv.SetRegistryWriter(kv)
	}
	return srv, aud
}

func newAllowRegistryServer(t *testing.T, kv credentials.KVWriter) (*api.Server, *capturingAuditor) {
	t.Helper()
	return newRegistryServer(t, kv, policy.AllowAllEngine{})
}

func newDenyRegistryServer(t *testing.T, kv credentials.KVWriter) (*api.Server, *capturingAuditor) {
	t.Helper()
	return newRegistryServer(t, kv, policy.DenyAllEngine{})
}

func newErrPolicyRegistryServer(t *testing.T, kv credentials.KVWriter) (*api.Server, *capturingAuditor) {
	t.Helper()
	return newRegistryServer(t, kv, errorPolicyEngine{})
}

// registryRequest sends method+path+body with an authenticated identity.
func registryRequest(t *testing.T, srv *api.Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	id := identity.Identity{
		CallerID: "test-caller",
		TeamID:   "test-team",
		Role:     identity.RoleDeveloper,
	}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// writeSecret is a test helper that writes a secret via the API and expects 201.
func writeSecret(t *testing.T, srv *api.Server, secretPath, body string) {
	t.Helper()
	rr := registryRequest(t, srv, http.MethodPost, "/secrets/"+secretPath, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("writeSecret: expected 201, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

// ── handleWriteSecret tests ───────────────────────────────────────────────────

func TestHandleWriteSecret_HappyPath_NewSecret(t *testing.T) {
	kv := newMemKV()
	srv, aud := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/db-password",
		`{"value":"s3cr3t!"}`)
	assertStatus(t, rr, http.StatusCreated)

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Response must be metadata — not the secret value.
	if _, hasValue := resp["value"]; hasValue {
		t.Error("ADVERSARIAL: response contains 'value' field — secret leaked in write response")
	}
	if resp["path"] != "myapp/db-password" {
		t.Errorf("path = %v, want myapp/db-password", resp["path"])
	}
	if resp["version"] == nil {
		t.Error("response missing 'version' field")
	}

	// Audit event must be logged.
	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event written")
	}
	if ev.Operation != "secret_write" {
		t.Errorf("audit operation = %q, want secret_write", ev.Operation)
	}
	if ev.Outcome != "success" {
		t.Errorf("audit outcome = %q, want success", ev.Outcome)
	}
	if ev.CallerID != "test-caller" {
		t.Errorf("audit CallerID = %q, want test-caller", ev.CallerID)
	}

	// Audit event must NOT contain the secret value.
	evJSON, _ := json.Marshal(ev)
	if strings.Contains(string(evJSON), "s3cr3t!") {
		t.Fatal("ADVERSARIAL: secret value appears in audit event JSON")
	}
}

func TestHandleWriteSecret_Update_Returns200_BumpsVersion(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Create secret.
	rr1 := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token",
		`{"value":"first-value"}`)
	assertStatus(t, rr1, http.StatusCreated)

	var r1 map[string]any
	json.NewDecoder(rr1.Body).Decode(&r1) //nolint:errcheck
	v1 := r1["version"].(float64)

	// Update secret.
	rr2 := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token",
		`{"value":"second-value"}`)
	assertStatus(t, rr2, http.StatusOK) // 200 for update

	var r2 map[string]any
	json.NewDecoder(rr2.Body).Decode(&r2) //nolint:errcheck
	v2 := r2["version"].(float64)

	if v2 <= v1 {
		t.Errorf("version not bumped: v1=%v v2=%v", v1, v2)
	}
}

func TestHandleWriteSecret_EmptyBody_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Send an empty JSON object.
	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `{}`)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleWriteSecret_InvalidJSON_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `not-json`)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleWriteSecret_EmptyPath_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// The router strips the leading "/secrets/" — sending just the handler with no path
	// We need to directly hit /secrets/ with nothing after it.
	req := httptest.NewRequest(http.MethodPost, "/secrets/", strings.NewReader(`{"value":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	// Either 400 (empty path) or 404 (no route match) — in both cases not 2xx.
	if rr.Code == http.StatusCreated || rr.Code == http.StatusOK {
		t.Errorf("expected non-2xx for empty path, got %d", rr.Code)
	}
}

func TestHandleWriteSecret_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `{"value":"x"}`)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleWriteSecret_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `{"value":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleWriteSecret_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil) // no KV writer

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `{"value":"x"}`)
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleWriteSecret_KVWriteError_Returns500(t *testing.T) {
	kv := newMemKV()
	kv.errOn = "secrets" // fail on any path containing "secrets"
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/myapp/token", `{"value":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleWriteSecret_ADVERSARIAL_AuditNeverContainsValue(t *testing.T) {
	const secretValue = "NEVER-LOG-THIS-SUPER-SECRET-VALUE-12345"
	kv := newMemKV()
	srv, aud := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/test/path",
		`{"value":"`+secretValue+`"}`)
	assertStatus(t, rr, http.StatusCreated)

	for i, ev := range aud.events {
		evJSON, _ := json.Marshal(ev)
		if strings.Contains(string(evJSON), secretValue) {
			t.Errorf("ADVERSARIAL: audit event[%d] contains secret value", i)
		}
	}

	// Also verify the HTTP response doesn't contain the value.
	if strings.Contains(rr.Body.String(), secretValue) {
		t.Error("ADVERSARIAL: HTTP response contains secret value")
	}
}

func TestHandleWriteSecret_VersionHistory_Limit(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Write 12 times — should retain only 10 versions in history.
	for i := 0; i < 12; i++ {
		body := fmt.Sprintf(`{"value":"value-%d"}`, i)
		path := "/secrets/myapp/rolling"
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
		req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("write %d failed: %d %s", i, rr.Code, rr.Body.String())
		}
	}

	// Get history and verify at most 10+1 entries (10 archived + current).
	rr := registryRequest(t, srv, http.MethodGet, "/secrets/myapp/rolling?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	versions, ok := resp["versions"].([]any)
	if !ok {
		t.Fatalf("no versions field in response: %v", resp)
	}
	// maxVersions=10 in history + 1 current = 11 max
	if len(versions) > 11 {
		t.Errorf("version history not trimmed: got %d entries, want ≤11", len(versions))
	}
}

// ── handleWriteMetadata tests ─────────────────────────────────────────────────

func TestHandleWriteMetadata_HappyPath(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Create the secret first.
	writeSecret(t, srv, "myapp/creds", `{"value":"x"}`)

	// Now update metadata.
	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/creds",
		`{"description":"My app credentials","tags":["prod","db"],"type":"database"}`)
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck

	if resp["description"] != "My app credentials" {
		t.Errorf("description = %v, want 'My app credentials'", resp["description"])
	}
	if _, hasValue := resp["value"]; hasValue {
		t.Error("ADVERSARIAL: metadata response contains 'value' field")
	}
}

func TestHandleWriteMetadata_SecretNotExist_Returns404(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/nonexistent/path",
		`{"description":"oops"}`)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleWriteMetadata_InvalidJSON_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "myapp/token", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/token", `not-json`)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleWriteMetadata_MergeSemantics(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "myapp/merge-test", `{"value":"x"}`)

	// Set description.
	rr1 := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/merge-test",
		`{"description":"initial desc"}`)
	assertStatus(t, rr1, http.StatusOK)

	// Update only tags — description should be retained.
	rr2 := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/merge-test",
		`{"tags":["tag1"]}`)
	assertStatus(t, rr2, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr2.Body).Decode(&resp) //nolint:errcheck
	if resp["description"] != "initial desc" {
		t.Errorf("merge failed: description = %v, want 'initial desc'", resp["description"])
	}
}

func TestHandleWriteMetadata_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	// Need to pre-seed the metadata so that policy deny is hit (not 404).
	// But DenyAllEngine will deny before reading the KV, so just test deny path.
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/token", `{"description":"x"}`)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleWriteMetadata_EmptyPath_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	req := httptest.NewRequest(http.MethodPost, "/metadata/", strings.NewReader(`{"description":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for empty path, got %d", rr.Code)
	}
}

func TestHandleWriteMetadata_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/token", `{"description":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleWriteMetadata_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/token", `{"description":"x"}`)
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleWriteMetadata_KVWriteError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)
	writeSecret(t, srv, "myapp/kverr", `{"value":"x"}`)

	// Now make writes fail.
	kv.errOn = "metadata"

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/myapp/kverr", `{"description":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

// ── handleListMetadata tests ──────────────────────────────────────────────────

func TestHandleListMetadata_HappyPath_ReturnsOnlyMetadata(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/api-key", `{"value":"sk-secret-123"}`)
	writeSecret(t, srv, "svc/db-pass", `{"value":"db-secret-456"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.Bytes()

	// ADVERSARIAL: secret values must NOT appear in the list response.
	if strings.Contains(string(body), "sk-secret-123") {
		t.Error("ADVERSARIAL: secret value 'sk-secret-123' found in list metadata response")
	}
	if strings.Contains(string(body), "db-secret-456") {
		t.Error("ADVERSARIAL: secret value 'db-secret-456' found in list metadata response")
	}

	var resp map[string]any
	json.NewDecoder(strings.NewReader(string(body))).Decode(&resp) //nolint:errcheck
	secrets, ok := resp["secrets"].([]any)
	if !ok {
		t.Fatalf("response has no 'secrets' array: %v", resp)
	}
	if len(secrets) < 2 {
		t.Errorf("expected at least 2 secrets in list, got %d", len(secrets))
	}

	// Verify no 'value' field in any item.
	for i, s := range secrets {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if _, hasVal := sm["value"]; hasVal {
			t.Errorf("ADVERSARIAL: secrets[%d] contains 'value' field", i)
		}
	}
}

func TestHandleListMetadata_FiltersDeleted(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/keep", `{"value":"x"}`)
	writeSecret(t, srv, "svc/delete-me", `{"value":"y"}`)

	// Soft-delete one.
	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/delete-me", "")
	assertStatus(t, rr, http.StatusNoContent)

	// List without include_deleted — should not include deleted.
	rrList := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rrList, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rrList.Body).Decode(&resp) //nolint:errcheck
	secrets := resp["secrets"].([]any)
	for _, s := range secrets {
		sm := s.(map[string]any)
		if sm["path"] == "svc/delete-me" {
			t.Error("deleted secret appeared in list without include_deleted=true")
		}
	}
}

func TestHandleListMetadata_IncludeDeleted(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/active", `{"value":"x"}`)
	writeSecret(t, srv, "svc/gone", `{"value":"y"}`)
	registryRequest(t, srv, http.MethodDelete, "/secrets/svc/gone", "")

	rrList := registryRequest(t, srv, http.MethodGet, "/metadata?include_deleted=true", "")
	assertStatus(t, rrList, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rrList.Body).Decode(&resp) //nolint:errcheck
	secrets := resp["secrets"].([]any)

	found := false
	for _, s := range secrets {
		sm := s.(map[string]any)
		if sm["path"] == "svc/gone" {
			found = true
		}
	}
	if !found {
		t.Error("deleted secret not found in list with include_deleted=true")
	}
}

func TestHandleListMetadata_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleListMetadata_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleListMetadata_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleListMetadata_ListPathsError_Returns500(t *testing.T) {
	kv := newMemKV()
	kv.listErr = fmt.Errorf("storage unavailable")
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleListMetadata_ADVERSARIAL_StripSensitiveFields(t *testing.T) {
	// Directly inject a metadata record that sneaks in a "value" field and
	// a "secret_key" field. The list endpoint must strip them.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "test/sneaky", `{"value":"legit-secret"}`)

	// Manually inject a poisoned metadata record into the KV store.
	kv.data["kv/data/metadata/test/sneaky"]["value"] = "MUST-NOT-APPEAR"
	kv.data["kv/data/metadata/test/sneaky"]["secret_master"] = "MUST-NOT-APPEAR-2"

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.String()
	if strings.Contains(body, "MUST-NOT-APPEAR") {
		t.Error("ADVERSARIAL: sensitive field leaked through list metadata response")
	}
}

// ── handleGetMetadata tests ───────────────────────────────────────────────────

func TestHandleGetMetadata_HappyPath(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/api-key", `{"value":"secret-abc"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/svc/api-key", "")
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.String()

	// ADVERSARIAL: value must not appear.
	if strings.Contains(body, "secret-abc") {
		t.Error("ADVERSARIAL: secret value found in get-metadata response")
	}

	var resp map[string]any
	json.NewDecoder(strings.NewReader(body)).Decode(&resp) //nolint:errcheck
	if resp["path"] != "svc/api-key" {
		t.Errorf("path = %v, want svc/api-key", resp["path"])
	}
}

func TestHandleGetMetadata_NotFound_Returns404(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/does/not/exist", "")
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleGetMetadata_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/svc/key", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleGetMetadata_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/svc/key", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleGetMetadata_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/svc/key", "")
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleGetMetadata_EmptyPath_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	req := httptest.NewRequest(http.MethodGet, "/metadata/", nil)
	id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for empty path, got %d", rr.Code)
	}
}

// ── handleDeleteSecret tests ──────────────────────────────────────────────────

func TestHandleDeleteSecret_SoftDelete(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/key", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key", "")
	assertStatus(t, rr, http.StatusNoContent)

	// Metadata should still exist and be marked deleted.
	metaPath := "kv/data/metadata/svc/key"
	meta, err := kv.GetSecret(context.Background(), metaPath)
	if err != nil {
		t.Fatalf("metadata should still exist after soft delete: %v", err)
	}
	if meta["meta_deleted"] != "true" {
		t.Errorf("soft delete: meta_deleted = %q, want 'true'", meta["meta_deleted"])
	}

	// Secret value should still exist.
	secretPath := "kv/data/secrets/svc/key"
	if _, err := kv.GetSecret(context.Background(), secretPath); err != nil {
		t.Error("soft delete: secret value should be retained")
	}
}

func TestHandleDeleteSecret_HardPurge(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/purge-me", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/purge-me?purge=true", "")
	assertStatus(t, rr, http.StatusNoContent)

	// Both metadata and secret value should be gone.
	if _, err := kv.GetSecret(context.Background(), "kv/data/metadata/svc/purge-me"); err == nil {
		t.Error("purge: metadata should be deleted")
	}
	if _, err := kv.GetSecret(context.Background(), "kv/data/secrets/svc/purge-me"); err == nil {
		t.Error("purge: secret value should be deleted")
	}
}

func TestHandleDeleteSecret_NotFound_Returns404(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/does/not/exist", "")
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleDeleteSecret_PolicyDeny_SoftDelete_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleDeleteSecret_PolicyDeny_Purge_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key?purge=true", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleDeleteSecret_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleDeleteSecret_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key", "")
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleDeleteSecret_EmptyPath_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/", nil)
	id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Errorf("expected non-204 for empty path, got %d", rr.Code)
	}
}

func TestHandleDeleteSecret_SoftDeleteKVError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/kverr", `{"value":"x"}`)

	// Now make metadata writes fail.
	kv.errOn = "metadata"

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/kverr", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

// ── handleSecretHistory tests (SECURITY CRITICAL) ─────────────────────────────

func TestHandleSecretHistory_HappyPath(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/versioned", `{"value":"v1"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/versioned", `{"value":"v2"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/versioned", `{"value":"v3"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/versioned?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck

	if resp["path"] != "svc/versioned" {
		t.Errorf("path = %v, want svc/versioned", resp["path"])
	}
	versions, ok := resp["versions"].([]any)
	if !ok {
		t.Fatalf("no 'versions' field in history response")
	}
	if len(versions) < 1 {
		t.Error("expected at least 1 version in history")
	}
}

func TestHandleSecretHistory_ADVERSARIAL_NoValues(t *testing.T) {
	const secretVal = "TOP-SECRET-VALUE-MUST-NOT-APPEAR-IN-HISTORY"
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/hist-test", `{"value":"`+secretVal+`"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/hist-test", `{"value":"updated-value"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/hist-test?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	if strings.Contains(rr.Body.String(), secretVal) {
		t.Error("ADVERSARIAL: secret value found in history response")
	}
	if strings.Contains(rr.Body.String(), "updated-value") {
		t.Error("ADVERSARIAL: updated secret value found in history response")
	}
}

func TestHandleSecretHistory_NotFound_Returns404(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/no/such/path?action=history", "")
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleSecretHistory_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/key?action=history", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleSecretHistory_PolicyError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newErrPolicyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/key?action=history", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleSecretHistory_NoRegistry_Returns503(t *testing.T) {
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/key?action=history", "")
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleSecretHistory_EmptyPath_Returns400(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	req := httptest.NewRequest(http.MethodGet, "/secrets/?action=history", nil)
	id := identity.Identity{CallerID: "u", TeamID: "t", Role: identity.RoleDeveloper}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for empty path, got %d", rr.Code)
	}
}

// ── handleReadSecret tests ────────────────────────────────────────────────────

func TestHandleReadSecret_HappyPath(t *testing.T) {
	kv := newMemKV()
	srv, aud := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/readable", `{"value":"readable-value"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/readable", "")
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.String()
	if !strings.Contains(body, "readable-value") {
		t.Error("read secret: expected value in response")
	}

	// Audit event must be logged for read.
	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event for secret read")
	}
	if ev.Operation != "credential_vend" {
		t.Errorf("audit operation = %q, want credential_vend", ev.Operation)
	}
	if ev.Outcome != "success" {
		t.Errorf("audit outcome = %q, want success", ev.Outcome)
	}
}

func TestHandleReadSecret_NotFound_Returns404(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/no/such/secret", "")
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleReadSecret_PolicyDeny_Returns403(t *testing.T) {
	kv := newMemKV()
	srv, _ := newDenyRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/key", "")
	assertStatus(t, rr, http.StatusForbidden)
}

func TestHandleReadSecret_AuditLoggedForEveryRead(t *testing.T) {
	kv := newMemKV()
	srv, aud := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/audited", `{"value":"x"}`)
	startCount := aud.eventCount()

	registryRequest(t, srv, http.MethodGet, "/secrets/svc/audited", "")
	registryRequest(t, srv, http.MethodGet, "/secrets/svc/audited", "")
	registryRequest(t, srv, http.MethodGet, "/secrets/svc/audited", "")

	// 3 reads should produce 3 audit events (in addition to the 1 write).
	if aud.eventCount()-startCount < 3 {
		t.Errorf("expected ≥3 read audit events, got %d", aud.eventCount()-startCount)
	}
}

func TestHandleReadSecret_NoRegistry_Returns400(t *testing.T) {
	// When registryWriter is nil, handleReadSecret returns 400 (path required / no registry).
	srv, _ := newAllowRegistryServer(t, nil)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/svc/key", "")
	// Expect 400 (empty path or no registry) — not a server panic.
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 when registry not configured, got %d", rr.Code)
	}
}

// ── Helper function unit tests ─────────────────────────────────────────────────

func TestSecretKVPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"myapp/token", "kv/data/secrets/myapp/token"},
		{"cloudflare/dns-key", "kv/data/secrets/cloudflare/dns-key"},
		{"a/b/c", "kv/data/secrets/a/b/c"},
	}
	// Test via round-trip write+read since secretKVPath is unexported.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			writeSecret(t, srv, tc.input, `{"value":"test"}`)
			if _, ok := kv.data[tc.want]; !ok {
				t.Errorf("expected data at KV path %q", tc.want)
			}
		})
	}
}

func TestMetadataKVPath_ViaWrite(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/token", `{"value":"x"}`)

	// Metadata should be at the expected path.
	metaPath := "kv/data/metadata/svc/token"
	if _, ok := kv.data[metaPath]; !ok {
		t.Errorf("metadata not found at expected path %q", metaPath)
	}
}

func TestVersionKVPath_ViaVersioning(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/vers", `{"value":"v1"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/vers", `{"value":"v2"}`)

	// Old version should be archived at kv/data/secrets/svc/vers/v1.
	archivePath := "kv/data/secrets/svc/vers/v1"
	if _, ok := kv.data[archivePath]; !ok {
		t.Errorf("version archive not found at %q", archivePath)
	}
}

func TestMetadataFromMap_RoundTrip(t *testing.T) {
	// Test via write+get: write a secret, update metadata, read it back.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "rt/test", `{"value":"x"}`)
	registryRequest(t, srv, http.MethodPost, "/metadata/rt/test",
		`{"description":"round-trip desc","tags":["a","b"],"type":"database","expires":"2030-01-01T00:00:00Z"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/rt/test", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck

	if resp["description"] != "round-trip desc" {
		t.Errorf("description = %v", resp["description"])
	}
	if resp["type"] != "database" {
		t.Errorf("type = %v", resp["type"])
	}
	if resp["expires"] != "2030-01-01T00:00:00Z" {
		t.Errorf("expires = %v", resp["expires"])
	}
	tags, _ := resp["tags"].([]any)
	if len(tags) != 2 {
		t.Errorf("tags = %v, want 2 elements", resp["tags"])
	}
}

func TestStripSensitiveFields_DirectTest(t *testing.T) {
	// Since stripSensitiveFields is unexported, we test it via the list endpoint
	// by injecting poisoned metadata fields.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "strip/test", `{"value":"actual-secret"}`)

	// Poison the metadata record.
	kv.data["kv/data/metadata/strip/test"]["value"] = "MUST-NOT-LEAK"
	kv.data["kv/data/metadata/strip/test"]["secret_key"] = "ALSO-MUST-NOT-LEAK"
	kv.data["kv/data/metadata/strip/test"]["my_value_field"] = "ALSO-STRIP-THIS"

	// Test via get-metadata.
	rr := registryRequest(t, srv, http.MethodGet, "/metadata/strip/test", "")
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.String()
	for _, forbidden := range []string{"MUST-NOT-LEAK", "ALSO-MUST-NOT-LEAK", "ALSO-STRIP-THIS"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("ADVERSARIAL: sensitive field %q leaked in get-metadata response", forbidden)
		}
	}
}

func TestParseVersionsHistory_Empty(t *testing.T) {
	// Test via history endpoint on a fresh secret (no prior versions).
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "hist/empty", `{"value":"only-version"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/hist/empty?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	versions, _ := resp["versions"].([]any)
	// Should have exactly 1 version (the current one).
	if len(versions) != 1 {
		t.Errorf("expected 1 version for new secret, got %d", len(versions))
	}
}

func TestParseVersionsHistory_MultipleVersions(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "hist/multi", `{"value":"v1"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/hist/multi", `{"value":"v2"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/hist/multi", `{"value":"v3"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/hist/multi?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	versions, _ := resp["versions"].([]any)
	// v1 archived, v2 archived, v3 current → at least 3 entries.
	if len(versions) < 3 {
		t.Errorf("expected ≥3 versions, got %d", len(versions))
	}
}

func TestMetadataToResponse_ServiceAndName(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "cloudflare/dns-token", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/cloudflare/dns-token", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck

	if resp["service"] != "cloudflare" {
		t.Errorf("service = %v, want cloudflare", resp["service"])
	}
	if resp["name"] != "dns-token" {
		t.Errorf("name = %v, want dns-token", resp["name"])
	}
}

func TestMetadataToResponse_SingleSegmentPath(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "standalone", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/standalone", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	// For single segment path: service=path, name="" (omitempty).
	if resp["service"] != "standalone" {
		t.Errorf("service = %v, want standalone", resp["service"])
	}
}

// ── Audit integrity tests ─────────────────────────────────────────────────────

func TestRegistryAudit_AllOperationsLogged(t *testing.T) {
	kv := newMemKV()
	srv, aud := newAllowRegistryServer(t, kv)

	// Write.
	writeSecret(t, srv, "audit/test", `{"value":"x"}`)
	// Update metadata.
	registryRequest(t, srv, http.MethodPost, "/metadata/audit/test", `{"description":"test"}`)
	// List.
	registryRequest(t, srv, http.MethodGet, "/metadata", "")
	// Get metadata.
	registryRequest(t, srv, http.MethodGet, "/metadata/audit/test", "")
	// Read secret.
	registryRequest(t, srv, http.MethodGet, "/secrets/audit/test", "")
	// History.
	registryRequest(t, srv, http.MethodGet, "/secrets/audit/test?action=history", "")
	// Delete.
	registryRequest(t, srv, http.MethodDelete, "/secrets/audit/test", "")

	// Every operation should have produced an audit event.
	if aud.eventCount() < 7 {
		t.Errorf("expected ≥7 audit events for 7 operations, got %d", aud.eventCount())
	}

	// All events must have required fields.
	for i, ev := range aud.events {
		if ev.CallerID == "" {
			t.Errorf("audit event[%d]: CallerID is empty", i)
		}
		if ev.Operation == "" {
			t.Errorf("audit event[%d]: Operation is empty", i)
		}
		if ev.Outcome == "" {
			t.Errorf("audit event[%d]: Outcome is empty", i)
		}
	}
}

func TestRegistryAudit_DeniedOpsLogged(t *testing.T) {
	kv := newMemKV()
	srv, aud := newDenyRegistryServer(t, kv)

	registryRequest(t, srv, http.MethodPost, "/secrets/svc/key", `{"value":"x"}`)
	registryRequest(t, srv, http.MethodGet, "/metadata", "")
	registryRequest(t, srv, http.MethodDelete, "/secrets/svc/key", "")

	// Policy denials must still be audited.
	if aud.eventCount() < 3 {
		t.Errorf("expected ≥3 denial audit events, got %d", aud.eventCount())
	}
	for i, ev := range aud.events {
		if ev.Outcome != "denied" {
			t.Errorf("audit event[%d]: outcome = %q, want denied", i, ev.Outcome)
		}
	}
}

// ── Content-Type tests ────────────────────────────────────────────────────────

func TestRegistryEndpoints_ContentTypeIsJSON(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "ct/test", `{"value":"x"}`)

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/secrets/ct/test2", `{"value":"y"}`},
		{http.MethodGet, "/metadata", ""},
		{http.MethodGet, "/metadata/ct/test", ""},
		{http.MethodGet, "/secrets/ct/test", ""},
		{http.MethodGet, "/secrets/ct/test?action=history", ""},
	}

	for _, ep := range endpoints {
		rr := registryRequest(t, srv, ep.method, ep.path, ep.body)
		ct := rr.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s %s: Content-Type = %q, want application/json", ep.method, ep.path, ct)
		}
	}
}

// ── Purge with version cleanup ────────────────────────────────────────────────

func TestHandleDeleteSecret_PurgeRemovesVersions(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "svc/purge-versions", `{"value":"v1"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/purge-versions", `{"value":"v2"}`)
	registryRequest(t, srv, http.MethodPost, "/secrets/svc/purge-versions", `{"value":"v3"}`)

	// Purge everything.
	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/svc/purge-versions?purge=true", "")
	assertStatus(t, rr, http.StatusNoContent)

	// Nothing should remain.
	for path := range kv.data {
		if strings.Contains(path, "purge-versions") {
			t.Errorf("purge: path %q still exists after purge", path)
		}
	}
}

// ── Non-string value fields ───────────────────────────────────────────────────

func TestHandleWriteSecret_NonStringValues(t *testing.T) {
	// Registry should accept non-string JSON values (number, bool) and store their
	// JSON representation.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/misc/config",
		`{"port":5432,"enabled":true,"name":"mydb"}`)
	assertStatus(t, rr, http.StatusCreated)
}

// ── handleGetSecretOrHistory routing ─────────────────────────────────────────

func TestHandleGetSecretOrHistory_RoutesToHistory(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "route/test", `{"value":"x"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/route/test?action=history", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	if _, hasVersions := resp["versions"]; !hasVersions {
		t.Errorf("action=history should return versions, got: %v", resp)
	}
}

func TestHandleGetSecretOrHistory_RoutesToRead(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "route/read-test", `{"value":"readable"}`)

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/route/read-test", "")
	assertStatus(t, rr, http.StatusOK)

	if !strings.Contains(rr.Body.String(), "readable") {
		t.Error("expected secret value in read response")
	}
}

// ── Additional edge-case tests for remaining coverage gaps ────────────────────

func TestHandleGetMetadata_KVGetError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Pre-seed a metadata record so the path exists but then make GetSecret fail.
	writeSecret(t, srv, "meta/kverr", `{"value":"x"}`)

	// Now cause GetSecret to return a non-not-found error for metadata paths.
	kv.getErrOn = "metadata/meta/kverr"

	rr := registryRequest(t, srv, http.MethodGet, "/metadata/meta/kverr", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleWriteMetadata_KVGetError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "meta/write-kverr", `{"value":"x"}`)

	// Cause GetSecret to fail for metadata reads on this path.
	kv.getErrOn = "metadata/meta/write-kverr"

	rr := registryRequest(t, srv, http.MethodPost, "/metadata/meta/write-kverr", `{"description":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleDeleteSecret_PurgeSecretDeleteError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "del/secret-err", `{"value":"x"}`)

	// Make DeleteSecret fail for the secret value path (not metadata).
	kv.deleteErrOn = "secrets/del/secret-err"

	rr := registryRequest(t, srv, http.MethodDelete, "/secrets/del/secret-err?purge=true", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleSecretHistory_KVGetError_Returns500(t *testing.T) {
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "hist/kverr", `{"value":"x"}`)

	// Cause metadata read to return non-not-found error.
	kv.getErrOn = "metadata/hist/kverr"

	rr := registryRequest(t, srv, http.MethodGet, "/secrets/hist/kverr?action=history", "")
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleWriteSecret_MetadataWriteError_Returns500(t *testing.T) {
	// First write succeeds (secret), second write (metadata) fails.
	// We use a targeted errOn to only fail the metadata path.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	// Pre-seed so the secret appears to exist for the "update" path (version archival).
	// On a new write, the code writes secret first then metadata.
	// We want to fail the metadata write on a new (first-time) write.
	kv.errOn = "metadata/new/meta-fail"

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/new/meta-fail", `{"value":"x"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}

func TestHandleListMetadata_EmptyList(t *testing.T) {
	// Registry configured but no secrets — should return empty array.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	rr := registryRequest(t, srv, http.MethodGet, "/metadata", "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	secrets, ok := resp["secrets"].([]any)
	if !ok {
		t.Fatalf("expected 'secrets' array, got %v", resp)
	}
	if len(secrets) != 0 {
		t.Errorf("expected empty list, got %d secrets", len(secrets))
	}
}

func TestHandleWriteSecret_VersionArchivalError_Returns500(t *testing.T) {
	// Create a secret, then make the version archive write fail on update.
	kv := newMemKV()
	srv, _ := newAllowRegistryServer(t, kv)

	writeSecret(t, srv, "ver/archive-fail", `{"value":"original"}`)

	// Now make writes to /v fail.
	kv.errOn = "/v"

	rr := registryRequest(t, srv, http.MethodPost, "/secrets/ver/archive-fail", `{"value":"updated"}`)
	assertStatus(t, rr, http.StatusInternalServerError)
}
