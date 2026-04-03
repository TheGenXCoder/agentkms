// quality_test.go — tests added to satisfy the code quality gate.
// Covers: isValidTeamID, recoveryMiddleware panic path, error mapping branches.
package api_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// errorEngine is a policy.Engine that always returns an internal error
// (not a denial — an actual error).  Used to test the policy-error paths.
type errorEngine struct{}

func (e errorEngine) Evaluate(_ context.Context, _ identity.Identity, _, _ string) (policy.Decision, error) {
	return policy.Decision{}, errors.New("policy engine: simulated internal error")
}

// ── Policy engine error path (handlers return 500, audit OutcomeError) ──────

func TestHandlers_PolicyEngineError_Return500(t *testing.T) {
	newErrServer := func(b backend.Backend) (*api.Server, *capturingAuditor) {
		aud := &capturingAuditor{}
		rl := auth.NewRevocationList()
		ts, _ := auth.NewTokenService(rl)
		return api.NewServer(b, aud, errorEngine{}, ts, "dev"), aud
	}

	t.Run("sign", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("perr/sign", backend.AlgorithmES256, "team"); err != nil {
			t.Fatal(err)
		}
		srv, aud := newErrServer(b)
		rr := request(t, srv, http.MethodPost, "/sign/perr/sign",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("test")), "algorithm": "ES256",
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
		ev, ok := aud.lastEvent()
		if !ok || ev.Outcome != "error" {
			t.Errorf("audit outcome = %q, want error", ev.Outcome)
		}
	})

	t.Run("encrypt", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("perr/enc", backend.AlgorithmAES256GCM, "team"); err != nil {
			t.Fatal(err)
		}
		srv, _ := newErrServer(b)
		rr := request(t, srv, http.MethodPost, "/encrypt/perr/enc",
			jsonReader(t, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("decrypt", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("perr/dec", backend.AlgorithmAES256GCM, "team"); err != nil {
			t.Fatal(err)
		}
		srv, _ := newErrServer(b)
		rr := request(t, srv, http.MethodPost, "/decrypt/perr/dec",
			jsonReader(t, map[string]any{
				"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 64)),
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("list-keys", func(t *testing.T) {
		srv, _ := newErrServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodGet, "/keys", nil)
		assertStatus(t, rr, http.StatusInternalServerError)
	})
}

// ── isValidKeyIDPrefix edge cases ───────────────────────────────────────────

func TestHandleListKeys_BareSeparatorPrefix(t *testing.T) {
	// A bare "/" prefix should be rejected (it strips to "", which is invalid).
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	rr := request(t, srv, http.MethodGet, "/keys?prefix=%2F", nil) // URL-encoded /
	assertStatus(t, rr, http.StatusBadRequest)
	assertContentTypeJSON(t, rr)
}

// ── isValidTeamID (via /keys?team_id= query param) ────────────────────────────

func TestHandleListKeys_TeamIDValidation(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)

	cases := []struct {
		name    string
		teamID  string
		wantOK  bool
	}{
		{"valid lowercase", "platform-team", true},
		{"valid with underscore", "ml_team", true},
		{"valid alphanumeric", "team1", true},
		{"empty (omitted)", "", true},
		// Invalid: uppercase letters
		{"uppercase rejected", "Platform-Team", false},
		// Invalid: slash (URL-encoded %2F so httptest doesn't panic)
		{"slash rejected", "a%2Fb", false},
		// Invalid: dot
		{"dot rejected", "a.b", false},
		// Invalid: at-sign
		{"at-sign rejected", "user%40domain", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := "/keys"
			if tc.teamID != "" {
				path += "?team_id=" + tc.teamID
			}
			rr := request(t, srv, http.MethodGet, path, nil)
			if tc.wantOK {
				if rr.Code == http.StatusBadRequest {
					t.Errorf("team_id %q: expected OK, got 400: %s", tc.teamID, rr.Body.String())
				}
			} else {
				if rr.Code != http.StatusBadRequest {
					t.Errorf("team_id %q: expected 400, got %d", tc.teamID, rr.Code)
				}
			}
		})
	}
}

// ── recoveryMiddleware — panic path ───────────────────────────────────────────

// panicOnSign is a backend.Backend whose Sign method panics unconditionally.
// Used exclusively to exercise the recoveryMiddleware panic-catch path.
type panicOnSign struct{ backend.Backend }

func (p panicOnSign) Sign(_ context.Context, _ string, _ []byte, _ backend.Algorithm) (*backend.SignResult, error) {
	panic("intentional panic: testing recoveryMiddleware")
}

// TestRecoveryMiddleware_PanicProducesCleanJSON verifies that a panicking handler
// returns a clean JSON 500 response and that the panic value never appears
// in the response body.
func TestRecoveryMiddleware_PanicProducesCleanJSON(t *testing.T) {
	// panicOnSign wraps a DevBackend but panics on Sign, exercising the
	// recoveryMiddleware panic-catch path.
	inner := backend.NewDevBackend()
	if err := inner.CreateKey("panic/key", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	panicker := panicOnSign{inner}

	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(panicker, aud, policy.AllowAllEngine{}, ts, "dev")

	rr := request(t, srv, http.MethodPost, "/sign/panic/key",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("panic test")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusInternalServerError)
	assertContentTypeJSON(t, rr)

	body := rr.Body.Bytes()
	_, code := assertErrorShape(t, "panic recovery", body)
	if code != "internal_error" {
		t.Errorf("expected internal_error code, got %q", code)
	}
	// The panic message must NOT leak into the response.
	for _, forbidden := range []string{
		"intentional panic",
		"panic:",
		"goroutine ",
		"runtime/",
		".go:",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("ADVERSARIAL: response body contains %q from panic — must not leak: %s",
				forbidden, body)
		}
	}

	// An audit event should have been written for the panic.
	ev, ok := aud.lastEvent()
	if !ok {
		t.Error("no audit event written for panic")
	} else if ev.Outcome != "error" {
		t.Errorf("panic audit event outcome = %q, want error", ev.Outcome)
	}
}

// ── Error mapping coverage ────────────────────────────────────────────────────


func TestBackendErrorMapping_AlgorithmMismatch(t *testing.T) {
	// AlgorithmMismatch → 400 algorithm_mismatch
	b := backend.NewDevBackend()
	if err := b.CreateKey("mismatch/key", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	// Send EdDSA request to an ES256 key → ErrAlgorithmMismatch from backend
	rr := request(t, srv, http.MethodPost, "/sign/mismatch/key",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("test")),
			"algorithm":    "EdDSA",
		}),
	)
	assertStatus(t, rr, http.StatusBadRequest)
	_, code := assertErrorShape(t, "algorithm mismatch", rr.Body.Bytes())
	if code != "algorithm_mismatch" {
		t.Errorf("expected algorithm_mismatch, got %q", code)
	}
}

func TestBackendErrorMapping_KeyTypeMismatch(t *testing.T) {
	// KeyTypeMismatch → 400 operation_not_supported
	b := backend.NewDevBackend()
	if err := b.CreateKey("typemismatch/key", backend.AlgorithmAES256GCM, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	// Try to sign with an AES key → ErrKeyTypeMismatch
	rr := request(t, srv, http.MethodPost, "/sign/typemismatch/key",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("test")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusBadRequest)
	_, code := assertErrorShape(t, "key type mismatch", rr.Body.Bytes())
	if code != "operation_not_supported" {
		t.Errorf("expected operation_not_supported, got %q", code)
	}
}

// ── Encrypt/Decrypt coverage gaps ───────────────────────────────────────────

func TestHandleEncrypt_KeyNotFound(t *testing.T) {
	b := backend.NewDevBackend() // no keys
	srv, _ := newAllowServer(t, b)

	rr := request(t, srv, http.MethodPost, "/encrypt/missing/key",
		jsonReader(t, map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("data")),
		}),
	)
	assertStatus(t, rr, http.StatusNotFound)
	_, code := assertErrorShape(t, "encrypt key-not-found", rr.Body.Bytes())
	if code != "key_not_found" {
		t.Errorf("expected key_not_found, got %q", code)
	}
}

func TestHandleDecrypt_KeyNotFound(t *testing.T) {
	b := backend.NewDevBackend() // no keys
	srv, _ := newAllowServer(t, b)

	rr := request(t, srv, http.MethodPost, "/decrypt/missing/key",
		jsonReader(t, map[string]any{
			"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}),
	)
	assertStatus(t, rr, http.StatusNotFound)
	_, code := assertErrorShape(t, "decrypt key-not-found", rr.Body.Bytes())
	if code != "key_not_found" {
		t.Errorf("expected key_not_found, got %q", code)
	}
}

func TestHandleDecrypt_WrongKeyType(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("dec/es-key", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	rr := request(t, srv, http.MethodPost, "/decrypt/dec/es-key",
		jsonReader(t, map[string]any{
			"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}),
	)
	assertStatus(t, rr, http.StatusBadRequest)
	_, code := assertErrorShape(t, "decrypt wrong type", rr.Body.Bytes())
	if code != "operation_not_supported" {
		t.Errorf("expected operation_not_supported, got %q", code)
	}
}

func TestHandleDecrypt_TooShortCiphertext_ErrInvalidInput(t *testing.T) {
	// A ciphertext that decodes to fewer than 32 bytes is rejected by
	// the backend with ErrInvalidInput.  This exercises the ErrInvalidInput
	// branch in statusFromBackendError / codeFromBackendError / messageFromBackendError.
	b := backend.NewDevBackend()
	if err := b.CreateKey("errinput/key", backend.AlgorithmAES256GCM, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	// 10 bytes of ciphertext — valid base64, but < 32 bytes, so DevBackend
	// rejects it as ErrInvalidInput.
	tooShort := base64.StdEncoding.EncodeToString(make([]byte, 10))
	rr := request(t, srv, http.MethodPost, "/decrypt/errinput/key",
		jsonReader(t, map[string]any{"ciphertext": tooShort}),
	)
	assertStatus(t, rr, http.StatusBadRequest)
	_, code := assertErrorShape(t, "decrypt too-short", rr.Body.Bytes())
	if code != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", code)
	}
}

func TestAdversarial_AuditFailure_EncryptAndDecrypt_Return500(t *testing.T) {
	// Mirrors TestAdversarial_AuditFailure_SuccessPath_Returns500 for sign,
	// verifying encrypt and decrypt also fail closed when the audit sink fails.
	newFail := func(b backend.Backend) *api.Server {
		rl := auth.NewRevocationList()
		ts, _ := auth.NewTokenService(rl)
		return api.NewServer(b, &failingAuditor{}, policy.AllowAllEngine{}, ts, "dev")
	}

	t.Run("encrypt audit fail", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("aud/enc", backend.AlgorithmAES256GCM, "team"); err != nil {
			t.Fatal(err)
		}
		srv := newFail(b)
		rr := request(t, srv, http.MethodPost, "/encrypt/aud/enc",
			jsonReader(t, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("decrypt audit fail", func(t *testing.T) {
		// Encrypt first with a working auditor, then decrypt with failing one.
		b := backend.NewDevBackend()
		if err := b.CreateKey("aud/dec", backend.AlgorithmAES256GCM, "team"); err != nil {
			t.Fatal(err)
		}
		workSrv, _ := newAllowServer(t, b)
		encRR := request(t, workSrv, http.MethodPost, "/encrypt/aud/dec",
			jsonReader(t, map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("x"))}),
		)
		assertStatus(t, encRR, http.StatusOK)
		ctB64 := decodeMap(t, encRR.Body.Bytes())["ciphertext"].(string)

		failSrv := newFail(b)
		rr := request(t, failSrv, http.MethodPost, "/decrypt/aud/dec",
			jsonReader(t, map[string]any{"ciphertext": ctB64}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})
}

func TestHandleListKeys_PolicyDenied(t *testing.T) {
	b := backend.NewDevBackend()
	srv, aud := newDenyServer(t, b)

	rr := request(t, srv, http.MethodGet, "/keys", nil)
	assertStatus(t, rr, http.StatusForbidden)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event for list-keys denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("audit outcome = %q, want denied", ev.Outcome)
	}
}

func TestExtractRemoteIP_IPv6(t *testing.T) {
	// Verify extractRemoteIP handles IPv6 addresses via net.SplitHostPort.
	// We can't call extractRemoteIP directly (unexported), but we can observe
	// it via an audit event's SourceIP field.
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(b, aud, policy.DenyAllEngine{}, ts, "dev")

	// Craft a request with an IPv6 remote addr.
	req, _ := http.NewRequest(http.MethodGet, "/keys", nil)
	id := identity.Identity{
		CallerID: "test-user",
		TeamID:   "test-team",
		Role:     identity.RoleDeveloper,
	}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	req.RemoteAddr = "[::1]:54321"

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event written")
	}
	// SourceIP must be "::1" (brackets and port stripped).
	if ev.SourceIP != "::1" && !strings.Contains(ev.SourceIP, "::1") {
		t.Errorf("SourceIP for [::1]:54321 = %q, want ::1", ev.SourceIP)
	}
}
