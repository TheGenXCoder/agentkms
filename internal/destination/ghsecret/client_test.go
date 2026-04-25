package ghsecret

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// newTestServer creates an httptest server that records requests.
// The handler func h is called for each request.
func newTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// freshKeyPair generates a Curve25519 keypair for test use.
func freshKeyPair(t *testing.T) (pub *[32]byte, priv *[32]byte, pubB64 string) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 = base64.StdEncoding.EncodeToString(pub[:])
	return pub, priv, pubB64
}

// TestClient_PutSecret_HappyPath verifies that PutSecret sends a proper
// encrypted value and key_id to the GitHub API.
func TestClient_PutSecret_HappyPath(t *testing.T) {
	t.Parallel()

	pub, priv, pubB64 := freshKeyPair(t)

	var recorded putSecretBody
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "public-key") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(publicKeyResponse{KeyID: "key1", Key: pubB64})
			return
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "secrets") {
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &recorded)
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})

	client := newGHClient(srv.URL, "tok-test", nil)
	encB64, err := SealBase64([]byte("my-secret"), pubB64)
	if err != nil {
		t.Fatalf("SealBase64: %v", err)
	}
	if err := client.PutSecret(context.Background(), "owner", "repo", "MY_SECRET", encB64, "key1"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	if recorded.KeyID != "key1" {
		t.Errorf("key_id: got %q, want %q", recorded.KeyID, "key1")
	}
	if recorded.EncryptedValue == "" {
		t.Error("encrypted_value is empty")
	}

	// Decrypt to verify content.
	ctBytes, err := base64.StdEncoding.DecodeString(recorded.EncryptedValue)
	if err != nil {
		t.Fatalf("decode encrypted_value: %v", err)
	}
	recovered, ok := box.OpenAnonymous(nil, ctBytes, pub, priv)
	if !ok {
		t.Fatal("OpenAnonymous: decryption failed")
	}
	if string(recovered) != "my-secret" {
		t.Errorf("decrypted: got %q, want %q", recovered, "my-secret")
	}
}

// TestClient_PutSecret_404 verifies that a 404 from the server is classified as
// a permanent TARGET_NOT_FOUND error.
func TestClient_PutSecret_404(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsTargetNotFound(err) {
		t.Errorf("expected TARGET_NOT_FOUND, got: %v", err)
	}
	if !IsPermanent(err) {
		t.Errorf("expected permanent error, got transient: %v", err)
	}
}

// TestClient_PutSecret_401 verifies that a 401 is classified as a permanent
// PERMISSION_DENIED error.
func TestClient_PutSecret_401(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Bad credentials"}`)
	})

	client := newGHClient(srv.URL, "bad-tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsPermissionDenied(err) {
		t.Errorf("expected PERMISSION_DENIED, got: %v", err)
	}
	if !IsPermanent(err) {
		t.Errorf("expected permanent error: %v", err)
	}
}

// TestClient_PutSecret_RateLimited verifies that a 429 is classified as a transient error.
func TestClient_PutSecret_RateLimited(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"message":"rate limited"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if IsPermanent(err) {
		t.Errorf("expected transient error, got permanent: %v", err)
	}
}

// TestClient_PutSecret_422 verifies that a 422 (stale key_id) is transient.
func TestClient_PutSecret_422(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"key_id mismatch"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if IsPermanent(err) {
		t.Errorf("expected transient error for 422, got permanent: %v", err)
	}
}

// TestClient_FetchPublicKey_HappyPath verifies FetchPublicKey parses the response.
func TestClient_FetchPublicKey_HappyPath(t *testing.T) {
	t.Parallel()

	_, _, pubB64 := freshKeyPair(t)
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(publicKeyResponse{KeyID: "abc123", Key: pubB64})
	})

	client := newGHClient(srv.URL, "tok", nil)
	keyID, key, err := client.FetchPublicKey(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("FetchPublicKey: %v", err)
	}
	if keyID != "abc123" {
		t.Errorf("keyID: got %q, want %q", keyID, "abc123")
	}
	if key != pubB64 {
		t.Errorf("key: got %q, want %q", key, pubB64)
	}
}

// TestClient_DeleteSecret_Idempotent verifies that a 404 on DeleteSecret is success.
func TestClient_DeleteSecret_Idempotent(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.DeleteSecret(context.Background(), "o", "r", "S")
	if err != nil {
		t.Errorf("DeleteSecret 404 should be success, got: %v", err)
	}
}

// TestClient_Ping_OK verifies Ping returns no error on 200.
func TestClient_Ping_OK(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zen" {
			fmt.Fprint(w, "Non-blocking is better than blocking.")
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})

	client := newGHClient(srv.URL, "", nil)
	latency, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if latency < 0 {
		t.Errorf("latency should be >= 0, got %d", latency)
	}
}

// ── Sentinel error propagation tests ──────────────────────────────────────────

// TestSentinel_404_IsTargetNotFound verifies that a 404 response from the
// GitHub API produces an error that satisfies errors.Is(err, ErrTargetNotFound).
func TestSentinel_404_IsTargetNotFound(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("errors.Is(err, ErrTargetNotFound) = false; err = %v", err)
	}
	// Must NOT match unrelated sentinels.
	if errors.Is(err, ErrPermissionDenied) {
		t.Errorf("404 error should not match ErrPermissionDenied")
	}
	if errors.Is(err, ErrTransient) {
		t.Errorf("404 error should not match ErrTransient")
	}
}

// TestSentinel_401_IsPermissionDenied verifies that a 401 response produces an
// error satisfying errors.Is(err, ErrPermissionDenied).
func TestSentinel_401_IsPermissionDenied(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Bad credentials"}`)
	})

	client := newGHClient(srv.URL, "bad-tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("errors.Is(err, ErrPermissionDenied) = false; err = %v", err)
	}
	if errors.Is(err, ErrTargetNotFound) {
		t.Errorf("401 error should not match ErrTargetNotFound")
	}
}

// TestSentinel_403_IsPermissionDenied verifies that a 403 response also
// satisfies errors.Is(err, ErrPermissionDenied).
func TestSentinel_403_IsPermissionDenied(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"Forbidden"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("errors.Is(err, ErrPermissionDenied) = false for 403; err = %v", err)
	}
}

// TestSentinel_500_IsTransient verifies that a 5xx response produces an error
// satisfying errors.Is(err, ErrTransient).
func TestSentinel_500_IsTransient(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"Internal Server Error"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTransient) {
		t.Errorf("errors.Is(err, ErrTransient) = false for 500; err = %v", err)
	}
	if errors.Is(err, ErrPermanent) {
		t.Errorf("500 error should not match ErrPermanent")
	}
}

// TestSentinel_422_IsTransient verifies that a 422 (stale key_id) produces an
// error satisfying errors.Is(err, ErrTransient).
func TestSentinel_422_IsTransient(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"key_id mismatch"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	err := client.PutSecret(context.Background(), "o", "r", "S", "enc", "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTransient) {
		t.Errorf("errors.Is(err, ErrTransient) = false for 422; err = %v", err)
	}
}

// TestSentinel_FetchPublicKey_404 verifies that FetchPublicKey 404 also
// propagates ErrTargetNotFound correctly.
func TestSentinel_FetchPublicKey_404(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	client := newGHClient(srv.URL, "tok", nil)
	_, _, err := client.FetchPublicKey(context.Background(), "o", "r")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("errors.Is(err, ErrTargetNotFound) = false for FetchPublicKey 404; err = %v", err)
	}
}
