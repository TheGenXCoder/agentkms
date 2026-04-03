// Package backend — unit tests for DualRunBackend.
package backend

import (
	"context"
	"errors"
	"testing"
)

func TestNewDualRunBackend_NilCheck(t *testing.T) {
	if _, err := NewDualRunBackend(nil, nil); err == nil {
		t.Fatal("expected error when both backends are nil")
	}
	dev := &DevBackend{}
	if _, err := NewDualRunBackend(dev, nil); err == nil {
		t.Fatal("expected error when new backend is nil")
	}
	if _, err := NewDualRunBackend(nil, dev); err == nil {
		t.Fatal("expected error when old backend is nil")
	}
}

func TestDualRunBackend_Sign_UsesNew(t *testing.T) {
	oldB := &mockBackend{name: "old"}
	newB := &mockBackend{name: "new"}
	dual, _ := NewDualRunBackend(oldB, newB)

	_, err := dual.Sign(context.Background(), "test-key", make([]byte, 32), AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if oldB.signCalled {
		t.Fatal("Sign: called old backend, expected only new")
	}
	if !newB.signCalled {
		t.Fatal("Sign: new backend not called")
	}
}

func TestDualRunBackend_Encrypt_UsesNew(t *testing.T) {
	oldB := &mockBackend{name: "old"}
	newB := &mockBackend{name: "new"}
	dual, _ := NewDualRunBackend(oldB, newB)

	_, err := dual.Encrypt(context.Background(), "test-key", []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if oldB.encryptCalled {
		t.Fatal("Encrypt: called old backend, expected only new")
	}
	if !newB.encryptCalled {
		t.Fatal("Encrypt: new backend not called")
	}
}

func TestDualRunBackend_Decrypt_Fallback(t *testing.T) {
	ctx := context.Background()
	oldB := &mockBackend{name: "old"}
	newB := &mockBackend{name: "new", decryptErr: ErrKeyNotFound} // simulate key not yet in new
	dual, _ := NewDualRunBackend(oldB, newB)

	_, err := dual.Decrypt(ctx, "test-key", []byte("ciphertext"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !newB.decryptCalled {
		t.Fatal("Decrypt: new backend not called first")
	}
	if !oldB.decryptCalled {
		t.Fatal("Decrypt: old backend not called as fallback")
	}
}

func TestDualRunBackend_Decrypt_NoFallbackOnSystemError(t *testing.T) {
	ctx := context.Background()
	oldB := &mockBackend{name: "old"}
	// A generic system error (e.g. network failure) should not trigger fallback.
	sysErr := errors.New("network failure")
	newB := &mockBackend{name: "new", decryptErr: sysErr}
	dual, _ := NewDualRunBackend(oldB, newB)

	_, err := dual.Decrypt(ctx, "test-key", []byte("ciphertext"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sysErr) {
		t.Fatalf("expected network failure error, got: %v", err)
	}

	if !newB.decryptCalled {
		t.Fatal("Decrypt: new backend not called")
	}
	if oldB.decryptCalled {
		t.Fatal("Decrypt: old backend called, but should only fallback on ErrKeyNotFound/ErrInvalidInput")
	}
}

func TestDualRunBackend_ListKeys_MergesResults(t *testing.T) {
	ctx := context.Background()
	oldB := &mockBackend{
		name: "old",
		keys: []*KeyMeta{
			{KeyID: "key1", Algorithm: AlgorithmES256, Version: 1},
			{KeyID: "key2", Algorithm: AlgorithmRS256, Version: 2},
		},
	}
	newB := &mockBackend{
		name: "new",
		keys: []*KeyMeta{
			{KeyID: "key2", Algorithm: AlgorithmRS256, Version: 3}, // newer version in new backend
			{KeyID: "key3", Algorithm: AlgorithmEdDSA, Version: 1},
		},
	}
	dual, _ := NewDualRunBackend(oldB, newB)

	keys, err := dual.ListKeys(ctx, KeyScope{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	// Expecting: key1 (old), key2 (new), key3 (new).
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	keyMap := make(map[string]*KeyMeta)
	for _, m := range keys {
		keyMap[m.KeyID] = m
	}

	if keyMap["key1"].Version != 1 {
		t.Errorf("key1: want version 1, got %d", keyMap["key1"].Version)
	}
	if keyMap["key2"].Version != 3 {
		t.Errorf("key2: want version 3 (from new backend), got %d", keyMap["key2"].Version)
	}
	if keyMap["key3"].Version != 1 {
		t.Errorf("key3: want version 1, got %d", keyMap["key3"].Version)
	}
}

func TestDualRunBackend_RotateKey_UsesNew(t *testing.T) {
	oldB := &mockBackend{name: "old"}
	newB := &mockBackend{name: "new"}
	dual, _ := NewDualRunBackend(oldB, newB)

	_, err := dual.RotateKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if oldB.rotateCalled {
		t.Fatal("RotateKey: called old backend, expected only new")
	}
	if !newB.rotateCalled {
		t.Fatal("RotateKey: new backend not called")
	}
}

// ── Mock Backend ──────────────────────────────────────────────────────────────

type mockBackend struct {
	name string

	signCalled bool
	signErr    error

	encryptCalled bool
	encryptErr    error

	decryptCalled bool
	decryptErr    error

	listCalled bool
	listErr    error
	keys       []*KeyMeta

	rotateCalled bool
	rotateErr    error
}

func (m *mockBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error) {
	m.signCalled = true
	if m.signErr != nil {
		return nil, m.signErr
	}
	return &SignResult{Signature: []byte("signature"), KeyVersion: 1}, nil
}

func (m *mockBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	m.encryptCalled = true
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return &EncryptResult{Ciphertext: []byte("ciphertext"), KeyVersion: 1}, nil
}

func (m *mockBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	m.decryptCalled = true
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return &DecryptResult{Plaintext: []byte("plaintext")}, nil
}

func (m *mockBackend) ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error) {
	m.listCalled = true
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.keys, nil
}

func (m *mockBackend) RotateKey(ctx context.Context, keyID string) (*KeyMeta, error) {
	m.rotateCalled = true
	if m.rotateErr != nil {
		return nil, m.rotateErr
	}
	return &KeyMeta{KeyID: keyID, Version: 2}, nil
}
