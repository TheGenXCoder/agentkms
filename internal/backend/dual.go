// Package backend — Backend dual-run mode for zero-downtime migration.
//
// B-07: Implements a Backend wrapper that routes operations between an "old"
// and a "new" backend.  This is required for zero-downtime backend migration
// (e.g., OpenBao → AWS KMS).
//
// Operational policy (B-07):
//   - Sign: Always use "new" backend.
//   - Encrypt: Always use "new" backend.
//   - Decrypt: Try "new" backend first; if it fails (not found/invalid format),
//     fall back to "old" backend.
//   - RotateKey: Always use "new" backend.
//   - ListKeys: Merge results from both backends (de-duplicated by KeyID).
package backend

import (
	"context"
	"errors"
	"fmt"
)

// DualRunBackend wraps two backends to enable migration.
// It is intended to be used during a migration window where both backends
// are active.
type DualRunBackend struct {
	old Backend
	new Backend
}

// NewDualRunBackend constructs a DualRunBackend from two existing backends.
func NewDualRunBackend(old, new Backend) (*DualRunBackend, error) {
	if old == nil || new == nil {
		return nil, fmt.Errorf("dual-run: both old and new backends must be provided")
	}
	return &DualRunBackend{old: old, new: new}, nil
}

// ── Backend interface implementation ──────────────────────────────────────────

// Sign computes a signature using the NEW backend.
func (b *DualRunBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error) {
	return b.new.Sign(ctx, keyID, payloadHash, alg)
}

// Encrypt encrypts plaintext using the NEW backend.
func (b *DualRunBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	return b.new.Encrypt(ctx, keyID, plaintext)
}

// Decrypt decrypts ciphertext.  It tries the NEW backend first, then falls
// back to the OLD backend if the new one returns ErrKeyNotFound or if the
// ciphertext format is clearly intended for the old backend.
func (b *DualRunBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	// 1. Try NEW backend first.
	res, err := b.new.Decrypt(ctx, keyID, ciphertext)
	if err == nil {
		return res, nil
	}

	// 2. If it's a structural error (invalid input/type mismatch), or if it
	// failed with ErrKeyNotFound, fall back to the old backend.
	//
	// Note: in a migration, it's normal for the new backend to return
	// ErrKeyNotFound for keys that have not been migrated yet.
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrInvalidInput) {
		return b.old.Decrypt(ctx, keyID, ciphertext)
	}

	// 3. Any other error (e.g. context cancellation, network failure) is
	// propagated — we don't fall back for system-level errors.
	return nil, err
}

// ListKeys returns metadata for all keys from BOTH backends.
func (b *DualRunBackend) ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error) {
	// Fetch from both concurrently (best-effort).
	// For simplicity, we'll do it serially here.
	newKeys, err := b.new.ListKeys(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("dual-run: ListKeys(new): %w", err)
	}

	oldKeys, err := b.old.ListKeys(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("dual-run: ListKeys(old): %w", err)
	}

	// Merge results, giving preference to the NEW metadata for any key IDs
	// present in both.
	merged := make(map[string]*KeyMeta)
	for _, m := range oldKeys {
		merged[m.KeyID] = m
	}
	for _, m := range newKeys {
		merged[m.KeyID] = m
	}

	result := make([]*KeyMeta, 0, len(merged))
	for _, m := range merged {
		result = append(result, m)
	}

	return result, nil
}

// RotateKey rotates a key in the NEW backend.
func (b *DualRunBackend) RotateKey(ctx context.Context, keyID string) (*KeyMeta, error) {
	return b.new.RotateKey(ctx, keyID)
}
