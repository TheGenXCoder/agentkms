package webhooks_test

// rotation_hook_test.go — Contract tests for the RotationHook interface and
// ErrNoBinding sentinel, added as part of T5 Part 1.
//
// These tests lock the public interface shape so that any future breaking
// change to the interface (method rename, signature change, etc.) is caught
// at compile time rather than discovered by downstream plugin authors.

import (
	"context"
	"errors"
	"testing"

	"github.com/agentkms/agentkms/internal/webhooks"
)

// ── Interface shape assertion ─────────────────────────────────────────────────

// testHookImpl is a minimal concrete type that satisfies webhooks.RotationHook.
// It exists only to provide the compile-time interface check below.
type testHookImpl struct{}

func (t *testHookImpl) TriggerRotation(_ context.Context, _ string) error {
	return nil
}

func (t *testHookImpl) BindingForCredential(_ context.Context, _ string) (string, error) {
	return "", nil
}

// TestRotationHook_InterfaceShape is a compile-time assertion that
// *testHookImpl satisfies the webhooks.RotationHook interface.
// If the interface ever changes (method renamed, signature altered), this
// assignment will fail to compile and alert plugin authors immediately.
func TestRotationHook_InterfaceShape(t *testing.T) {
	var _ webhooks.RotationHook = (*testHookImpl)(nil)
	// Also verify that the fakeRotationHook used in orchestrator_test.go
	// satisfies the interface — two independent implementors for robustness.
	var _ webhooks.RotationHook = (*fakeRotationHook)(nil)
}

// ── ErrNoBinding export sanity ────────────────────────────────────────────────

// TestErrNoBinding_IsExported verifies that ErrNoBinding is exported from the
// webhooks package and that callers can use errors.Is to compare against it.
// This is the primary mechanism by which plugin authors (and the OSS orchestrator)
// detect the "credential not managed by any binding" condition.
func TestErrNoBinding_IsExported(t *testing.T) {
	// Direct identity check.
	if !errors.Is(webhooks.ErrNoBinding, webhooks.ErrNoBinding) {
		t.Fatal("errors.Is(ErrNoBinding, ErrNoBinding) must be true")
	}

	// Wrapped error must still match via errors.Is, which is the standard
	// way callers will compare errors returned from BindingForCredential.
	wrapped := errors.Join(webhooks.ErrNoBinding, errors.New("additional context"))
	if !errors.Is(wrapped, webhooks.ErrNoBinding) {
		t.Error("errors.Is must work on errors wrapped with errors.Join")
	}

	// A different sentinel must NOT match ErrNoBinding.
	otherErr := errors.New("some other error")
	if errors.Is(otherErr, webhooks.ErrNoBinding) {
		t.Error("a different error must not match ErrNoBinding")
	}
}
