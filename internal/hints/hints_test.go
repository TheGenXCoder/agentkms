// FO-D6: Acceptance tests for the teaser hint library.
// These tests define the contract for Pro upgrade hints:
// formatting, suppression via flag, and suppression via env var.
package hints

import (
	"strings"
	"testing"
)

func TestHint_Format_NotSuppressed(t *testing.T) {
	h := NewWithOverride(false)
	got := h.Format("Audit logging is limited", "audit-pro", "full forensic timelines")
	if got == "" {
		t.Fatal("expected non-empty formatted hint when not suppressed, got empty string")
	}
	if !strings.HasPrefix(got, "ℹ") {
		t.Errorf("expected hint to start with ℹ prefix, got %q", got)
	}
}

func TestHint_Format_Suppressed(t *testing.T) {
	h := NewWithOverride(true)
	got := h.Format("Audit logging is limited", "audit-pro", "full forensic timelines")
	if got != "" {
		t.Errorf("expected empty string when suppressed, got %q", got)
	}
}

func TestHint_Format_ContainsPlugin(t *testing.T) {
	h := NewWithOverride(false)
	plugin := "audit-pro"
	got := h.Format("Audit logging is limited", plugin, "full forensic timelines")
	if !strings.Contains(got, plugin) {
		t.Errorf("expected output to contain plugin name %q, got %q", plugin, got)
	}
}

func TestHint_Format_ContainsBenefit(t *testing.T) {
	h := NewWithOverride(false)
	benefit := "full forensic timelines"
	got := h.Format("Audit logging is limited", "audit-pro", benefit)
	if !strings.Contains(got, benefit) {
		t.Errorf("expected output to contain benefit %q, got %q", benefit, got)
	}
}

func TestHint_NewWithOverride_True(t *testing.T) {
	h := NewWithOverride(true)
	if !h.IsSuppressed() {
		t.Error("expected IsSuppressed() to return true when created with suppress=true")
	}
}

func TestHint_NewWithOverride_False(t *testing.T) {
	h := NewWithOverride(false)
	if h.IsSuppressed() {
		t.Error("expected IsSuppressed() to return false when created with suppress=false")
	}
}

func TestHint_New_RespectsEnvOff(t *testing.T) {
	t.Setenv("AGENTKMS_HINTS", "off")
	h := New()
	if !h.IsSuppressed() {
		t.Error("expected IsSuppressed() to return true when AGENTKMS_HINTS=off")
	}
}

func TestHint_New_RespectsEnvFalse(t *testing.T) {
	t.Setenv("AGENTKMS_HINTS", "false")
	h := New()
	if !h.IsSuppressed() {
		t.Error("expected IsSuppressed() to return true when AGENTKMS_HINTS=false")
	}
}

func TestHint_New_DefaultNotSuppressed(t *testing.T) {
	t.Setenv("AGENTKMS_HINTS", "")
	h := New()
	if h.IsSuppressed() {
		t.Error("expected IsSuppressed() to return false when AGENTKMS_HINTS is unset")
	}
}
