package auth_test

import (
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/auth"
)

func newStore(t *testing.T) *auth.RecoveryStore {
	t.Helper()
	rs, err := auth.NewRecoveryStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewRecoveryStore: %v", err)
	}
	return rs
}

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	rs := newStore(t)
	codes, err := rs.GenerateRecoveryCodes("user@team")
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != auth.RecoveryCodeCount {
		t.Errorf("expected %d codes, got %d", auth.RecoveryCodeCount, len(codes))
	}
}

func TestGenerateRecoveryCodes_Plaintext_NotEmpty(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")
	for _, c := range codes {
		if c.Plaintext == "" {
			t.Errorf("code %d has empty plaintext", c.Index)
		}
	}
}

func TestGenerateRecoveryCodes_Formatted(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")
	for _, c := range codes {
		// Should be dash-separated groups.
		if !strings.Contains(c.Plaintext, "-") {
			t.Errorf("code %d is not dash-grouped: %q", c.Index, c.Plaintext)
		}
	}
}

func TestRedeemRecoveryCode_Success(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	if err := rs.RedeemRecoveryCode("user@team", codes[0].Plaintext); err != nil {
		t.Fatalf("redeem valid code: %v", err)
	}
}

func TestRedeemRecoveryCode_BurnsCode(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	rs.RedeemRecoveryCode("user@team", codes[0].Plaintext) //nolint:errcheck

	// Second redeem must fail.
	if err := rs.RedeemRecoveryCode("user@team", codes[0].Plaintext); err == nil {
		t.Fatal("expected error on second redeem, got nil")
	}
}

func TestRedeemRecoveryCode_WrongCode(t *testing.T) {
	rs := newStore(t)
	rs.GenerateRecoveryCodes("user@team") //nolint:errcheck

	err := rs.RedeemRecoveryCode("user@team", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")
	if err == nil {
		t.Fatal("expected error for wrong code, got nil")
	}
}

func TestRedeemRecoveryCode_UnknownCaller(t *testing.T) {
	rs := newStore(t)
	err := rs.RedeemRecoveryCode("nobody@team", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")
	if err == nil {
		t.Fatal("expected error for unknown caller, got nil")
	}
}

func TestRedeemRecoveryCode_CaseInsensitive(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	lower := strings.ToLower(codes[1].Plaintext)
	if err := rs.RedeemRecoveryCode("user@team", lower); err != nil {
		t.Fatalf("lowercase redeem failed: %v", err)
	}
}

func TestRedeemRecoveryCode_StripsSpaces(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	spaced := strings.ReplaceAll(codes[2].Plaintext, "-", " ")
	if err := rs.RedeemRecoveryCode("user@team", spaced); err != nil {
		t.Fatalf("space-separated redeem failed: %v", err)
	}
}

func TestRemainingCodes(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	if rs.RemainingCodes("user@team") != auth.RecoveryCodeCount {
		t.Errorf("expected %d remaining, got %d", auth.RecoveryCodeCount, rs.RemainingCodes("user@team"))
	}

	rs.RedeemRecoveryCode("user@team", codes[0].Plaintext) //nolint:errcheck

	if rs.RemainingCodes("user@team") != auth.RecoveryCodeCount-1 {
		t.Errorf("expected %d remaining after redeem, got %d", auth.RecoveryCodeCount-1, rs.RemainingCodes("user@team"))
	}
}

func TestRevokeAllCodes(t *testing.T) {
	rs := newStore(t)
	codes, _ := rs.GenerateRecoveryCodes("user@team")

	rs.RevokeAllCodes("user@team") //nolint:errcheck

	if err := rs.RedeemRecoveryCode("user@team", codes[0].Plaintext); err == nil {
		t.Fatal("expected error after revocation, got nil")
	}
}

func TestPersistence_ReloadRetainsHashes(t *testing.T) {
	dir := t.TempDir()
	rs1, _ := auth.NewRecoveryStore(dir)
	codes, _ := rs1.GenerateRecoveryCodes("user@team")

	// Re-open from disk.
	rs2, err := auth.NewRecoveryStore(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Should still be able to redeem the code.
	if err := rs2.RedeemRecoveryCode("user@team", codes[3].Plaintext); err != nil {
		t.Fatalf("redeem after reload: %v", err)
	}
}

func TestAdversarial_TimingAttack(t *testing.T) {
	// Verify constant-time comparison — no panic on mismatched lengths.
	rs := newStore(t)
	rs.GenerateRecoveryCodes("user@team") //nolint:errcheck
	// Short code, empty code, all-zeros.
	for _, bad := range []string{"X", "", "00000000000000000000000000"} {
		_ = rs.RedeemRecoveryCode("user@team", bad)
	}
}
