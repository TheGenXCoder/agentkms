package aws_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
	aws "github.com/agentkms/agentkms/internal/dynsecrets/aws"
)

// ── helpers ─────────────────────────────────────────────────────────────────

const (
	testRoleARN    = "arn:aws:iam::123456789012:role/deploy-staging"
	testRegion     = "us-east-1"
	testSession    = "frank-acmecorp-20260420"
	testExternalID = "c9-session-abc123"
)

// newPlugin creates a Plugin with valid config for tests that don't
// exercise constructor validation.
func newPlugin(t *testing.T) *aws.Plugin {
	t.Helper()
	p, err := aws.New(testRoleARN, testRegion)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return p
}

// validScope returns a well-formed aws-sts Scope.
func validScope() credentials.Scope {
	return credentials.Scope{
		Kind: "aws-sts",
		Params: map[string]any{
			"role_arn":     testRoleARN,
			"session_name": testSession,
			"external_id":  testExternalID,
		},
		TTL: 30 * time.Minute,
	}
}

// ── TestAWSPlugin_Kind ─────────────────────────────────────────────────────

func TestAWSPlugin_Kind(t *testing.T) {
	p := newPlugin(t)
	if got := p.Kind(); got != "aws-sts" {
		t.Errorf("Kind() = %q, want %q", got, "aws-sts")
	}
}

// ── TestAWSPlugin_Validate ─────────────────────────────────────────────────

func TestAWSPlugin_Validate_ValidScope(t *testing.T) {
	p := newPlugin(t)
	if err := p.Validate(context.Background(), validScope()); err != nil {
		t.Errorf("Validate(validScope): unexpected error: %v", err)
	}
}

func TestAWSPlugin_Validate_MissingRoleARN(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	delete(s.Params, "role_arn")

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(missing role_arn): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_InvalidRoleARN(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.Params["role_arn"] = "not-a-valid-arn"

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(invalid role_arn): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_MissingSessionName(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	delete(s.Params, "session_name")

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(missing session_name): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_SessionNameTooLong(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	// 65 characters exceeds the 64-char max.
	s.Params["session_name"] = strings.Repeat("a", 65)

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(session_name too long): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_SessionNameInvalidChars(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.Params["session_name"] = "bad session!name#here"

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(session_name invalid chars): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_TTLTooShort(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.TTL = 10 * time.Minute // < 15m minimum

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(TTL < 15m): expected error, got nil")
	}
}

func TestAWSPlugin_Validate_TTLTooLong(t *testing.T) {
	p := newPlugin(t)
	s := validScope()
	s.TTL = 13 * time.Hour // > 12h maximum

	if err := p.Validate(context.Background(), s); err == nil {
		t.Error("Validate(TTL > 12h): expected error, got nil")
	}
}

// ── TestAWSPlugin_Narrow ───────────────────────────────────────────────────

func TestAWSPlugin_Narrow_TTLCapped(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.TTL = 2 * time.Hour

	bounds := credentials.ScopeBounds{
		Kind:   "aws-sts",
		MaxTTL: 30 * time.Minute,
	}

	narrowed, err := p.Narrow(ctx, requested, bounds)
	if err != nil {
		t.Fatalf("Narrow: unexpected error: %v", err)
	}

	if narrowed.TTL != 30*time.Minute {
		t.Errorf("narrowed TTL = %v, want %v", narrowed.TTL, 30*time.Minute)
	}
}

func TestAWSPlugin_Narrow_RoleARNMismatch(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()
	requested.Params["role_arn"] = "arn:aws:iam::123456789012:role/deploy-staging"

	bounds := credentials.ScopeBounds{
		Kind: "aws-sts",
		MaxParams: map[string]any{
			"role_arn": "arn:aws:iam::123456789012:role/read-only",
		},
		MaxTTL: time.Hour,
	}

	_, err := p.Narrow(ctx, requested, bounds)
	if err == nil {
		t.Error("Narrow(role_arn mismatch): expected error, got nil")
	}
}

func TestAWSPlugin_Narrow_RoleARNMatch(t *testing.T) {
	p := newPlugin(t)
	ctx := context.Background()

	requested := validScope()

	bounds := credentials.ScopeBounds{
		Kind: "aws-sts",
		MaxParams: map[string]any{
			"role_arn": testRoleARN,
		},
		MaxTTL: time.Hour,
	}

	narrowed, err := p.Narrow(ctx, requested, bounds)
	if err != nil {
		t.Fatalf("Narrow: unexpected error: %v", err)
	}

	gotARN, ok := narrowed.Params["role_arn"].(string)
	if !ok {
		t.Fatalf("narrowed role_arn: expected string, got %T", narrowed.Params["role_arn"])
	}
	if gotARN != testRoleARN {
		t.Errorf("narrowed role_arn = %q, want %q", gotARN, testRoleARN)
	}
}

// ── TestAWSPlugin_New ──────────────────────────────────────────────────────

func TestAWSPlugin_New_EmptyRoleARN(t *testing.T) {
	_, err := aws.New("", testRegion)
	if err == nil {
		t.Error("New(empty roleARN): expected error, got nil")
	}
}

func TestAWSPlugin_New_EmptyRegion(t *testing.T) {
	_, err := aws.New(testRoleARN, "")
	if err == nil {
		t.Error("New(empty region): expected error, got nil")
	}
}
