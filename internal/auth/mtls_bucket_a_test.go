package auth_test

// Bucket A — the mTLS identity extractor is the point at which the
// certificate OU (caller role/ou) enters the system.  v0.1 parsed the OU
// into an enum and discarded the raw value; v0.1.1 preserves it on
// Identity.CallerOU for forensics.

import (
	"testing"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
)

func TestBucketA_ExtractIdentity_PreservesCallerOU(t *testing.T) {
	// "developer" is one of the recognised OUs — Role derives to
	// RoleDeveloper, and CallerOU preserves the raw string.
	_, r := makeClientCert(t,
		"bert@platform",
		"platform",
		"developer",
		"",
	)
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.CallerOU != "developer" {
		t.Errorf("CallerOU = %q, want developer", id.CallerOU)
	}
	if id.Role != identity.RoleDeveloper {
		t.Errorf("Role = %q, want developer", id.Role)
	}
}

func TestBucketA_ExtractIdentity_PreservesUnrecognisedOU(t *testing.T) {
	// An OU the extractor does not map to a Role must still be preserved
	// on CallerOU so forensics can distinguish "default RoleDeveloper
	// because OU was known" from "default RoleDeveloper because OU was
	// unknown".
	_, r := makeClientCert(t,
		"svc@payments",
		"payments",
		"custom-operator",
		"",
	)
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.CallerOU != "custom-operator" {
		t.Errorf("CallerOU = %q, want custom-operator", id.CallerOU)
	}
	// Role falls back to RoleDeveloper for unknown OUs (existing behaviour).
	if id.Role != identity.RoleDeveloper {
		t.Errorf("Role = %q, want developer (default)", id.Role)
	}
}

func TestBucketA_ExtractIdentity_EmptyOU_CallerOUEmpty(t *testing.T) {
	// No OU on the certificate → CallerOU is empty, Role defaults.
	_, r := makeClientCert(t,
		"ci@payments",
		"payments",
		"",
		"",
	)
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.CallerOU != "" {
		t.Errorf("CallerOU = %q, want empty", id.CallerOU)
	}
}
