package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

func TestHandleSOC2ComplianceExport(t *testing.T) {
	b := backend.NewDevBackend()
	aud := &exportableAuditor{}
	// Use an engine that allows "compliance_export".
	srv := newServerWithAuditor(t, b, aud, policy.AllowAllEngine{})

	// 1. Create some audit events of different types.
	now := time.Now().UTC()
	
	// CC6.1 & CC7.2
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev1", Timestamp: now.Add(-10 * time.Minute), Operation: audit.OperationAuth, Outcome: audit.OutcomeSuccess,
	})
	
	// CC8.1 & CC7.2
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev2", Timestamp: now.Add(-5 * time.Minute), Operation: audit.OperationRotateKey, Outcome: audit.OutcomeSuccess,
	})
	
	// CC6.2 & CC7.2
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev3", Timestamp: now.Add(-1 * time.Minute), Operation: audit.OperationCredentialVend, Outcome: audit.OutcomeSuccess,
	})

	// 2. Export.
	path := "/compliance/soc2"
	rr := request(t, srv, http.MethodGet, path, nil)
	assertStatus(t, rr, http.StatusOK)

	// 3. Verify response.
	dec := json.NewDecoder(rr.Body)
	var received []struct {
		audit.AuditEvent
		SOC2Controls []string `json:"soc2_controls"`
	}
	
	for dec.More() {
		var ev struct {
			audit.AuditEvent
			SOC2Controls []string `json:"soc2_controls"`
		}
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("failed to decode exported event: %v", err)
		}
		received = append(received, ev)
	}

	if len(received) != 3 {
		t.Fatalf("expected 3 events, got %d", len(received))
	}

	// Verify mappings.
	// ev1 (Auth) -> CC6.1, CC7.2
	if !containsInSlice(received[0].SOC2Controls, "CC6.1") || !containsInSlice(received[0].SOC2Controls, "CC7.2") {
		t.Errorf("ev1 missing controls: %v", received[0].SOC2Controls)
	}
	
	// ev2 (RotateKey) -> CC8.1, CC7.2
	if !containsInSlice(received[1].SOC2Controls, "CC8.1") || !containsInSlice(received[1].SOC2Controls, "CC7.2") {
		t.Errorf("ev2 missing controls: %v", received[1].SOC2Controls)
	}
	
	// ev3 (CredentialVend) -> CC6.2, CC7.2
	if !containsInSlice(received[2].SOC2Controls, "CC6.2") || !containsInSlice(received[2].SOC2Controls, "CC7.2") {
		t.Errorf("ev3 missing controls: %v", received[2].SOC2Controls)
	}
}

func containsInSlice(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
