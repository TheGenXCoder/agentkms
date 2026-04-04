package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

func TestMetricsMiddleware(t *testing.T) {
	// Setup
	devBackend := backend.NewDevBackend()
	auditor, err := audit.NewFileAuditSink("/dev/null")
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	engine := policy.AllowAllEngine{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)

	s := NewServer(devBackend, auditor, engine, ts, "test")

	// Reset metrics state for clean testing
	metricsMu.Lock()
	requestsTotal = make(map[string]map[int]*int64)
	requestDurationBuckets = make(map[string]map[float64]*int64)
	requestDurationSum = make(map[string]*float64)
	auditEventsTotal = 0
	metricsMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	id := identity.Identity{
		CallerID: "test-user",
		TeamID:   "test-team",
		Role:     identity.RoleDeveloper,
	}
	req = req.WithContext(SetIdentityInContext(req.Context(), id))
	rr := httptest.NewRecorder()

	// Initial metrics fetch should have 0 audit events
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %v, got %v", http.StatusOK, rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "agentkms_audit_events_total 0") {
		t.Errorf("Expected 0 audit events initially. Body: %s", body)
	}

	// Trigger a simulated request to increment request count
	testHandler := s.metricsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		time.Sleep(10 * time.Millisecond) // Ensure duration is recorded
	})

	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req2 = req2.WithContext(SetIdentityInContext(req2.Context(), id))
	rr2 := httptest.NewRecorder()
	testHandler(rr2, req2)

	// Trigger an audit event
	s.RecordAuditEvent()

	// Fetch metrics again
	req3 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req3 = req3.WithContext(SetIdentityInContext(req3.Context(), id))
	rr3 := httptest.NewRecorder()
	s.ServeHTTP(rr3, req3)

	body3 := rr3.Body.String()
	if !strings.Contains(body3, "agentkms_audit_events_total 1") {
		t.Errorf("Expected 1 audit event. Body: %s", body3)
	}

	if !strings.Contains(body3, "http_requests_total{method=\"POST\",status=\"202\"} 1") {
		t.Errorf("Expected POST 202 request count to be 1. Body: %s", body3)
	}

	// Check duration sum
	if !strings.Contains(body3, "http_request_duration_seconds_sum{method=\"POST\"}") {
		t.Errorf("Expected duration sum for POST. Body: %s", body3)
	}
}
