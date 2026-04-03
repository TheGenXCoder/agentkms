package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/policy"
)

func TestPopulateAnomalies(t *testing.T) {
	ev := &audit.AuditEvent{}
	anomalies := []policy.AnomalyRecord{
		{Message: "msg1"},
		{Message: "msg2"},
	}
	populateAnomalies(ev, anomalies)
	if len(ev.Anomalies) != 2 {
		t.Errorf("Expected 2 anomalies, got %d", len(ev.Anomalies))
	}
	if ev.Anomalies[0] != "msg1" || ev.Anomalies[1] != "msg2" {
		t.Errorf("Unexpected anomalies: %v", ev.Anomalies)
	}
}

func TestWriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONError(rr, http.StatusBadRequest, "bad request")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %v, got %v", http.StatusBadRequest, rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json")
	}
	if rr.Body.String() != "{\"error\":\"bad request\"}" {
		t.Errorf("Unexpected body: %s", rr.Body.String())
	}
}

func TestDecodeJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"foo":"bar"}`))
	var data map[string]string
	err := decodeJSON(req, &data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if data["foo"] != "bar" {
		t.Errorf("Unexpected data: %v", data)
	}
}

func TestUserAgent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "test-ua")
	if ua := userAgent(req); ua != "test-ua" {
		t.Errorf("Expected test-ua, got %s", ua)
	}

	longUA := strings.Repeat("a", 300)
	req.Header.Set("User-Agent", longUA)
	ua := userAgent(req)
	if len(ua) != 256 {
		t.Errorf("Expected length 256, got %d", len(ua))
	}
	if ua != strings.Repeat("a", 256) {
		t.Errorf("Unexpected UA string")
	}
}
