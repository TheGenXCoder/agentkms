package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// sampleEvents returns a small set of audit events for test fixtures.
func sampleEvents() []audit.AuditEvent {
	return []audit.AuditEvent{
		{
			EventID:        "evt-001",
			Timestamp:      time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC),
			CallerID:       "agent@team-alpha",
			Operation:      "credential_vend",
			Outcome:        "success",
			CredentialUUID: "cred-aaaa-bbbb-cccc-dddd",
		},
		{
			EventID:        "evt-002",
			Timestamp:      time.Date(2026, 4, 16, 11, 0, 0, 0, time.UTC),
			CallerID:       "agent@team-beta",
			Operation:      "credential_revoke",
			Outcome:        "success",
			CredentialUUID: "cred-eeee-ffff-0000-1111",
		},
		{
			EventID:   "evt-003",
			Timestamp: time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC),
			CallerID:  "scanner@security",
			Operation: "leak_detection",
			Outcome:   "detected",
		},
	}
}

func TestHTMLReport_Generate_ReturnsHTML(t *testing.T) {
	r := NewHTMLReport(sampleEvents())
	out, err := r.Generate()
	if err != nil {
		t.Fatalf("Generate() returned error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Generate() returned empty output")
	}
	html := string(out)
	if !strings.HasPrefix(html, "<!DOCTYPE html>") && !strings.HasPrefix(html, "<html") {
		t.Errorf("Generate() output does not start with <!DOCTYPE html> or <html; got prefix: %.40s", html)
	}
}

func TestHTMLReport_Generate_ContainsSummaryStats(t *testing.T) {
	events := sampleEvents()
	r := NewHTMLReport(events)
	out, err := r.Generate()
	if err != nil {
		t.Fatalf("Generate() returned error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "Total Events:") {
		t.Error("Generate() output does not contain 'Total Events:'")
	}
	// The count should reflect the number of input events.
	if !strings.Contains(html, "3") {
		t.Error("Generate() output does not contain event count '3'")
	}
}

func TestHTMLReport_Generate_ContainsCredentialTable(t *testing.T) {
	events := sampleEvents()
	r := NewHTMLReport(events)
	out, err := r.Generate()
	if err != nil {
		t.Fatalf("Generate() returned error: %v", err)
	}
	html := string(out)
	// The credential UUID from the first event must appear in the output.
	if !strings.Contains(html, "cred-aaaa-bbbb-cccc-dddd") {
		t.Error("Generate() output does not contain credential UUID 'cred-aaaa-bbbb-cccc-dddd'")
	}
	// The second credential UUID should also be present.
	if !strings.Contains(html, "cred-eeee-ffff-0000-1111") {
		t.Error("Generate() output does not contain credential UUID 'cred-eeee-ffff-0000-1111'")
	}
}

func TestHTMLReport_Generate_EmptyEvents(t *testing.T) {
	r := NewHTMLReport([]audit.AuditEvent{})
	out, err := r.Generate()
	if err != nil {
		t.Fatalf("Generate() returned error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Generate() with empty events returned empty output; should produce valid HTML")
	}
	html := string(out)
	if !strings.HasPrefix(html, "<!DOCTYPE html>") && !strings.HasPrefix(html, "<html") {
		t.Error("Generate() with empty events does not produce valid HTML")
	}
	if !strings.Contains(html, "No events") {
		t.Error("Generate() with empty events does not contain 'No events' message")
	}
}

func TestHTMLReport_Generate_ContainsTimestamp(t *testing.T) {
	r := NewHTMLReport(sampleEvents())
	out, err := r.Generate()
	if err != nil {
		t.Fatalf("Generate() returned error: %v", err)
	}
	html := string(out)
	// The report should contain a generation timestamp. We check for the
	// current year as a reasonable proxy — the generation time must include it.
	year := time.Now().UTC().Format("2006")
	if !strings.Contains(html, year) {
		t.Errorf("Generate() output does not contain generation year %s", year)
	}
	if !strings.Contains(html, "Generated") {
		t.Error("Generate() output does not contain 'Generated' label for the timestamp")
	}
}

func TestHTMLReport_WriteToFile_CreatesFile(t *testing.T) {
	r := NewHTMLReport(sampleEvents())
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")

	if err := r.WriteToFile(path); err != nil {
		t.Fatalf("WriteToFile() returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("WriteToFile() did not create file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("WriteToFile() created an empty file")
	}
}

func TestHTMLReport_WriteToFile_InvalidPath(t *testing.T) {
	r := NewHTMLReport(sampleEvents())
	err := r.WriteToFile("/nonexistent/dir/report.html")
	if err == nil {
		t.Error("WriteToFile() with invalid path should return an error, got nil")
	}
}
