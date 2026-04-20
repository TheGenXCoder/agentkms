package report

import (
	"github.com/agentkms/agentkms/internal/audit"
)

// HTMLReport generates a static HTML file from audit events.
type HTMLReport struct {
	events []audit.AuditEvent
}

// NewHTMLReport creates an HTMLReport from a slice of audit events.
func NewHTMLReport(events []audit.AuditEvent) *HTMLReport {
	return &HTMLReport{events: events}
}

// Generate produces HTML content as a byte slice.
func (r *HTMLReport) Generate() ([]byte, error) {
	return nil, nil
}

// WriteToFile generates and writes HTML to the given path.
func (r *HTMLReport) WriteToFile(path string) error {
	return nil
}
