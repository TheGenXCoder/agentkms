package report

import (
	"fmt"
	"os"
	"strings"
	"time"

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
	var b strings.Builder

	b.WriteString("<!DOCTYPE html><html><head><title>AgentKMS Audit Report</title></head><body>")

	// Summary stats.
	b.WriteString(fmt.Sprintf("<h2>Summary</h2><p>Total Events: %d</p>", len(r.events)))

	if len(r.events) == 0 {
		b.WriteString("<p>No events</p>")
	} else {
		// Credential table.
		b.WriteString("<h2>Events</h2><table><tr><th>EventID</th><th>Operation</th><th>Outcome</th><th>CredentialUUID</th></tr>")
		for _, ev := range r.events {
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				ev.EventID, ev.Operation, ev.Outcome, ev.CredentialUUID))
		}
		b.WriteString("</table>")
	}

	// Generation timestamp.
	b.WriteString(fmt.Sprintf("<footer><p>Generated %s</p></footer>", time.Now().UTC().Format(time.RFC3339)))

	b.WriteString("</body></html>")

	return []byte(b.String()), nil
}

// WriteToFile generates and writes HTML to the given path.
func (r *HTMLReport) WriteToFile(path string) error {
	data, err := r.Generate()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
