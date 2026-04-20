package audit

import (
	"fmt"
	"time"
)

// RetentionPruner removes audit events older than the configured retention window.
// In the OSS tier the default retention is 24 hours; the Pro tier offers unlimited retention.
type RetentionPruner struct {
	retention time.Duration
}

// NewRetentionPruner returns a RetentionPruner that drops events older than
// the given retention duration.
func NewRetentionPruner(retention time.Duration) *RetentionPruner {
	return &RetentionPruner{retention: retention}
}

// Prune takes a slice of events and returns only those within the retention window.
// Events older than `now - retention` are dropped. Events exactly at the boundary are kept (inclusive).
func (rp *RetentionPruner) Prune(events []AuditEvent, now time.Time) []AuditEvent {
	kept := make([]AuditEvent, 0, len(events))
	for _, e := range events {
		if now.Sub(e.Timestamp) <= rp.retention {
			kept = append(kept, e)
		}
	}
	return kept
}

// PruneHint returns a human-readable message about pruned events for CLI output.
// Returns empty string if nothing was pruned. The message mentions the Pro upgrade path.
func (rp *RetentionPruner) PruneHint(totalBefore, totalAfter int) string {
	if totalBefore == totalAfter {
		return ""
	}
	pruned := totalBefore - totalAfter
	return fmt.Sprintf("ℹ %d of %d events pruned (older than %s). Install c9-retention-unlimited for unlimited history.", pruned, totalBefore, rp.retention)
}
