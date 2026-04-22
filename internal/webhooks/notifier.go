package webhooks

import (
	"context"
	"fmt"
	"os"
	"time"
)

// ConsoleNotifier implements Notifier by writing a structured line to os.Stderr.
//
// Format:
//
//	time=<RFC3339> level=warn event=alert_manual_revoke credential=<UUID> branch=<branch> escalated=<bool>
//
// Notification failures are best-effort and do not abort orchestration.
// The audit event is the compliance record; the notification is operator UX.
//
// Slack integration is v0.4.
type ConsoleNotifier struct{}

// NewConsoleNotifier returns a ConsoleNotifier.
func NewConsoleNotifier() *ConsoleNotifier { return &ConsoleNotifier{} }

// Notify writes a structured log line to os.Stderr describing the alert result.
func (n *ConsoleNotifier) Notify(_ context.Context, result AlertResult) error {
	level := "info"
	event := "alert_processed"

	switch result.Branch {
	case ManualRevokeBranch:
		level = "warn"
		event = "alert_manual_revoke"
	case LiveRevokedBranch:
		level = "warn"
		event = "alert_credential_revoked"
	case ExpiredBranch:
		event = "alert_expired_detected"
	}

	line := fmt.Sprintf(
		"time=%s level=%s event=%s credential=%s branch=%d escalated=%v",
		time.Now().UTC().Format(time.RFC3339),
		level,
		event,
		result.CredentialUUID,
		int(result.Branch),
		result.Escalated,
	)

	if result.ManualRevocationURL != "" {
		line += fmt.Sprintf(" manual_url=%s", result.ManualRevocationURL)
	}
	if result.OrchestratorError != nil {
		line += fmt.Sprintf(" error=%q", result.OrchestratorError.Error())
	}

	fmt.Fprintln(os.Stderr, line)
	return nil
}
