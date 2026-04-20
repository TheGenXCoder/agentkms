package forensics

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	separator = "  ──────────────────────────────────────────────────────────────────"
	checkmark = "✓"
	cross     = "✗"
	info      = "ℹ"
)

// FormatReport renders a Report as a human-readable terminal string.
// Designed for <30-second readability by a security engineer.
func FormatReport(r *Report) string {
	var b strings.Builder

	writeBlastRadius(&b, r)
	b.WriteString("\n")
	b.WriteString(separator)
	b.WriteString("\n")
	writeScope(&b, r)
	writeLifecycle(&b, r)
	writeUsageEvents(&b, r)
	writePostExpiry(&b, r)
	b.WriteString("\n")
	b.WriteString(separator)
	b.WriteString("\n")
	writeAssessment(&b, r)
	writeIssuanceContext(&b, r)
	writeTeaser(&b)

	return b.String()
}

// writeBlastRadius writes the opening line with blast-radius assessment.
func writeBlastRadius(b *strings.Builder, r *Report) {
	radius := blastRadius(r)
	fmt.Fprintf(b, "\n  Leaked credential found in audit ledger.  %s Blast radius: %s.\n", cross, radius)
}

// blastRadius determines the blast radius label from the report.
func blastRadius(r *Report) string {
	if r.Scope == nil {
		return "UNKNOWN"
	}
	var scope map[string]interface{}
	if err := json.Unmarshal(r.Scope, &scope); err != nil {
		return "UNKNOWN"
	}
	// If repos is present and is a single-item array, it's bounded.
	if repos, ok := scope["repos"].([]interface{}); ok {
		if len(repos) == 1 {
			return "BOUNDED"
		}
		if len(repos) > 1 {
			return "WIDE"
		}
	}
	// If scope has explicit bounds (contents:write etc.) treat as bounded.
	if _, ok := scope["permissions"]; ok {
		return "BOUNDED"
	}
	// If we have any known scope field at all, treat as BOUNDED.
	if len(scope) > 0 {
		return "BOUNDED"
	}
	return "UNKNOWN"
}

// writeScope writes the scope summary block.
func writeScope(b *strings.Builder, r *Report) {
	if r.Scope == nil {
		fmt.Fprintf(b, "  Scope:         Scope not available (pre-v0.3 credential)\n")
		return
	}
	var scope map[string]interface{}
	if err := json.Unmarshal(r.Scope, &scope); err != nil {
		fmt.Fprintf(b, "  Scope:         (unparseable)\n")
		return
	}

	// Build a human-readable scope string.
	var scopeLabel string
	var repoCount int
	var permsParts []string

	if repos, ok := scope["repos"].([]interface{}); ok {
		repoCount = len(repos)
		if repoCount == 1 {
			scopeLabel = fmt.Sprintf("%v", repos[0])
		} else {
			names := make([]string, 0, repoCount)
			for _, r := range repos {
				names = append(names, fmt.Sprintf("%v", r))
			}
			scopeLabel = strings.Join(names, ", ")
		}
	}

	// Gather permissions — may be a string or slice.
	switch v := scope["permissions"].(type) {
	case string:
		permsParts = append(permsParts, v)
	case []interface{}:
		for _, p := range v {
			permsParts = append(permsParts, fmt.Sprintf("%v", p))
		}
	}

	// Build detail line.
	var detail string
	if repoCount > 0 {
		noun := "repo"
		if repoCount > 1 {
			noun = "repos"
		}
		detail = fmt.Sprintf("(%d %s", repoCount, noun)
		if len(permsParts) > 0 {
			detail += "; " + strings.Join(permsParts, " + ")
		}
		detail += ")"
	} else if len(permsParts) > 0 {
		detail = "(" + strings.Join(permsParts, " + ") + ")"
	}

	if scopeLabel != "" && detail != "" {
		fmt.Fprintf(b, "  Scope:         %s\n                 %s\n", scopeLabel, detail)
	} else if scopeLabel != "" {
		fmt.Fprintf(b, "  Scope:         %s\n", scopeLabel)
	} else {
		fmt.Fprintf(b, "  Scope:         (defined)\n")
	}

	// TTL line — derived from issued/expired window.
	if !r.IssuedAt.IsZero() && !r.ExpiredAt.IsZero() {
		ttl := r.ExpiredAt.Sub(r.IssuedAt)
		fmt.Fprintf(b, "  TTL applied:   %s\n", formatDuration(ttl))
	}
}

// writeLifecycle writes the three-timestamp lifecycle block.
func writeLifecycle(b *strings.Builder, r *Report) {
	fmt.Fprintf(b, "  Lifecycle:")

	if r.IssuedAt.IsZero() {
		fmt.Fprintf(b, "     issued  (unknown)\n")
	} else {
		callerNote := ""
		if r.CallerID != "" {
			callerNote = fmt.Sprintf("  (to %s)", r.CallerID)
		}
		fmt.Fprintf(b, "     issued  %s%s\n", formatTimestamp(r.IssuedAt), callerNote)
	}

	if r.ExpiredAt.IsZero() {
		fmt.Fprintf(b, "               expired (no expiry set)\n")
	} else {
		expiredNote := "← credential already dead"
		fmt.Fprintf(b, "               expired %s  %s\n", formatTimestamp(r.ExpiredAt), expiredNote)
	}

	if r.DetectedAt.IsZero() {
		fmt.Fprintf(b, "               leaked  not yet detected\n")
	} else {
		var leakNote string
		if !r.ExpiredAt.IsZero() {
			gap := r.DetectedAt.Sub(r.ExpiredAt)
			if gap > 0 {
				leakNote = fmt.Sprintf("← reported %s after expiry", formatDuration(gap))
			} else {
				// Detected before expiry — still live.
				leakNote = "← credential was live at detection"
			}
		}
		fmt.Fprintf(b, "               leaked  %s  %s\n", formatTimestamp(r.DetectedAt), leakNote)
	}
	b.WriteString("\n")
}

// writeUsageEvents writes the chronological usage event list.
func writeUsageEvents(b *strings.Builder, r *Report) {
	if r.IssuedAt.IsZero() || r.ExpiredAt.IsZero() {
		fmt.Fprintf(b, "  Usage during live window:\n")
	} else {
		window := r.ExpiredAt.Sub(r.IssuedAt)
		fmt.Fprintf(b, "  Usage during live window (%s):\n", formatDuration(window))
	}

	if len(r.UsageEvents) == 0 {
		fmt.Fprintf(b, "    No usage recorded\n")
		return
	}

	for _, ev := range r.UsageEvents {
		ts := ev.Timestamp.UTC().Format("15:04")
		desc := ev.Description
		if desc == "" {
			desc = ev.Operation
		}
		fmt.Fprintf(b, "    %s  %-38s %s expected\n", ts, desc, checkmark)
	}
}

// writePostExpiry writes the post-expiry usage status.
func writePostExpiry(b *strings.Builder, r *Report) {
	b.WriteString("\n")
	if r.ExpiredAt.IsZero() || r.DetectedAt.IsZero() {
		fmt.Fprintf(b, "  Post-expiry usage: unknown\n")
		return
	}

	// Count events after expiry.
	postExpiry := 0
	for _, ev := range r.UsageEvents {
		if ev.Timestamp.After(r.ExpiredAt) {
			postExpiry++
		}
	}

	if postExpiry == 0 {
		fmt.Fprintf(b, "  Post-expiry usage: NONE (credential was dead when leaked)\n")
	} else {
		fmt.Fprintf(b, "  Post-expiry usage: %d event(s) detected — review required\n", postExpiry)
	}
}

// writeAssessment writes the assessment and action lines.
func writeAssessment(b *strings.Builder, r *Report) {
	assessment := r.Assessment
	if assessment == "" {
		fmt.Fprintf(b, "  Assessment pending\n")
		return
	}

	switch assessment {
	case "no damage":
		gap := ""
		if !r.ExpiredAt.IsZero() && !r.DetectedAt.IsZero() {
			d := r.DetectedAt.Sub(r.ExpiredAt)
			if d > 0 {
				gap = fmt.Sprintf(" — credential expired %s before leak detection.", formatDuration(d))
			}
		}
		fmt.Fprintf(b, "  %s Assessment: no damage%s\n", checkmark, gap)
		fmt.Fprintf(b, "  %s Action required: none. GitHub has already revoked the dead token.\n", checkmark)
	case "potential exposure":
		fmt.Fprintf(b, "  %s Assessment: potential exposure — credential was live at leak detection.\n", cross)
		fmt.Fprintf(b, "  %s Action required: rotate immediately and audit downstream systems.\n", cross)
	default:
		fmt.Fprintf(b, "  Assessment: %s\n", assessment)
	}
	b.WriteString("\n")
}

// writeIssuanceContext writes the full issuance context block.
func writeIssuanceContext(b *strings.Builder, r *Report) {
	fmt.Fprintf(b, "  Full issuance context:\n")

	if r.CallerID != "" {
		fmt.Fprintf(b, "    Requester:   %s\n", r.CallerID)
	}
	if r.TeamID != "" {
		fmt.Fprintf(b, "    Team:        %s\n", r.TeamID)
	}
	if r.RuleID != "" {
		fmt.Fprintf(b, "    Policy:      %s\n", r.RuleID)
	}
	if r.CredentialType != "" {
		fmt.Fprintf(b, "    Via:         MCP tool `vend_%s`\n", r.CredentialType)
	}
	b.WriteString("\n")
}

// writeTeaser writes the OSS upsell footer.
func writeTeaser(b *strings.Builder) {
	fmt.Fprintf(b, "  %s Single-credential inspect only on OSS. Install c9-forensics-plus\n", info)
	fmt.Fprintf(b, "    for correlated multi-credential queries and org-wide search.\n")
}

// formatTimestamp formats a time.Time as "2006-01-02 15:04 UTC".
func formatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// formatDuration formats a duration in human-readable form (e.g. "8h", "63h", "2d5h").
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	totalHours := int(math.Round(d.Hours()))
	if totalHours == 0 {
		mins := int(math.Round(d.Minutes()))
		if mins == 0 {
			return "< 1m"
		}
		return fmt.Sprintf("%dm", mins)
	}
	if totalHours < 24 {
		return fmt.Sprintf("%dh", totalHours)
	}
	days := totalHours / 24
	hours := totalHours % 24
	if hours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, hours)
}
