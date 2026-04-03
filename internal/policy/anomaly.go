package policy

// anomaly.go — P-07: Rules-based anomaly detection for the policy engine.
//
// Tracking:
//   - Spike detection: tracks total operations per caller in a window.
//   - Repeated denials: tracks consecutive denials for a caller.
//   - Unusual hours: alerts when a caller operates outside their typical
//     hours (baseline-less, uses a "quiet hours" rule-like check).
//
// This is an internal component of Engine.  It does not have its own
// configuration in the Policy schema yet (P-07 uses hardcoded or
// engine-level thresholds for MVP).

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// AnomalyType categorises the detected anomaly.
type AnomalyType string

const (
	AnomalySpike          AnomalyType = "spike"
	AnomalyRepeatedDenial AnomalyType = "repeated_denial"
	AnomalyUnusualHours   AnomalyType = "unusual_hours"
)

// AnomalyRecord is the result of an anomaly check.
type AnomalyRecord struct {
	Type    AnomalyType
	Message string
}

// anomalyState tracks historical data for anomaly detection.
type anomalyState struct {
	mu sync.Mutex

	// callerID -> []timestamps of successful/allowed requests.
	activity map[string][]time.Time

	// callerID -> count of consecutive denials.
	denials map[string]int
}

func newAnomalyState() *anomalyState {
	return &anomalyState{
		activity: make(map[string][]time.Time),
		denials:  make(map[string]int),
	}
}

// Detect checks for anomalies based on the current request and its decision.
// It updates internal state and returns any detected anomalies.
func (as *anomalyState) Detect(id identity.Identity, decision Decision, now time.Time) []AnomalyRecord {
	as.mu.Lock()
	defer as.mu.Unlock()

	var anomalies []AnomalyRecord

	// 1. Repeated Denial detection.
	if !decision.Allow {
		as.denials[id.CallerID]++
		if as.denials[id.CallerID] >= 5 {
			anomalies = append(anomalies, AnomalyRecord{
				Type:    AnomalyRepeatedDenial,
				Message: fmt.Sprintf("caller %q has %d consecutive denials", id.CallerID, as.denials[id.CallerID]),
			})
		}
	} else {
		// Reset denials on successful (allowed) request.
		as.denials[id.CallerID] = 0
	}

	// 2. Spike detection (allowed requests only, or all requests?).
	// Architecture doc §4.5: "Spike in operation volume from a single identity".
	// We'll track all requests to detect probing spikes too.
	activity := as.activity[id.CallerID]
	activity = append(activity, now)

	// Prune activity older than 1 minute.
	cutoff := now.Add(-1 * time.Minute)
	start := 0
	for i, ts := range activity {
		if ts.After(cutoff) {
			start = i
			break
		}
	}
	activity = activity[start:]
	as.activity[id.CallerID] = activity

	// Rule: > 100 requests per minute is a spike.
	if len(activity) > 100 {
		anomalies = append(anomalies, AnomalyRecord{
			Type:    AnomalySpike,
			Message: fmt.Sprintf("caller %q operation spike: %d requests in last minute", id.CallerID, len(activity)),
		})
	}

	// 3. Unusual Hours.
	// Rules-based: we'll define 00:00-06:00 UTC as "unusual hours" for
	// developers (but not services/agents, which are 24/7).
	if id.Role == identity.RoleDeveloper {
		hour := now.UTC().Hour()
		if hour >= 0 && hour < 6 {
			anomalies = append(anomalies, AnomalyRecord{
				Type:    AnomalyUnusualHours,
				Message: fmt.Sprintf("developer %q operating at unusual hour: %02d:00 UTC", id.CallerID, hour),
			})
		}
	}

	return anomalies
}
