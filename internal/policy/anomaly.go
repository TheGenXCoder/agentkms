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
	"math"
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
	AnomalyStatistical    AnomalyType = "statistical_outlier"
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

	// P-08: Statistical baselining.
	// callerID -> stats for per-minute request counts.
	velocityStats map[string]*runningStats

	// callerID -> hour (0-23) -> count of requests.
	hourlyProfile map[string][]int
}

// runningStats implements Welford's algorithm for online mean and variance.
type runningStats struct {
	n    int
	mean float64
	m2   float64
}

func (s *runningStats) Update(x float64) {
	s.n++
	delta := x - s.mean
	s.mean += delta / float64(s.n)
	delta2 := x - s.mean
	s.m2 += delta * delta2
}

func (s *runningStats) Variance() float64 {
	if s.n < 2 {
		return 0
	}
	return s.m2 / float64(s.n-1)
}

func (s *runningStats) Mean() float64 {
	return s.mean
}

func newAnomalyState() *anomalyState {
	return &anomalyState{
		activity:      make(map[string][]time.Time),
		denials:       make(map[string]int),
		velocityStats: make(map[string]*runningStats),
		hourlyProfile: make(map[string][]int),
	}
}

// Detect checks for anomalies based on the current request and its decision.
// It updates internal state and returns any detected anomalies.
func (as *anomalyState) Detect(id identity.Identity, decision Decision, now time.Time) []AnomalyRecord {
	as.mu.Lock()
	defer as.mu.Unlock()

	var anomalies []AnomalyRecord

	// 1. Repeated Denial detection (P-07 rules-based).
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

	// 2. Spike detection & Statistical Velocity (P-08).
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

	// Rule: > 100 requests per minute is a hard spike (P-07).
	count := len(activity)
	if count > 100 {
		anomalies = append(anomalies, AnomalyRecord{
			Type:    AnomalySpike,
			Message: fmt.Sprintf("caller %q operation spike: %d requests in last minute", id.CallerID, count),
		})
	}

	// P-08: Statistical baselining of token velocity.
	stats := as.velocityStats[id.CallerID]
	if stats == nil {
		stats = &runningStats{}
		as.velocityStats[id.CallerID] = stats
	}

	// Update stats for the current per-minute count.
	stats.Update(float64(count))

	// After we have enough data (n > 50), flag if current count > mean + 3*stddev.
	if stats.n > 50 {
		mean := stats.Mean()
		stdDev := math.Sqrt(stats.Variance())
		if count > 10 && float64(count) > mean+(3.0*stdDev) {
			anomalies = append(anomalies, AnomalyRecord{
				Type:    AnomalyStatistical,
				Message: fmt.Sprintf("statistical outlier: caller %q velocity %d is > 3 stddev above mean %.2f", id.CallerID, count, mean),
			})
		}
	}

	// 3. Unusual Hours & Statistical Hours (P-08).
	// Hardcoded unusual hours (P-07).
	if id.Role == identity.RoleDeveloper {
		hour := now.UTC().Hour()
		if hour >= 0 && hour < 6 {
			anomalies = append(anomalies, AnomalyRecord{
				Type:    AnomalyUnusualHours,
				Message: fmt.Sprintf("developer %q operating at unusual hour: %02d:00 UTC", id.CallerID, hour),
			})
		}

		// P-08: Statistical Hourly Profiling.
		profile := as.hourlyProfile[id.CallerID]
		if profile == nil {
			profile = make([]int, 24)
			as.hourlyProfile[id.CallerID] = profile
		}
		profile[hour]++

		// If this hour's activity is significantly higher than usual (e.g. > 5x average)
		// after we have some baseline (total requests > 100).
		total := 0
		for _, c := range profile {
			total += c
		}
		if total > 100 {
			avg := float64(total) / 24.0
			if float64(profile[hour]) > avg*5.0 && profile[hour] > 20 {
				anomalies = append(anomalies, AnomalyRecord{
					Type:    AnomalyStatistical,
					Message: fmt.Sprintf("statistical outlier: caller %q activity in hour %02d is %dx higher than baseline", id.CallerID, hour, int(float64(profile[hour])/avg)),
				})
			}
		}
	}

	return anomalies
}
