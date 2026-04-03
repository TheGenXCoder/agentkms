package policy

import (
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

func TestAnomalyState_SpikeDetection(t *testing.T) {
	as := newAnomalyState()
	id := identity.Identity{CallerID: "bert"}
	now := time.Now()

	// 101 requests in 1 minute.
	for i := 0; i < 100; i++ {
		anomalies := as.Detect(id, Decision{Allow: true}, now)
		if len(anomalies) > 0 {
			t.Fatalf("at request %d: expected no anomalies, got %v", i, anomalies)
		}
	}

	anomalies := as.Detect(id, Decision{Allow: true}, now)
	if len(anomalies) == 0 {
		t.Fatal("expected spike anomaly after 101 requests")
	}

	foundSpike := false
	for _, a := range anomalies {
		if a.Type == AnomalySpike {
			foundSpike = true
			break
		}
	}
	if !foundSpike {
		t.Fatalf("expected spike anomaly, got: %v", anomalies)
	}
}

func TestAnomalyState_RepeatedDenials(t *testing.T) {
	as := newAnomalyState()
	id := identity.Identity{CallerID: "bert"}
	now := time.Now()

	// 4 denials.
	for i := 1; i <= 4; i++ {
		anomalies := as.Detect(id, Decision{Allow: false}, now)
		if len(anomalies) > 0 {
			t.Fatalf("at denial %d: expected no anomalies, got %v", i, anomalies)
		}
	}

	// 5th denial.
	anomalies := as.Detect(id, Decision{Allow: false}, now)
	if len(anomalies) == 0 {
		t.Fatal("expected repeated_denial anomaly after 5 denials")
	}

	foundRepeated := false
	for _, a := range anomalies {
		if a.Type == AnomalyRepeatedDenial {
			foundRepeated = true
			break
		}
	}
	if !foundRepeated {
		t.Fatalf("expected repeated_denial anomaly, got: %v", anomalies)
	}

	// Successful (allowed) request should reset.
	anomalies = as.Detect(id, Decision{Allow: true}, now)
	if len(anomalies) > 0 {
		// Should not have any anomalies (unless spike)
		for _, a := range anomalies {
			if a.Type == AnomalyRepeatedDenial {
				t.Fatal("repeated_denial should be reset")
			}
		}
	}
}

func TestAnomalyState_UnusualHours(t *testing.T) {
	as := newAnomalyState()

	// Case 1: Developer at 02:00 UTC (unusual).
	idDev := identity.Identity{CallerID: "bert", Role: identity.RoleDeveloper}
	unusualTime := time.Date(2026, 4, 3, 2, 0, 0, 0, time.UTC)
	anomalies := as.Detect(idDev, Decision{Allow: true}, unusualTime)

	foundUnusual := false
	for _, a := range anomalies {
		if a.Type == AnomalyUnusualHours {
			foundUnusual = true
			break
		}
	}
	if !foundUnusual {
		t.Fatalf("expected unusual_hours anomaly for developer, got: %v", anomalies)
	}

	// Case 2: Service at 02:00 UTC (normal).
	idSvc := identity.Identity{CallerID: "ci-runner", Role: identity.RoleService}
	anomalies = as.Detect(idSvc, Decision{Allow: true}, unusualTime)
	for _, a := range anomalies {
		if a.Type == AnomalyUnusualHours {
			t.Fatal("unusual_hours should not trigger for service")
		}
	}

	// Case 3: Developer at 10:00 UTC (normal).
	normalTime := time.Date(2026, 4, 3, 10, 0, 0, 0, time.UTC)
	anomalies = as.Detect(idDev, Decision{Allow: true}, normalTime)
	for _, a := range anomalies {
		if a.Type == AnomalyUnusualHours {
			t.Fatal("unusual_hours should not trigger for developer during day")
		}
	}
}

func TestAnomalyState_StatisticalVelocity(t *testing.T) {
	as := newAnomalyState()
	id := identity.Identity{CallerID: "bert", Role: identity.RoleDeveloper}
	now := time.Now()

	// 1. Establish baseline (50 requests with low velocity: 1 per minute)
	for i := 0; i < 50; i++ {
		// Mock time advancing 1 minute each time
		tnow := now.Add(time.Duration(i) * time.Minute)
		as.Detect(id, Decision{Allow: true}, tnow)
	}

	// 2. Statistical outlier: suddenly 50 requests in one minute
	tburst := now.Add(51 * time.Minute)
	var anomalies []AnomalyRecord
	for i := 0; i < 50; i++ {
		// Store the anomalies from the 11th request onwards (where count > 10).
		res := as.Detect(id, Decision{Allow: true}, tburst)
		if len(res) > 0 {
			anomalies = append(anomalies, res...)
		}
	}

	foundOutlier := false
	for _, a := range anomalies {
		if a.Type == AnomalyStatistical {
			foundOutlier = true
			break
		}
	}
	if !foundOutlier {
		t.Fatalf("expected statistical_outlier anomaly for velocity burst, got: %v", anomalies)
	}
}
