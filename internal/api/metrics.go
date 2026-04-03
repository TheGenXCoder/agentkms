package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ── Metrics middleware ────────────────────────────────────────────────────────

// metricsMiddleware tracks request count, latency, and status codes for
// Prometheus-style metrics collection.
//
// Metrics exported:
// - http_requests_total{method, status}
// - http_request_duration_seconds_bucket{le}
// - agentkms_audit_events_total
//
// p99 latency is derived from the duration buckets by Prometheus.
func (s *Server) metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		
		next(rw, r)
		
		duration := time.Since(start).Seconds()
		s.recordRequestMetric(r.Method, rw.status, duration)
	}
}

// ── Metrics registry ──────────────────────────────────────────────────────────

var (
	// requestsTotal: method -> status -> count
	requestsTotal = make(map[string]map[int]*int64)
	// requestDurationBuckets: method -> bucket -> count
	// Buckets: 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
	requestDurationBuckets = make(map[string]map[float64]*int64)
	requestDurationSum = make(map[string]*float64)
	
	auditEventsTotal int64
	
	metricsMu sync.Mutex
	
	buckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
)

func (s *Server) recordRequestMetric(method string, status int, duration float64) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	
	if requestsTotal[method] == nil {
		requestsTotal[method] = make(map[int]*int64)
	}
	if requestsTotal[method][status] == nil {
		var v int64
		requestsTotal[method][status] = &v
	}
	*requestsTotal[method][status]++
	
	if requestDurationBuckets[method] == nil {
		requestDurationBuckets[method] = make(map[float64]*int64)
		for _, b := range buckets {
			var v int64
			requestDurationBuckets[method][b] = &v
		}
		var inf int64
		requestDurationBuckets[method][-1] = &inf // -1 represents +Inf
	}
	
	for _, b := range buckets {
		if duration <= b {
			*requestDurationBuckets[method][b]++
		}
	}
	*requestDurationBuckets[method][-1]++ // +Inf
	
	if requestDurationSum[method] == nil {
		var v float64
		requestDurationSum[method] = &v
	}
	*requestDurationSum[method] += duration
}

// RecordAuditEvent tracks the total volume of audit events written.
// Call this from auditLog.
func (s *Server) RecordAuditEvent() {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	auditEventsTotal++
}

// handleMetrics handles the /metrics endpoint, exporting data in Prometheus format.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	fmt.Fprintln(w, "# HELP http_requests_total Total number of HTTP requests.")
	fmt.Fprintln(w, "# TYPE http_requests_total counter")
	for method, statuses := range requestsTotal {
		for status, count := range statuses {
			fmt.Fprintf(w, "http_requests_total{method=\"%s\",status=\"%d\"} %d\n", method, status, *count)
		}
	}
	
	fmt.Fprintln(w, "# HELP http_request_duration_seconds_bucket HTTP request duration buckets.")
	fmt.Fprintln(w, "# TYPE http_request_duration_seconds_bucket histogram")
	for method, counts := range requestDurationBuckets {
		for _, b := range buckets {
			fmt.Fprintf(w, "http_request_duration_seconds_bucket{method=\"%s\",le=\"%g\"} %d\n", method, b, *counts[b])
		}
		// +Inf
		infCount := *counts[-1]
		fmt.Fprintf(w, "http_request_duration_seconds_bucket{method=\"%s\",le=\"+Inf\"} %d\n", method, infCount)
		fmt.Fprintf(w, "http_request_duration_seconds_count{method=\"%s\"} %d\n", method, infCount)
		
		sum := 0.0
		if s, ok := requestDurationSum[method]; ok {
			sum = *s
		}
		fmt.Fprintf(w, "http_request_duration_seconds_sum{method=\"%s\"} %f\n", method, sum)
	}
	
	fmt.Fprintln(w, "# HELP agentkms_audit_events_total Total volume of audit events written.")
	fmt.Fprintln(w, "# TYPE agentkms_audit_events_total counter")
	fmt.Fprintf(w, "agentkms_audit_events_total %d\n", auditEventsTotal)
}

// ── Response Writer Wrapper ───────────────────────────────────────────────────

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
