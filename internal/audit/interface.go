// Package audit defines the Auditor interface and AuditEvent type used
// throughout AgentKMS.
//
// SECURITY RULE: All audit writes in business logic MUST go through an
// Auditor implementation.  Never call a specific sink (ELK, Splunk, file,
// CloudWatch) directly from a handler, policy engine, or credential vending
// function.  This invariant is what makes the audit layer pluggable and
// testable without changing business logic.
//
// Implementations live alongside this file:
//
//	file.go       — append-only NDJSON file (local dev, Tier 0)
//	multi.go      — fan-out to N sinks (MultiAuditor)
//	elk.go        — Elasticsearch/Logstash HTTP ingest  (Tier 1, backlog AU-02)
//	splunk.go     — Splunk HEC                         (Tier 2, backlog AU-05)
//	datadog.go    — Datadog Logs API                   (Tier 2, backlog AU-06)
//	cloudwatch.go — AWS CloudWatch Logs                (Tier 3, backlog AU-07)
//	siem.go       — Generic SIEM webhook               (Tier 2, backlog AU-08)
package audit

import (
	"context"
	"time"
)

// Auditor is the only permitted way to write structured audit events in
// AgentKMS.
//
// All implementations MUST be safe for concurrent use by multiple goroutines.
//
// SECURITY CONTRACT:
//
//  1. Log MUST write every event durably (or queue it for durable delivery).
//     Silent failures are not permitted — if Log cannot write, it must return
//     an error so the caller can decide whether to abort the operation.
//
//  2. Log MUST NOT log the AuditEvent.PayloadHash field as anything other than
//     a hash reference.  The field is already a hash; implementations must not
//     attempt to "decode" or "expand" it.
//
//  3. Flush MUST be called on graceful shutdown to drain any internal buffers.
//     Implementations that write synchronously may return nil immediately.
//
//  4. No implementation may log raw key material, plaintext payloads, or LLM
//     API credentials — the AuditEvent type is intentionally structured to
//     make this impossible if used correctly, but implementations must not
//     append additional context that violates this rule.
type Auditor interface {
	// Log writes a single structured audit event to the sink.
	//
	// Log MUST NOT block indefinitely.  Implementations should apply an
	// internal write deadline and return an error on timeout rather than
	// hanging the calling goroutine.
	//
	// If the sink is temporarily unavailable, implementations may queue
	// events internally, but MUST return an error if the queue is full or
	// the write deadline is exceeded.
	//
	// CONTEXT WARNING: implementations check ctx for cancellation before
	// writing.  If the caller's request context may be cancelled (e.g., on
	// client disconnect or timeout), callers MUST pass a detached context to
	// Log to ensure audit events are not silently dropped.
	//
	// Correct pattern (Go 1.21+):
	//   auditor.Log(context.WithoutCancel(reqCtx), event)
	//
	// Without this, a client disconnect before the audit write completes
	// causes Log to return ctx.Err() and the event is lost — a compliance
	// violation under SOC 2 CC7.2 and PCI-DSS Req 10.
	Log(ctx context.Context, event AuditEvent) error

	// Flush ensures all buffered events have been written durably to the
	// underlying sink.  Must be called before process shutdown.
	//
	// Flush MUST NOT block indefinitely; it should apply a timeout derived
	// from the provided context.
	Flush(ctx context.Context) error
}

// Exporter is an optional interface that an Auditor may implement to support
// reading back audit events for compliance delivery.
//
// In Tier 0/1, the FileAuditSink implements this by reading from the local
// file.  In higher tiers, implementations may query ELK, Splunk, or other
// external sinks.
type Exporter interface {
	// Export streams all audit events between start and end (inclusive)
	// to the provided channel. Implementations must close the channel
	// when complete or on error.
	//
	// SECURITY: Callers must verify the identity has the 'auditor' role
	// before calling Export.  The returned events may contain sensitive
	// metadata (IPs, caller IDs).
	Export(ctx context.Context, start, end time.Time) (<-chan AuditEvent, <-chan error)
}
