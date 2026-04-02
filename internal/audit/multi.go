package audit

import (
	"context"
	"errors"
	"fmt"
)

// MultiAuditor fans out every Log and Flush call to a set of underlying
// Auditor implementations.
//
// Fan-out behaviour:
//   - Log is called on EVERY sink regardless of whether a previous sink
//     returned an error.  This ensures that a single failing sink (e.g. a
//     temporarily unavailable ELK cluster) does not suppress delivery to
//     healthy sinks (e.g. a local file or CloudWatch).
//   - All errors are collected and returned as a joined error.  The caller
//     receives a non-nil error if ANY sink failed.  It is the caller's
//     responsibility to decide whether to abort the operation (recommended
//     for security-critical writes) or continue with a degraded audit trail.
//   - Flush follows the same fan-out and error-collection policy.
//
// An empty MultiAuditor (no sinks) is valid and returns nil from Log and
// Flush.  This simplifies test setup but should not occur in production.
//
// Concurrency: safe for concurrent use.  The underlying sink implementations
// are responsible for their own concurrency safety; MultiAuditor does not
// impose additional synchronisation beyond calling each sink sequentially.
type MultiAuditor struct {
	sinks []Auditor
}

// NewMultiAuditor constructs a MultiAuditor that fans out to the provided
// sinks.  At least one sink should be provided in production; an empty list
// is accepted but produces an audit gap.
func NewMultiAuditor(sinks ...Auditor) *MultiAuditor {
	// Defensive copy so the caller cannot mutate the slice after construction.
	s := make([]Auditor, len(sinks))
	copy(s, sinks)
	return &MultiAuditor{sinks: s}
}

// Log calls Log on every configured sink, collecting all errors.
//
// If k of N sinks fail, the returned error joins k individual errors.
// The error message identifies which sink index failed; since sink
// implementations are opaque interfaces, index-based identification is the
// best available without requiring sinks to expose a Name() method.
//
// IMPORTANT: a non-nil return does NOT mean the event was undelivered — some
// sinks may have succeeded.  The caller should log the error at an
// appropriate severity and decide whether to fail the operation.
func (m *MultiAuditor) Log(ctx context.Context, event AuditEvent) error {
	return m.fanOut(ctx, func(sink Auditor, idx int) error {
		if err := sink.Log(ctx, event); err != nil {
			return fmt.Errorf("audit sink[%d]: log: %w", idx, err)
		}
		return nil
	})
}

// Flush calls Flush on every configured sink, collecting all errors.
//
// Flush is best-effort on shutdown: all sinks are flushed regardless of
// individual failures.  All errors are collected and returned joined.
func (m *MultiAuditor) Flush(ctx context.Context) error {
	return m.fanOut(ctx, func(sink Auditor, idx int) error {
		if err := sink.Flush(ctx); err != nil {
			return fmt.Errorf("audit sink[%d]: flush: %w", idx, err)
		}
		return nil
	})
}

// fanOut calls op on each sink and collects non-nil errors into a joined
// error.  All sinks are called regardless of prior errors.
func (m *MultiAuditor) fanOut(ctx context.Context, op func(Auditor, int) error) error {
	var errs []error
	for i, sink := range m.sinks {
		if err := op(sink, i); err != nil {
			errs = append(errs, err)
		}
		// Continue to next sink even on error: fan-out must be total.
		_ = ctx // ctx is forwarded via closure; used here to satisfy linter
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Sinks returns the number of configured audit sinks.  Useful for
// configuration validation (warn if zero sinks in production).
func (m *MultiAuditor) Sinks() int {
	return len(m.sinks)
}
