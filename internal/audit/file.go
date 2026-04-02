package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// FileAuditSink writes AuditEvents as append-only Newline-Delimited JSON
// (NDJSON) to a local file.  Each line is a complete, self-contained JSON
// object representing one AuditEvent.
//
// This sink is used in Tier 0 (local dev mode, `agentkms-dev`).  It satisfies
// the Auditor interface and can be composed into a MultiAuditor alongside
// production sinks (ELK, Splunk, etc.).
//
// Concurrency: safe for concurrent use; a mutex serialises all writes.
//
// Append-only guarantee: the file is opened with O_APPEND.  No existing
// content is ever overwritten or truncated by this implementation.
type FileAuditSink struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

// NewFileAuditSink opens (or creates) the file at path and returns a
// FileAuditSink ready to write audit events.
//
// The file is opened in append mode: existing data is preserved.  If the
// file does not exist, it is created with mode 0600.
//
// The caller is responsible for calling Close() when the sink is no longer
// needed.
func NewFileAuditSink(path string) (*FileAuditSink, error) {
	// O_APPEND ensures every Write call atomically appends on POSIX systems,
	// even if the process is restarted mid-line.
	// O_CREATE creates the file if it does not exist.
	// O_WRONLY: we never need to read the file through this handle.
	// 0600: only the owning user can read/write — audit logs may contain
	//       IP addresses and session identifiers.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening file sink %q: %w", path, err)
	}

	enc := json.NewEncoder(f)
	// Disable HTML escaping so that key IDs like "payments/signing-key"
	// are not mangled to "payments\u002fsigning-key" in the log.
	enc.SetEscapeHTML(false)

	return &FileAuditSink{
		f:   f,
		enc: enc,
	}, nil
}

// Log serialises event as a single JSON line and appends it to the file.
//
// Log acquires the sink's mutex for the duration of the encode+write to
// guarantee that concurrent calls do not interleave partial JSON lines.
//
// The context is checked for cancellation before acquiring the lock; if
// already cancelled, Log returns immediately with ctx.Err() so the caller
// can decide whether the operation should be aborted.
func (s *FileAuditSink) Log(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: file sink log cancelled: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enc.Encode(event); err != nil {
		return fmt.Errorf("audit: file sink encode: %w", err)
	}
	
	// SECURITY: Ensure data is durably committed to disk after each write
	// This prevents audit event loss if the process crashes between a write
	// and the next scheduled Flush() call.
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("audit: file sink fsync: %w", err)
	}
	
	return nil
}

// Flush calls fsync on the underlying file, ensuring that all previously
// written bytes have been durably committed to the storage device.
//
// Flush should be called on graceful shutdown to prevent the loss of the
// most recently written events in the OS page cache.
func (s *FileAuditSink) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: file sink flush cancelled: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("audit: file sink fsync: %w", err)
	}
	return nil
}

// Close flushes and closes the underlying file.  After Close, Log and Flush
// will return errors.  Close is idempotent with respect to subsequent
// os.File.Close errors.
//
// Close is not part of the Auditor interface; callers that hold a concrete
// *FileAuditSink should call Close on shutdown after calling Flush.
func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		return fmt.Errorf("audit: file sink close sync: %w", err)
	}
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("audit: file sink close: %w", err)
	}
	return nil
}
