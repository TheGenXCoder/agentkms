package audit

// ELK audit sink — AU-02.
//
// Writes AuditEvents as NDJSON to an Elasticsearch cluster via the
// Elasticsearch Ingest API (PUT /{index}/_doc).  Falls back to the
// Bulk API (POST /_bulk) for batched writes when BufferSize > 1.
//
// Security requirements:
//   - TLS is required for production (ELKConfig.TLSInsecureSkipVerify = false)
//   - The API key / basic-auth credentials are never logged
//   - Events are validated via AuditEvent.Validate() before writing
//
// Concurrency: safe for concurrent use; a mutex serialises batch flushes.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// validEventID matches UUID-format event IDs (lowercase hex + hyphens).
var validEventID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ELKConfig holds connection parameters for an Elasticsearch cluster.
type ELKConfig struct {
	// Address is the Elasticsearch base URL, e.g. "https://es.internal:9200".
	// Required.
	Address string

	// Index is the Elasticsearch index to write audit events to.
	// Defaults to "agentkms-audit" if empty.
	Index string

	// APIKey is an Elasticsearch API key in "<id>:<secret>" format.
	// Takes precedence over Username/Password if non-empty.
	// SECURITY: never log this value.
	APIKey string

	// Username and Password are used for basic auth when APIKey is empty.
	// SECURITY: never log these values.
	Username string
	Password string

	// BufferSize is the number of events to buffer before flushing to ES.
	// 0 or 1 means flush on every Log() call (synchronous, no batching).
	// Higher values improve throughput at the cost of potential event loss
	// on unclean shutdown (mitigated by Flush()).
	BufferSize int

	// FlushInterval is how often buffered events are flushed if BufferSize
	// is not reached.  0 disables interval flushing (only Flush() triggers).
	FlushInterval time.Duration

	// TLSInsecureSkipVerify skips TLS certificate verification.
	// MUST be false in production.  Permitted for local POC only.
	TLSInsecureSkipVerify bool
}

// ELKAuditSink writes AuditEvents to an Elasticsearch cluster.
// Implements the Auditor interface.
type ELKAuditSink struct {
	cfg    ELKConfig
	index  string
	client *http.Client
	mu     sync.Mutex
	buf    []AuditEvent

	// dropped tracks events dropped due to buffer overflow.
	dropped int

	// maxBuf is the hard cap on buffer size (BufferSize * 20).
	maxBuf int
}

// NewELKAuditSink creates an ELKAuditSink ready to write events.
// The sink uses the provided context for background flush goroutines.
// Call Close() (or cancel the context) to shut down background workers.
func NewELKAuditSink(ctx context.Context, cfg ELKConfig) (*ELKAuditSink, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("audit: ELKAuditSink: Address is required")
	}
	index := cfg.Index
	if index == "" {
		index = "agentkms-audit"
	}

	transport := &http.Transport{}
	if cfg.TLSInsecureSkipVerify {
		// SECURITY: only for local POC; must be false in production.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	sink := &ELKAuditSink{
		cfg:    cfg,
		index:  index,
		client: &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}
	// Hard cap: 20× buffer size, minimum 100.
	if cfg.BufferSize > 1 {
		sink.maxBuf = cfg.BufferSize * 20
	} else {
		sink.maxBuf = 100
	}
	if sink.maxBuf < 100 {
		sink.maxBuf = 100
	}

	// Start background flush goroutine if interval is configured.
	if cfg.FlushInterval > 0 {
		go sink.flushLoop(ctx, cfg.FlushInterval)
	}

	return sink, nil
}

// Log validates the event and writes it to Elasticsearch.
// If BufferSize > 1, the event is buffered; otherwise it is written immediately.
func (s *ELKAuditSink) Log(ctx context.Context, event AuditEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("audit: ELKAuditSink: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: ELKAuditSink: context cancelled: %w", err)
	}

	s.mu.Lock()
	if s.cfg.BufferSize <= 1 {
		s.mu.Unlock()
		return s.writeOne(ctx, event)
	}

	s.buf = append(s.buf, event)

	// Cap buffer to prevent unbounded growth during sustained ELK outage.
	if len(s.buf) > s.maxBuf {
		drop := len(s.buf) - s.maxBuf
		s.buf = s.buf[drop:]
		s.dropped += drop
	}

	if len(s.buf) >= s.cfg.BufferSize {
		return s.flushLocked(ctx)
	}
	s.mu.Unlock()
	return nil
}

// Flush writes all buffered events to Elasticsearch.
// Must be called on graceful shutdown.
func (s *ELKAuditSink) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: ELKAuditSink: flush context cancelled: %w", err)
	}
	s.mu.Lock()
	return s.flushLocked(ctx)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// writeOne writes a single event via PUT /{index}/_doc/{event_id}.
func (s *ELKAuditSink) writeOne(ctx context.Context, event AuditEvent) error {
	if !validEventID.MatchString(event.EventID) {
		return fmt.Errorf("audit: ELKAuditSink: invalid EventID format: %q", event.EventID)
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: ELKAuditSink: marshal: %w", err)
	}

	docURL := fmt.Sprintf("%s/%s/_doc/%s",
		strings.TrimRight(s.cfg.Address, "/"),
		s.index,
		url.PathEscape(event.EventID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, docURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit: ELKAuditSink: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.setAuth(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: ELKAuditSink: HTTP request: %w", err)
	}
	defer resp.Body.Close()
	// Drain response body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit: ELKAuditSink: unexpected status %d for event %s",
			resp.StatusCode, event.EventID)
	}
	return nil
}

// flushLocked swaps the buffer and flushes it to ES without holding the lock
// during the HTTP call. Caller must hold s.mu, but this function will release
// it before blocking.
func (s *ELKAuditSink) flushLocked(ctx context.Context) error {
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return nil
	}

	// Swap buffer to avoid blocking Log() during slow HTTP calls.
	batch := s.buf
	s.buf = make([]AuditEvent, 0, s.cfg.BufferSize)
	s.mu.Unlock()

	// Build NDJSON bulk payload.
	var bulk bytes.Buffer
	for _, ev := range batch {
		meta := fmt.Sprintf(`{"index":{"_index":%q,"_id":%q}}`, s.index, ev.EventID)
		bulk.WriteString(meta)
		bulk.WriteByte('\n')

		line, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("audit: ELKAuditSink: marshal event %s: %w", ev.EventID, err)
		}
		bulk.Write(line)
		bulk.WriteByte('\n')
	}

	url := fmt.Sprintf("%s/_bulk", strings.TrimRight(s.cfg.Address, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &bulk)
	if err != nil {
		return fmt.Errorf("audit: ELKAuditSink: build bulk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	s.setAuth(req)

	resp, err := s.client.Do(req)
	if err != nil {
		// Log and discard, do not re-buffer best-effort batch.
		return fmt.Errorf("audit: ELKAuditSink: bulk HTTP: %w", err)
	}
	defer resp.Body.Close()

	// Parse bulk response to detect per-item failures (MEDIUM-04).
	// ES returns 200 even when individual items fail; check "errors" field.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit: ELKAuditSink: bulk returned status %d", resp.StatusCode)
	}

	var bulkResp struct {
		Errors bool `json:"errors"`
		Items  []struct {
			Index struct {
				ID     string `json:"_id"`
				Status int    `json:"status"`
				Error  struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"error"`
			} `json:"index"`
		} `json:"items"`
	}
	if err := json.Unmarshal(respBody, &bulkResp); err != nil {
		return fmt.Errorf("audit: ELKAuditSink: parse bulk response: %w", err)
	}
	if bulkResp.Errors {
		failed := 0
		for _, item := range bulkResp.Items {
			if item.Index.Status < 200 || item.Index.Status >= 300 {
				failed++
			}
		}
		fmt.Fprintf(os.Stderr, "audit: ELK: bulk write had %d/%d item failures\n",
			failed, len(bulkResp.Items))
	}

	s.mu.Lock()
	if s.dropped > 0 {
		fmt.Fprintf(os.Stderr, "audit: ELK: %d events were dropped due to buffer overflow\n", s.dropped)
		s.dropped = 0
	}
	s.mu.Unlock()
	return nil
}

// setAuth adds the configured authentication header to the request.
// SECURITY: API key and password are set in headers, never in URLs or logs.
func (s *ELKAuditSink) setAuth(req *http.Request) {
	if s.cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.cfg.APIKey)
	} else if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
}

// flushLoop periodically flushes buffered events at the configured interval.
// Runs in a goroutine until ctx is cancelled.
func (s *ELKAuditSink) flushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s.mu.Lock()
			_ = s.flushLocked(finalCtx)
			return
		case <-ticker.C:
			s.mu.Lock()
			if err := s.flushLocked(ctx); err != nil {
				s.mu.Lock()
				fmt.Fprintf(os.Stderr, "audit: ELK: flush error: %v (buffer=%d, dropped=%d)\n",
					err, len(s.buf), s.dropped)
				s.mu.Unlock()
			}
		}
	}
}
