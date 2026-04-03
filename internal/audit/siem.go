package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// SIEMConfig holds connection parameters for a Generic SIEM webhook.
type SIEMConfig struct {
	// Address is the webhook URL.
	// Required.
	Address string

	// AuthHeader is the HTTP header to use for authentication, e.g. "X-API-Key".
	// Optional.
	AuthHeader string

	// AuthValue is the value for the authentication header.
	// Optional.
	// SECURITY: never log this value.
	AuthValue string

	// BufferSize is the number of events to buffer before flushing to the webhook.
	// 0 or 1 means flush on every Log() call.
	BufferSize int

	// FlushInterval is how often buffered events are flushed.
	FlushInterval time.Duration

	// TLSInsecureSkipVerify skips TLS certificate verification.
	// MUST be false in production.
	TLSInsecureSkipVerify bool
}

// SIEMAuditSink writes AuditEvents to a Generic SIEM webhook as NDJSON.
// Implements the Auditor interface.
type SIEMAuditSink struct {
	cfg    SIEMConfig
	client *http.Client
	mu     sync.Mutex
	buf    []AuditEvent
	maxBuf int
}

// NewSIEMAuditSink creates a SIEMAuditSink.
func NewSIEMAuditSink(ctx context.Context, cfg SIEMConfig) (*SIEMAuditSink, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("audit: SIEMAuditSink: Address is required")
	}

	transport := &http.Transport{}
	if cfg.TLSInsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	sink := &SIEMAuditSink{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}

	if cfg.BufferSize > 1 {
		sink.maxBuf = cfg.BufferSize * 20
	} else {
		sink.maxBuf = 100
	}

	if cfg.FlushInterval > 0 {
		go sink.flushLoop(ctx, cfg.FlushInterval)
	}

	return sink, nil
}

// Log validates the event and writes it to the webhook.
func (s *SIEMAuditSink) Log(ctx context.Context, event AuditEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("audit: SIEMAuditSink: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: SIEMAuditSink: context cancelled: %w", err)
	}

	s.mu.Lock()

	if s.cfg.BufferSize <= 1 {
		s.mu.Unlock()
		return s.writeBatch(ctx, []AuditEvent{event})
	}

	s.buf = append(s.buf, event)
	if len(s.buf) > s.maxBuf {
		s.buf = s.buf[len(s.buf)-s.maxBuf:]
	}

	if len(s.buf) >= s.cfg.BufferSize {
		return s.flushLocked(ctx)
	}
	s.mu.Unlock()
	return nil
}

// Flush writes all buffered events to the webhook.
func (s *SIEMAuditSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	return s.flushLocked(ctx)
}

func (s *SIEMAuditSink) flushLocked(ctx context.Context) error {
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.buf
	s.buf = make([]AuditEvent, 0, s.cfg.BufferSize)
	s.mu.Unlock()

	return s.writeBatch(ctx, batch)
}

func (s *SIEMAuditSink) writeBatch(ctx context.Context, events []AuditEvent) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("audit: SIEMAuditSink: marshal: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Address, &body)
	if err != nil {
		return fmt.Errorf("audit: SIEMAuditSink: build request: %w", err)
	}

	if s.cfg.AuthHeader != "" && s.cfg.AuthValue != "" {
		req.Header.Set(s.cfg.AuthHeader, s.cfg.AuthValue)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: SIEMAuditSink: HTTP request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit: SIEMAuditSink: unexpected status %d", resp.StatusCode)
	}

	return nil
}

func (s *SIEMAuditSink) flushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s.Flush(finalCtx)
			return
		case <-ticker.C:
			s.Flush(ctx)
		}
	}
}
