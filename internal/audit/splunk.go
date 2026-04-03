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

// SplunkConfig holds connection parameters for Splunk HEC.
type SplunkConfig struct {
	// Address is the Splunk HEC base URL, e.g. "https://splunk.internal:8088/services/collector".
	// Required.
	Address string

	// Token is the HEC authentication token.
	// Required.
	// SECURITY: never log this value.
	Token string

	// SourceType is the Splunk sourcetype for the event.
	// Defaults to "agentkms-audit" if empty.
	SourceType string

	// Index is the Splunk index to write audit events to.
	// Optional; if empty, Splunk uses the default index for the HEC token.
	Index string

	// Host is the Splunk host field for the event.
	// Optional.
	Host string

	// BufferSize is the number of events to buffer before flushing to Splunk.
	// 0 or 1 means flush on every Log() call.
	BufferSize int

	// FlushInterval is how often buffered events are flushed.
	FlushInterval time.Duration

	// TLSInsecureSkipVerify skips TLS certificate verification.
	// MUST be false in production.
	TLSInsecureSkipVerify bool
}

// SplunkAuditSink writes AuditEvents to Splunk HEC.
// Implements the Auditor interface.
type SplunkAuditSink struct {
	cfg    SplunkConfig
	client *http.Client
	mu     sync.Mutex
	buf    []AuditEvent
	maxBuf int
}

// NewSplunkAuditSink creates a SplunkAuditSink.
func NewSplunkAuditSink(ctx context.Context, cfg SplunkConfig) (*SplunkAuditSink, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("audit: SplunkAuditSink: Address is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("audit: SplunkAuditSink: Token is required")
	}

	transport := &http.Transport{}
	if cfg.TLSInsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	sink := &SplunkAuditSink{
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

// Log validates the event and writes it to Splunk.
func (s *SplunkAuditSink) Log(ctx context.Context, event AuditEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("audit: SplunkAuditSink: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: SplunkAuditSink: context cancelled: %w", err)
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

// Flush writes all buffered events to Splunk.
func (s *SplunkAuditSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	return s.flushLocked(ctx)
}

func (s *SplunkAuditSink) flushLocked(ctx context.Context) error {
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.buf
	s.buf = make([]AuditEvent, 0, s.cfg.BufferSize)
	s.mu.Unlock()

	return s.writeBatch(ctx, batch)
}

// splunkEvent represents the HEC JSON format.
type splunkEvent struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host,omitempty"`
	SourceType string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      AuditEvent  `json:"event"`
}

func (s *SplunkAuditSink) writeBatch(ctx context.Context, events []AuditEvent) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)

	sourceType := s.cfg.SourceType
	if sourceType == "" {
		sourceType = "agentkms-audit"
	}

	for _, ev := range events {
		se := splunkEvent{
			Time:       ev.Timestamp.Unix(),
			Host:       s.cfg.Host,
			SourceType: sourceType,
			Index:      s.cfg.Index,
			Event:      ev,
		}
		if err := enc.Encode(se); err != nil {
			return fmt.Errorf("audit: SplunkAuditSink: encode: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Address, &body)
	if err != nil {
		return fmt.Errorf("audit: SplunkAuditSink: build request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: SplunkAuditSink: HTTP request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit: SplunkAuditSink: unexpected status %d", resp.StatusCode)
	}

	return nil
}

func (s *SplunkAuditSink) flushLoop(ctx context.Context, interval time.Duration) {
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
