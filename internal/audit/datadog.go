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

// DatadogConfig holds connection parameters for Datadog Logs API.
type DatadogConfig struct {
	// Address is the Datadog Logs API URL, e.g. "https://http-intake.logs.datadoghq.com/api/v2/logs".
	// Required.
	Address string

	// APIKey is the Datadog API key.
	// Required.
	// SECURITY: never log this value.
	APIKey string

	// Service is the Datadog service name for the logs.
	// Defaults to "agentkms" if empty.
	Service string

	// Host is the Datadog host field for the logs.
	// Optional.
	Host string

	// Tags is a comma-separated list of tags to add to the logs.
	// Example: "env:prod,team:platform".
	Tags string

	// BufferSize is the number of events to buffer before flushing to Datadog.
	// 0 or 1 means flush on every Log() call.
	BufferSize int

	// FlushInterval is how often buffered events are flushed.
	FlushInterval time.Duration

	// TLSInsecureSkipVerify skips TLS certificate verification.
	// MUST be false in production.
	TLSInsecureSkipVerify bool
}

// DatadogAuditSink writes AuditEvents to Datadog Logs API.
// Implements the Auditor interface.
type DatadogAuditSink struct {
	cfg    DatadogConfig
	client *http.Client
	mu     sync.Mutex
	buf    []AuditEvent
	maxBuf int
}

// NewDatadogAuditSink creates a DatadogAuditSink.
func NewDatadogAuditSink(ctx context.Context, cfg DatadogConfig) (*DatadogAuditSink, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("audit: DatadogAuditSink: Address is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("audit: DatadogAuditSink: APIKey is required")
	}

	transport := &http.Transport{}
	if cfg.TLSInsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	sink := &DatadogAuditSink{
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

// Log validates the event and writes it to Datadog.
func (s *DatadogAuditSink) Log(ctx context.Context, event AuditEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("audit: DatadogAuditSink: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: DatadogAuditSink: context cancelled: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.BufferSize <= 1 {
		return s.writeBatch(ctx, []AuditEvent{event})
	}

	s.buf = append(s.buf, event)
	if len(s.buf) > s.maxBuf {
		s.buf = s.buf[len(s.buf)-s.maxBuf:]
	}

	if len(s.buf) >= s.cfg.BufferSize {
		return s.flushLocked(ctx)
	}
	return nil
}

// Flush writes all buffered events to Datadog.
func (s *DatadogAuditSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked(ctx)
}

func (s *DatadogAuditSink) flushLocked(ctx context.Context) error {
	if len(s.buf) == 0 {
		return nil
	}
	err := s.writeBatch(ctx, s.buf)
	if err == nil {
		s.buf = s.buf[:0]
	}
	return err
}

type ddEvent struct {
	Service string     `json:"service,omitempty"`
	Host    string     `json:"host,omitempty"`
	Tags    string     `json:"ddtags,omitempty"`
	Message AuditEvent `json:"message"`
}

func (s *DatadogAuditSink) writeBatch(ctx context.Context, events []AuditEvent) error {
	service := s.cfg.Service
	if service == "" {
		service = "agentkms"
	}

	ddEvents := make([]ddEvent, len(events))
	for i, ev := range events {
		ddEvents[i] = ddEvent{
			Service: service,
			Host:    s.cfg.Host,
			Tags:    s.cfg.Tags,
			Message: ev,
		}
	}

	body, err := json.Marshal(ddEvents)
	if err != nil {
		return fmt.Errorf("audit: DatadogAuditSink: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Address, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit: DatadogAuditSink: build request: %w", err)
	}

	req.Header.Set("DD-API-KEY", s.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: DatadogAuditSink: HTTP request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit: DatadogAuditSink: unexpected status %d", resp.StatusCode)
	}

	return nil
}

func (s *DatadogAuditSink) flushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Flush(ctx)
		}
	}
}
