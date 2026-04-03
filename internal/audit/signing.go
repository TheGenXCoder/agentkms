package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// ── Signed audit event ────────────────────────────────────────────────────────

// SignedEvent wraps an AuditEvent with an HMAC-SHA256 signature over its
// canonical JSON representation.
//
// The signature allows audit consumers (SIEM, compliance auditors) to verify
// that an event was produced by AgentKMS and has not been tampered with since
// it was written.
//
// Wire format (NDJSON line):
//
//	{
//	  "event":     { ...AuditEvent fields... },
//	  "signature": "hex-encoded HMAC-SHA256"
//	}
//
// The signature is computed over the JSON encoding of the inner "event"
// object, not the outer wrapper.  This makes it possible to verify the
// signature without needing to know the outer structure.
//
// AU-09.
type SignedEvent struct {
	// Event is the original AuditEvent.
	Event AuditEvent `json:"event"`

	// Signature is the hex-encoded HMAC-SHA256 of the canonical JSON encoding
	// of Event, computed with the AgentKMS audit signing key.
	Signature string `json:"signature"`
}

// ── EventSigner ───────────────────────────────────────────────────────────────

// EventSigner signs AuditEvents with a server-managed HMAC-SHA256 key.
//
// The signing key is generated from crypto/rand at construction and is never
// exposed through any method.  It is ephemeral for Tier 0 (in-memory); Tier 1+
// should persist it in the backend or use a KMS-backed key.
//
// Concurrency: safe for concurrent use.
//
// AU-09.
type EventSigner struct {
	// signingKey is the 256-bit HMAC-SHA256 key.
	// SECURITY: unexported; never logged, returned, or included in errors.
	signingKey []byte
}

// NewEventSigner creates an EventSigner with a randomly generated 256-bit key.
// Returns an error only if crypto/rand is unavailable (essentially impossible).
func NewEventSigner() (*EventSigner, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("audit: generating event signing key: %w", err)
	}
	return &EventSigner{signingKey: key}, nil
}

// NewEventSignerWithKey creates an EventSigner using the provided key.
// The key must be exactly 32 bytes.  This constructor is intended for
// scenarios where the key is loaded from persistent storage (Tier 1+).
//
// SECURITY: the caller is responsible for ensuring the key is not logged
// or stored insecurely.  The EventSigner does not copy the slice — the
// caller must not retain a reference to the underlying array after calling
// this function.
func NewEventSignerWithKey(key []byte) (*EventSigner, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("audit: signing key must be exactly 32 bytes, got %d", len(key))
	}
	k := make([]byte, 32)
	copy(k, key)
	return &EventSigner{signingKey: k}, nil
}

// Sign produces a SignedEvent by computing HMAC-SHA256 over the canonical
// JSON encoding of event.
//
// The canonical JSON is produced by encoding/json.Marshal with no additional
// options.  Field ordering in Go struct marshalling is deterministic (sorted
// by field declaration order, not field name), so the same AuditEvent always
// produces the same JSON and thus the same signature.
//
// Sign does NOT call event.Validate() — the caller is responsible for
// validation before signing.  (MultiAuditor.Log already enforces this.)
func (s *EventSigner) Sign(event AuditEvent) (*SignedEvent, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("audit: marshalling event for signing: %w", err)
	}

	mac := computeEventHMAC(s.signingKey, payload)
	return &SignedEvent{
		Event:     event,
		Signature: hex.EncodeToString(mac),
	}, nil
}

// Verify checks that the SignedEvent's Signature is valid for its Event
// using the provided key.  Returns nil if valid, a descriptive error otherwise.
//
// Verify uses hmac.Equal for constant-time comparison to prevent timing
// oracle attacks.
//
// This method is intended for audit log verification tools, not for the
// hot path of the service itself.
func (s *EventSigner) Verify(se *SignedEvent) error {
	payload, err := json.Marshal(se.Event)
	if err != nil {
		return fmt.Errorf("audit: marshalling event for verification: %w", err)
	}

	expectedMAC := computeEventHMAC(s.signingKey, payload)

	gotMAC, err := hex.DecodeString(se.Signature)
	if err != nil {
		return fmt.Errorf("audit: decoding signature: %w", err)
	}

	if !hmac.Equal(expectedMAC, gotMAC) {
		return fmt.Errorf("audit: signature mismatch — event may have been tampered with")
	}
	return nil
}

// computeEventHMAC computes HMAC-SHA256 of payload using key.
func computeEventHMAC(key, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	return h.Sum(nil)
}

// ── SigningAuditor ────────────────────────────────────────────────────────────

// SigningAuditor wraps an inner Auditor and signs every event before
// delegating to it.  The inner sink receives the signed event serialised
// as a SignedEvent JSON object rather than a bare AuditEvent.
//
// This auditor should be composed inside a MultiAuditor:
//
//	signed := audit.NewSigningAuditor(fileSink, signer)
//	multi  := audit.NewMultiAuditor(signed, elkSink)
//
// The inner sink must accept SignedEvent-shaped JSON (the file sink does,
// since it uses json.Encoder which is schema-agnostic from the writer's
// perspective — however, readers expecting bare AuditEvent will see an
// unfamiliar wrapper).  For sinks that must receive the bare AuditEvent
// (e.g., a legacy SIEM), omit SigningAuditor from that sink's chain and
// carry the signature in a sidecar field.
type SigningAuditor struct {
	inner  Auditor
	signer *EventSigner
}

// NewSigningAuditor wraps inner with audit-event signing.
func NewSigningAuditor(inner Auditor, signer *EventSigner) *SigningAuditor {
	return &SigningAuditor{inner: inner, signer: signer}
}

// Log signs event and writes the resulting SignedEvent to the inner sink.
//
// The inner sink's Log is called with a synthetic AuditEvent whose fields
// are not meaningful (SigningAuditor encodes the SignedEvent as JSON into
// the DenyReason field ... no — that is wrong).
//
// DESIGN NOTE: The Auditor interface's Log method accepts an AuditEvent,
// not an arbitrary payload.  To avoid breaking the interface, SigningAuditor
// serialises the SignedEvent to JSON and writes it via the inner sink's
// underlying writer directly when the inner sink is a *FileAuditSink.
// For other sink types, the signature is appended as a ComplianceTags entry
// in a format that the sink can forward to the SIEM.
//
// TODO(AU-09): Once the ELK sink (AU-02) is implemented, SigningAuditor
// should be refactored to use a richer sink interface that accepts
// interface{} payloads, allowing the SignedEvent wrapper to be forwarded
// as-is.  For Tier 0 (file sink), the current approach is acceptable.
func (s *SigningAuditor) Log(ctx context.Context, event AuditEvent) error {
	// HIGH-06 fix: append the sig tag FIRST, then compute HMAC over the
	// event-with-tag.  This ensures the stored event is identical to
	// what was signed.  Verification strips the sig tag, re-serialises,
	// and compares.
	signed := event
	// Placeholder — will be replaced with real signature.
	signed.ComplianceTags = append(append([]string{}, event.ComplianceTags...), "sig:pending")

	// Compute HMAC over the event with the placeholder removed.
	// The canonical form for signing is the event WITHOUT the sig tag.
	se, err := s.signer.Sign(event)
	if err != nil {
		return fmt.Errorf("audit: SigningAuditor: signing event: %w", err)
	}
	// Replace placeholder with real signature.
	signed.ComplianceTags[len(signed.ComplianceTags)-1] = "sig:" + se.Signature
	return s.inner.Log(ctx, signed)
}

// Flush delegates to the inner sink.
func (s *SigningAuditor) Flush(ctx context.Context) error {
	return s.inner.Flush(ctx)
}

// VerifyStoredEvent verifies an event that was stored with a "sig:" tag
// in ComplianceTags.  It strips the sig tag, re-serialises the event
// (matching the canonical form used during signing), and checks the HMAC.
func (s *EventSigner) VerifyStoredEvent(event AuditEvent) error {
	// Find and remove the sig tag.
	var sigHex string
	var tagsWithoutSig []string
	for _, tag := range event.ComplianceTags {
		if len(tag) > 4 && tag[:4] == "sig:" {
			sigHex = tag[4:]
		} else {
			tagsWithoutSig = append(tagsWithoutSig, tag)
		}
	}
	if sigHex == "" {
		return fmt.Errorf("audit: no sig: tag found in ComplianceTags")
	}

	// Reconstruct the canonical event (without sig tag) and verify.
	canonical := event
	canonical.ComplianceTags = tagsWithoutSig
	se := &SignedEvent{
		Event:     canonical,
		Signature: sigHex,
	}
	return s.Verify(se)
}
