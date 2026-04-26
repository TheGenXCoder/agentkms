package webhooks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// NDJSONAuditStore is a production AuditStore backed by the NDJSON audit log
// written by audit.FileAuditSink.
//
// FindByTokenHash performs a full linear scan of the file on each call. This
// is intentional: webhook events are rare (a few per incident), the file is
// append-only, and a simple scan avoids an in-process index that could diverge
// from the on-disk truth. For very large audit files (> 1 GiB) an external
// forensics query tool (agentkms-forensics) is the right instrument; the
// webhook response path is not a hot loop.
//
// UpdateInvalidatedAt appends a synthetic "revoke" audit event rather than
// rewriting the original vend event. This preserves the append-only guarantee
// of the audit file. The next FindByTokenHash call will see the revoke event
// and return a record with InvalidatedAt set.
//
// Concurrency: safe for concurrent use; a mutex serialises all file operations.
//
// File format: one JSON-encoded audit.AuditEvent per line (NDJSON).
// The store looks for events where:
//   - AuditEvent.ProviderTokenHash == hash  (identifies the credential)
//   - AuditEvent.CredentialUUID != ""       (issued by AgentKMS)
//
// The most recently written "revoke" event for a given CredentialUUID
// determines the InvalidatedAt value. If no revoke event exists, the
// credential is treated as still live.
type NDJSONAuditStore struct {
	mu   sync.Mutex
	path string
}

// NewNDJSONAuditStore returns an NDJSONAuditStore that reads from and appends
// to the NDJSON audit log at path. The file must already exist (created by
// audit.FileAuditSink on server start). NewNDJSONAuditStore does not open the
// file; it is opened fresh on each FindByTokenHash and UpdateInvalidatedAt
// call to tolerate log rotation without requiring a restart.
func NewNDJSONAuditStore(path string) *NDJSONAuditStore {
	return &NDJSONAuditStore{path: path}
}

// FindByTokenHash scans the NDJSON audit log for a credential_vend event
// whose provider_token_hash matches hash, then checks whether a subsequent
// revoke event for the same CredentialUUID sets InvalidatedAt.
//
// Returns ErrCredentialNotFound when no vend record matches hash.
func (s *NDJSONAuditStore) FindByTokenHash(ctx context.Context, hash string) (*CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("webhooks: NDJSONAuditStore: open %q: %w", s.path, err)
	}
	defer f.Close()

	// Two-pass approach in a single scan:
	//   Pass 1 (implicit): collect all events; find the vend event for hash.
	//   We also collect the latest revoke event for each CredentialUUID so we
	//   can determine InvalidatedAt without a second file read.

	var (
		// vendRecord holds the first vend event that matches hash.
		vendRecord *audit.AuditEvent
		// revokedAt maps CredentialUUID → the latest InvalidatedAt from revoke events.
		revokedAt = make(map[string]time.Time)
	)

	scanner := bufio.NewScanner(f)
	// Increase scanner buffer for very long lines (large scope JSON).
	const maxLineSz = 1 << 20 // 1 MiB
	buf := make([]byte, maxLineSz)
	scanner.Buffer(buf, maxLineSz)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var ev audit.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			// Skip malformed lines — file may be mid-write.
			continue
		}

		// Track the most recent invalidation timestamp for each credential UUID.
		// Both "revoke" events emitted by UpdateInvalidatedAt and any external
		// revocation events (e.g. manual admin revoke) set this.
		if ev.Operation == audit.OperationRevoke &&
			ev.CredentialUUID != "" &&
			!ev.Timestamp.IsZero() {
			if existing, ok := revokedAt[ev.CredentialUUID]; !ok || ev.Timestamp.After(existing) {
				revokedAt[ev.CredentialUUID] = ev.Timestamp
			}
		}

		// Match vend event by ProviderTokenHash.
		if vendRecord == nil &&
			ev.ProviderTokenHash == hash &&
			ev.CredentialUUID != "" {
			cp := ev
			vendRecord = &cp
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("webhooks: NDJSONAuditStore: scan %q: %w", s.path, err)
	}

	if vendRecord == nil {
		return nil, ErrCredentialNotFound
	}

	rec := &CredentialRecord{
		CredentialUUID:    vendRecord.CredentialUUID,
		ProviderTokenHash: vendRecord.ProviderTokenHash,
		CredentialType:    vendRecord.CredentialType,
		IssuedAt:          vendRecord.Timestamp,
		CallerID:          vendRecord.CallerID,
		RuleID:            vendRecord.RuleID,
		InvalidatedAt:     revokedAt[vendRecord.CredentialUUID], // zero if still live
	}
	return rec, nil
}

// UpdateInvalidatedAt appends a synthetic audit.OperationRevoke event to the
// NDJSON log with the given credentialUUID and timestamp. This marks the
// credential as invalidated without rewriting or truncating the audit file,
// preserving the append-only integrity guarantee.
//
// The next FindByTokenHash call for this credential will see the revoke event
// and return a CredentialRecord with InvalidatedAt set, routing subsequent
// webhooks for the same token to ExpiredBranch.
func (s *NDJSONAuditStore) UpdateInvalidatedAt(ctx context.Context, credentialUUID string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ev, err := audit.New()
	if err != nil {
		return fmt.Errorf("webhooks: NDJSONAuditStore: create event: %w", err)
	}
	ev.Operation = audit.OperationRevoke
	ev.CredentialUUID = credentialUUID
	ev.InvalidationReason = audit.ReasonRevokedLeak
	ev.Outcome = audit.OutcomeSuccess
	ev.Timestamp = at

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhooks: NDJSONAuditStore: marshal event: %w", err)
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("webhooks: NDJSONAuditStore: open %q for append: %w", s.path, err)
	}
	defer f.Close()

	// Append the JSON line followed by a newline (NDJSON format).
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("webhooks: NDJSONAuditStore: write event: %w", err)
	}
	// fsync for durability — consistent with FileAuditSink.Log.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("webhooks: NDJSONAuditStore: fsync: %w", err)
	}
	return nil
}
