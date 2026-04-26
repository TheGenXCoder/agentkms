package webhooks

import (
	"context"
	"sync"
	"time"
)

// DevAuditStore is an in-memory AuditStore implementation for the dev server.
// It starts empty; credentials must be pre-registered via Register or seeded
// from the EncryptedKV store. Primarily used so the AlertOrchestrator has a
// non-nil store during T6 demo scenarios where credentials are inserted at
// runtime via Register.
//
// For production the AuditStore is backed by the NDJSON audit log on disk.
type DevAuditStore struct {
	mu      sync.Mutex
	records map[string]*CredentialRecord // keyed by ProviderTokenHash
}

// NewDevAuditStore returns an empty DevAuditStore.
func NewDevAuditStore() *DevAuditStore {
	return &DevAuditStore{
		records: make(map[string]*CredentialRecord),
	}
}

// Register adds a CredentialRecord to the store (or replaces any existing
// record for the same ProviderTokenHash). Allows test scripts and the T6 demo
// to pre-seed records before injecting webhook payloads.
func (s *DevAuditStore) Register(r CredentialRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := r
	s.records[r.ProviderTokenHash] = &cp
}

// FindByTokenHash implements AuditStore.
func (s *DevAuditStore) FindByTokenHash(_ context.Context, hash string) (*CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[hash]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	// Return a copy so callers cannot mutate the stored record by accident.
	cp := *r
	return &cp, nil
}

// UpdateInvalidatedAt implements AuditStore.
func (s *DevAuditStore) UpdateInvalidatedAt(_ context.Context, credentialUUID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.CredentialUUID == credentialUUID {
			r.InvalidatedAt = at
			return nil
		}
	}
	// Credential not found — treat as a no-op (idempotent).
	return nil
}
