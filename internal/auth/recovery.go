// Package auth — recovery.go
//
// Recovery provides three mechanisms to regain access when a device is
// lost or a passphrase is forgotten:
//
//  1. Recovery Codes (Layer 1 — device loss, most common case)
//     At enrollment time, GenerateRecoveryCodes produces N one-time-use
//     codes (default 8, each 128 bits of entropy).  The codes are returned
//     ONCE in plaintext — the caller prints/stores them.  The server stores
//     only their Argon2id hashes.  Each code can be redeemed exactly once via
//     RedeemRecoveryCode, which returns a short-lived bootstrap token for
//     re-enrollment.
//
//  2. Admin Re-enrollment (Layer 2 — all codes lost)
//     An admin identity (held on a separate device with a separate cert) can
//     call IssuePlatformRecoveryToken for any registered CallerID.  This
//     returns a bootstrap token that lets the user enroll a replacement device
//     under the same identity.
//
//  3. Server Disaster Recovery (Layer 3 — server loss)
//     See internal/backup/backup.go for encrypted KV snapshots.
//     OpenBao Shamir unseal key management is documented in
//     docs/security-runbook.md.
//
// SECURITY INVARIANTS:
//   - Recovery codes are high-entropy (128 bits), single-use, and server-side
//     hashed with Argon2id.  Replay attacks are impossible.
//   - Bootstrap tokens issued by recovery are short-lived (15 minutes) and
//     single-use.
//   - Every recovery event is audited with the caller identity, outcome,
//     and the code index (not the code itself).

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// RecoveryCodeCount is the number of recovery codes generated at enrollment.
	RecoveryCodeCount = 8

	// recoveryCodeBytes is the raw entropy per code (128 bits).
	recoveryCodeBytes = 16

	// recoveryArgon2Time, Memory, Threads — lighter than key derivation because
	// recovery codes already have 128-bit entropy.  The hash is a rate-limit
	// on brute-force, not the sole security control.
	recoveryArgon2Time    = 1
	recoveryArgon2Memory  = 32 * 1024 // 32 MiB
	recoveryArgon2Threads = 2
	recoveryArgon2KeyLen  = 32

	// RecoveryTokenTTL is how long a recovery bootstrap token is valid.
	RecoveryTokenTTL = 15 * time.Minute
)

// RecoveryCode is a single-use code returned to the user at enrollment.
// The plaintext is shown ONCE — it is never stored server-side.
type RecoveryCode struct {
	// Index is the code number (0–7).  Used to identify which code was redeemed
	// in audit logs without revealing the code itself.
	Index int `json:"index"`

	// Plaintext is the human-readable code (base32, no padding, grouped in 4s).
	// SECURITY: show to the user once and discard from memory.
	Plaintext string `json:"-"`
}

// recoveryCodeRecord is the server-side representation of a recovery code.
type recoveryCodeRecord struct {
	Index  int    `json:"index"`
	Hash   []byte `json:"hash"`
	Salt   []byte `json:"salt"`
	Used   bool   `json:"used"`
	UsedAt string `json:"used_at,omitempty"`
}

// RecoveryStore persists recovery code hashes for enrolled identities.
// In production this would be backed by OpenBao KV; for T3 local it uses
// a JSON file in the AgentKMS data directory.
type RecoveryStore struct {
	mu      sync.RWMutex
	dataDir string
	// callerID → []recoveryCodeRecord
	records map[string][]recoveryCodeRecord
}

// NewRecoveryStore creates a RecoveryStore backed by dataDir.
func NewRecoveryStore(dataDir string) (*RecoveryStore, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("recovery: create data dir: %w", err)
	}
	rs := &RecoveryStore{
		dataDir: dataDir,
		records: make(map[string][]recoveryCodeRecord),
	}
	if err := rs.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("recovery: load: %w", err)
	}
	return rs, nil
}

// GenerateRecoveryCodes generates RecoveryCodeCount one-time-use codes for
// the given callerID, persists their hashes, and returns the plaintext codes.
//
// The plaintext codes MUST be shown to the user and then discarded from memory.
// They are never stored server-side.
func (rs *RecoveryStore) GenerateRecoveryCodes(callerID string) ([]RecoveryCode, error) {
	codes := make([]RecoveryCode, RecoveryCodeCount)
	records := make([]recoveryCodeRecord, RecoveryCodeCount)

	for i := 0; i < RecoveryCodeCount; i++ {
		// 128 bits of entropy.
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("recovery: generate code %d: %w", i, err)
		}

		// Format as base32 (no padding) grouped in 4-character chunks.
		b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		plain := groupCode(b32)

		// Hash with Argon2id.
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("recovery: generate salt %d: %w", i, err)
		}
		hash := argon2.IDKey(raw, salt, recoveryArgon2Time, recoveryArgon2Memory, recoveryArgon2Threads, recoveryArgon2KeyLen)

		codes[i] = RecoveryCode{Index: i, Plaintext: plain}
		records[i] = recoveryCodeRecord{Index: i, Hash: hash, Salt: salt}
	}

	rs.mu.Lock()
	rs.records[callerID] = records
	rs.mu.Unlock()

	if err := rs.persist(); err != nil {
		return nil, fmt.Errorf("recovery: persist: %w", err)
	}
	return codes, nil
}

// RedeemRecoveryCode validates a plaintext recovery code for the given callerID.
// Returns nil on success and marks the code as used.
// Returns an error if the code is invalid, already used, or not found.
//
// SECURITY: Uses constant-time comparison to prevent timing oracles.
// Redeemed codes are marked used immediately — replay attacks are impossible
// even if the attacker intercepts the response.
func (rs *RecoveryStore) RedeemRecoveryCode(callerID, plaintext string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	records, ok := rs.records[callerID]
	if !ok || len(records) == 0 {
		return fmt.Errorf("recovery: no recovery codes registered for identity")
	}

	// Normalise input — strip spaces and dashes.
	clean := normaliseCode(plaintext)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return fmt.Errorf("recovery: invalid code format")
	}

	for i, rec := range records {
		if rec.Used {
			continue
		}
		candidate := argon2.IDKey(raw, rec.Salt, recoveryArgon2Time, recoveryArgon2Memory, recoveryArgon2Threads, recoveryArgon2KeyLen)
		if subtle.ConstantTimeCompare(candidate, rec.Hash) == 1 {
			// Valid — mark used.
			records[i].Used = true
			records[i].UsedAt = time.Now().UTC().Format(time.RFC3339)
			rs.records[callerID] = records
			return rs.persist()
		}
	}

	return fmt.Errorf("recovery: code not valid or already used")
}

// RemainingCodes returns the number of unused recovery codes for a callerID.
func (rs *RecoveryStore) RemainingCodes(callerID string) int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	records := rs.records[callerID]
	n := 0
	for _, r := range records {
		if !r.Used {
			n++
		}
	}
	return n
}

// RevokeAllCodes invalidates all recovery codes for a callerID.
// Called when a full re-enrollment is issued (the new set replaces the old).
func (rs *RecoveryStore) RevokeAllCodes(callerID string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.records, callerID)
	return rs.persist()
}

// ── Persistence ───────────────────────────────────────────────────────────────

func (rs *RecoveryStore) path() string {
	return filepath.Join(rs.dataDir, "recovery-codes.json")
}

func (rs *RecoveryStore) persist() error {
	data, err := json.MarshalIndent(rs.records, "", "  ")
	if err != nil {
		return err
	}
	tmp := rs.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, rs.path())
}

func (rs *RecoveryStore) load() error {
	data, err := os.ReadFile(rs.path())
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &rs.records)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// groupCode formats a base32 string into 4-character groups separated by dashes
// for human readability:  ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567
func groupCode(s string) string {
	out := make([]byte, 0, len(s)+len(s)/4)
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// normaliseCode strips dashes and spaces and uppercases the input.
func normaliseCode(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if c == '-' || c == ' ' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, byte(c))
	}
	return string(out)
}
