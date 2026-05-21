package auth

// bootstrap_store.go — Operator bootstrap token store.
//
// Operator bootstrap tokens are opaque single-use tokens that an operator
// creates ahead of time and hands to an end-user/device so they can call
// POST /auth/cert/issue without an existing session token.
//
// Storage: Vault KV v2 at kv/data/bootstrap-tokens/<sha256-hex-of-token>.
// Each record carries the authorised user_id, a device_name pattern
// (currently exact-match only), an expiry, and a used flag.
//
// SECURITY INVARIANTS:
//  1. The raw token is never stored — only its SHA-256 hex digest is.
//  2. Redemption is atomic (best-effort): the record is marked used=true
//     before the cert is signed, so a concurrent redemption sees used=true
//     and returns 401.  (True atomicity requires Vault transactions; this
//     implementation has a TOCTOU window of O(1 Vault round-trip), which is
//     acceptable for Tier 0.)
//  3. The store is injected as an interface so tests can mock it without
//     talking to a real Vault instance.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BootstrapRecord is the value stored in Vault KV for a bootstrap token.
type BootstrapRecord struct {
	// UserID is the user the bootstrap token is issued for.
	UserID string `json:"user_id"`

	// DeviceNamePattern is the device name the enrolling device must claim.
	// Currently exact-match; future: glob/regex.
	DeviceNamePattern string `json:"device_name_pattern"`

	// ExpiresAt is when this token expires (UTC).
	ExpiresAt time.Time `json:"expires_at"`

	// Used is flipped to true after the first successful redemption.
	Used bool `json:"used"`
}

// BootstrapStore persists and redeems operator bootstrap tokens.
type BootstrapStore interface {
	// Create generates a new opaque bootstrap token, writes its record to the
	// backing store keyed by sha256(rawToken), and returns the raw token (64-char
	// hex).  The raw token is the only thing the caller needs; it is never
	// logged or persisted — only its hash is stored.
	Create(ctx context.Context, record BootstrapRecord) (rawToken string, err error)

	// Fetch retrieves the record for rawToken.  Returns nil, nil if not found.
	Fetch(ctx context.Context, rawToken string) (*BootstrapRecord, error)

	// MarkUsed atomically marks the token as used.
	MarkUsed(ctx context.Context, rawToken string) error
}

// vaultBootstrapStore implements BootstrapStore backed by Vault KV v2.
type vaultBootstrapStore struct {
	address string
	token   string
	mount   string // KV mount, e.g. "kv"
	client  *http.Client
}

// NewVaultBootstrapStore creates a BootstrapStore backed by Vault KV v2.
// mount is the KV engine mount path (typically "kv").
func NewVaultBootstrapStore(address, vaultToken string, mount string) BootstrapStore {
	if mount == "" {
		mount = "kv"
	}
	return &vaultBootstrapStore{
		address: strings.TrimRight(address, "/"),
		token:   vaultToken,
		mount:   mount,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *vaultBootstrapStore) kvPath(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	keyHash := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s/v1/%s/data/bootstrap-tokens/%s",
		s.address, s.mount, keyHash)
}

func (s *vaultBootstrapStore) Create(ctx context.Context, record BootstrapRecord) (string, error) {
	// Generate 32 random bytes → 64-char hex raw token.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("bootstrap_store: Create: generate random token: %w", err)
	}
	rawToken := hex.EncodeToString(raw[:])

	// Ensure the record is stored as unused.
	record.Used = false

	payload := map[string]any{"data": record}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bootstrap_store: Create marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.kvPath(rawToken), bytes.NewReader(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("bootstrap_store: Create build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("bootstrap_store: Create HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("bootstrap_store: Create HTTP %d", resp.StatusCode)
	}

	// Never log rawToken.
	return rawToken, nil
}

func (s *vaultBootstrapStore) Fetch(ctx context.Context, rawToken string) (*BootstrapRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.kvPath(rawToken), nil)
	if err != nil {
		return nil, fmt.Errorf("bootstrap_store: build fetch request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bootstrap_store: fetch HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap_store: fetch HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("bootstrap_store: read fetch response: %w", err)
	}

	var envelope struct {
		Data struct {
			Data BootstrapRecord `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("bootstrap_store: parse fetch response: %w", err)
	}
	return &envelope.Data.Data, nil
}

func (s *vaultBootstrapStore) MarkUsed(ctx context.Context, rawToken string) error {
	// Read-modify-write.  TOCTOU is acceptable for Tier 0 (see package comment).
	existing, err := s.Fetch(ctx, rawToken)
	if err != nil {
		return fmt.Errorf("bootstrap_store: MarkUsed fetch: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("bootstrap_store: MarkUsed: token not found")
	}
	existing.Used = true

	payload := map[string]any{"data": existing}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("bootstrap_store: MarkUsed marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.kvPath(rawToken), bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("bootstrap_store: MarkUsed build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap_store: MarkUsed HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("bootstrap_store: MarkUsed HTTP %d", resp.StatusCode)
	}
	return nil
}
