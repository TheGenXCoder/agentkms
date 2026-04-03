package policy

// vault_loader.go — P-05: Load policy from OpenBao/Vault KV v2.
//
// VaultPolicyLoader fetches a Policy YAML document from a Vault KV v2 path
// and wraps it in an Engine.  It supports hot-reload: a background goroutine
// polls the KV path at a configurable interval and atomically swaps in the
// new Policy if the content changes.
//
// Fall-through behaviour:
//   - If the KV path returns 404, the loader falls back to the local file
//     path (VaultPolicyConfig.LocalFallbackPath).  This allows a local YAML
//     file to serve as a safe default when the KV store is not yet populated.
//   - If both KV and local file are unavailable, Load() returns an error.
//
// SECURITY INVARIANTS:
//
//  1. A policy that fails Validate() is NEVER loaded into the engine.
//     If the KV document is malformed or invalid, the engine retains the
//     last valid policy (or the local fallback).
//
//  2. The Vault token is held in memory only; it is never written to disk or
//     included in any log output.
//
//  3. Deny-by-default is preserved at all times: if the engine has never
//     successfully loaded a policy, DenyAllEngine behaviour applies.
//
// P-05.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultPolicyConfig holds configuration for VaultPolicyLoader.
type VaultPolicyConfig struct {
	// Address is the Vault/OpenBao base URL.
	Address string

	// Token is the Vault token with read access to the KV path.
	// SECURITY: never log this value.
	Token string `json:"-"`

	// TLSConfig is the TLS configuration for the Vault client, including
	// client certificates for mTLS.
	// Required in production.
	TLSConfig *tls.Config

	// KVMount is the KV v2 secrets engine mount path (default "kv").
	KVMount string

	// PolicyPath is the key within the KV mount where the policy YAML lives.
	// Example: "policy/production" → kv/data/policy/production
	PolicyPath string

	// LocalFallbackPath is the local file path to use when the KV path
	// returns 404.  If empty, no fallback is attempted.
	LocalFallbackPath string

	// ReloadInterval is how often the loader polls for policy changes.
	// Zero disables background reload.
	ReloadInterval time.Duration
}

// VaultPolicyLoader loads a Policy from Vault KV and wraps it in a live Engine.
// Use AsEngineI() on the returned engine to satisfy the api.Server interface.
type VaultPolicyLoader struct {
	cfg    VaultPolicyConfig
	client *http.Client
	mu     sync.RWMutex
	engine *Engine

	// lastReload tracks the time of the last successful policy load.
	// Used by Healthy() to detect staleness.
	lastReload time.Time

	// consecutiveFailures tracks reload failures since last success.
	consecutiveFailures int
}

// NewVaultPolicyLoader constructs a VaultPolicyLoader.
// It does NOT fetch the policy at construction time; call Load() explicitly.
func NewVaultPolicyLoader(cfg VaultPolicyConfig) *VaultPolicyLoader {
	if cfg.KVMount == "" {
		cfg.KVMount = "kv"
	}
	// Warn if Token will be sent over plaintext HTTP to a non-loopback host.
	addr := strings.ToLower(cfg.Address)
	if strings.HasPrefix(addr, "http://") &&
		!strings.Contains(addr, "127.0.0.1") &&
		!strings.Contains(addr, "localhost") {
		fmt.Fprintf(os.Stderr,
			"agentkms: WARNING: VaultPolicyLoader Address uses http:// for a non-loopback host;\n"+
			"  Vault tokens will be sent in plaintext.\n"+
			"  Use https:// in production.\n")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg.TLSConfig

	return &VaultPolicyLoader{
		cfg:    cfg,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

// Load fetches the policy from Vault KV (with local fallback) and stores it
// in the internal Engine.  Must be called before Engine().
//
// If reload interval is configured, Load also starts a background goroutine
// that re-fetches the policy at the configured interval.  The goroutine runs
// until ctx is cancelled.
func (v *VaultPolicyLoader) Load(ctx context.Context) error {
	if err := v.reload(ctx); err != nil {
		return err
	}
	if v.cfg.ReloadInterval > 0 {
		go v.reloadLoop(ctx, v.cfg.ReloadInterval)
	}
	return nil
}

// Engine returns the current live Engine.
// Panics if Load() has not been called successfully.
func (v *VaultPolicyLoader) Engine() *Engine {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.engine == nil {
		panic("policy: VaultPolicyLoader.Engine() called before Load()")
	}
	return v.engine
}

// EngineI returns the current live Engine as an EngineI interface.
func (v *VaultPolicyLoader) EngineI() EngineI {
	return AsEngineI(v.Engine())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// reload fetches the policy from KV (or fallback) and atomically replaces
// the internal Engine.  Returns nil on success.
func (v *VaultPolicyLoader) reload(ctx context.Context) error {
	p, err := v.fetchPolicy(ctx)
	if err != nil {
		v.mu.Lock()
		v.consecutiveFailures++
		v.mu.Unlock()
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.engine = New(*p)
	v.lastReload = time.Now()
	v.consecutiveFailures = 0
	return nil
}

// Healthy reports whether the policy loader is operating normally.
// Returns false if the policy is staler than 2× ReloadInterval
// or if there have been 3+ consecutive reload failures.
func (v *VaultPolicyLoader) Healthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.consecutiveFailures >= 3 {
		return false
	}
	if v.cfg.ReloadInterval > 0 && !v.lastReload.IsZero() {
		staleThreshold := v.cfg.ReloadInterval * 2
		if time.Since(v.lastReload) > staleThreshold {
			return false
		}
	}
	return true
}

// LastReload returns the time of the last successful policy load.
func (v *VaultPolicyLoader) LastReload() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastReload
}

// fetchPolicy fetches and validates the policy, trying KV first then fallback.
func (v *VaultPolicyLoader) fetchPolicy(ctx context.Context) (*Policy, error) {
	// Try KV first.
	p, err := v.fetchFromKV(ctx)
	if err == nil {
		return p, nil
	}

	// If 404 and fallback is configured, use the local file.
	if errors.Is(err, errKVNotFound) && v.cfg.LocalFallbackPath != "" {
		p, ferr := LoadFromFile(v.cfg.LocalFallbackPath)
		if ferr == nil {
			return p, nil
		}
		return nil, fmt.Errorf("policy: KV not found AND local fallback failed: KV=%w; local=%v", err, ferr)
	}

	return nil, err
}

// fetchFromKV fetches and parses the policy YAML from Vault KV v2.
// Returns errNotFound (wrapped) when the key does not exist.
func (v *VaultPolicyLoader) fetchFromKV(ctx context.Context) (*Policy, error) {
	// KV v2 data path: {mount}/data/{key}
	path := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(v.cfg.Address, "/"),
		strings.Trim(v.cfg.KVMount, "/"),
		strings.TrimLeft(v.cfg.PolicyPath, "/"),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.cfg.Token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1 MiB max policy
	if err != nil {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, errKVNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: KV returned HTTP %d", resp.StatusCode)
	}

	// KV v2 wraps the secret in {"data":{"data":{...},"metadata":{...}}}.
	var envelope struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: parse KV envelope: %w", err)
	}

	yamlDoc, ok := envelope.Data.Data["policy"]
	if !ok || yamlDoc == "" {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: KV secret missing 'policy' field")
	}

	p, err := LoadFromBytes([]byte(yamlDoc))
	if err != nil {
		return nil, fmt.Errorf("policy: VaultPolicyLoader: invalid policy from KV: %w", err)
	}
	return p, nil
}

// reloadLoop calls reload at the given interval until ctx is cancelled.
// Errors are swallowed (the engine retains the last valid policy).
func (v *VaultPolicyLoader) reloadLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = v.reload(ctx) // retain last valid policy on error
		}
	}
}

// errKVNotFound is a sentinel error for 404 KV responses.
// Use errors.Is(err, errKVNotFound) to test for this condition.
var errKVNotFound = errors.New("policy: KV path not found (404)")
