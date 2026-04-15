//go:build darwin

// Package credentials — macOS Keychain backend for dev KV store.
//
// Secrets are stored in the macOS Keychain (encrypted at rest by the OS,
// protected by login password / Touch ID). This is the correct storage
// mechanism for dev secrets on a Mac — not plaintext files.
//
// Keychain layout:
//
//	Service:  "agentkms-dev"
//	Account:  the KV path, e.g. "kv/data/generic/forge/telegram"
//	Password: JSON-encoded map[string]string of the secret fields
//
// CLI usage (how secrets get in):
//
//	agentkms-dev secrets set generic/forge/telegram token=<value>
//	agentkms-dev secrets set llm/anthropic api_key=<value>
//	agentkms-dev secrets list
//	agentkms-dev secrets delete generic/forge/telegram
//
// The dev server reads from Keychain on GetSecret — no plaintext file ever
// touches the filesystem.
package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

const keychainService = "agentkms-dev"

// KeychainKV implements KVReader using the macOS Keychain via the
// `security` command-line tool.
//
// Paths follow the same Vault KV v2 layout as DevKVStore:
//   - Generic:  "kv/data/generic/{path}"
//   - LLM keys: "kv/data/llm/{provider}"
//
// Concurrency: safe — each call shells out to `security`, which
// handles its own locking.
type KeychainKV struct{}

// NewKeychainKV returns a KeychainKV.
func NewKeychainKV() *KeychainKV {
	return &KeychainKV{}
}

// GetSecret retrieves a secret from the Keychain.
// Returns ErrCredentialNotFound if no entry exists for this path.
func (k *KeychainKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	// security find-generic-password -s <service> -a <account> -w
	// -w prints the password only (no other output)
	out, err := exec.Command(
		"security",
		"find-generic-password",
		"-s", keychainService,
		"-a", path,
		"-w",
	).Output()
	if err != nil {
		// exit code 44 = item not found
		return nil, fmt.Errorf("%w: path %q not found in Keychain (service=%q)",
			ErrCredentialNotFound, path, keychainService)
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, fmt.Errorf("%w: path %q returned empty value", ErrCredentialNotFound, path)
	}

	var fields map[string]string
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("credentials: keychain entry for %q is not valid JSON: %w", path, err)
	}
	return fields, nil
}

// ── CLI helpers (called by agentkms-dev secrets subcommand) ──────────────────

// KeychainSet stores key=value pairs at path in the Keychain.
// If an entry already exists for this path, it is updated.
func KeychainSet(path string, fields map[string]string) error {
	data, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("keychain: marshalling fields: %w", err)
	}

	// Try to update first; if that fails (item not found), add.
	updateCmd := exec.Command(
		"security",
		"add-generic-password",
		"-U", // update if exists
		"-s", keychainService,
		"-a", path,
		"-w", string(data),
	)
	if out, err := updateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain: setting %q: %w\n%s", path, err, string(out))
	}
	return nil
}

// KeychainDelete removes a secret from the Keychain.
func KeychainDelete(path string) error {
	cmd := exec.Command(
		"security",
		"delete-generic-password",
		"-s", keychainService,
		"-a", path,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain: deleting %q: %w\n%s", path, err, string(out))
	}
	return nil
}

// KeychainList returns all account names (KV paths) stored under the
// agentkms-dev service. Uses `security dump-keychain` filtered by service.
func KeychainList() ([]string, error) {
	// security find-generic-password can only find one item at a time.
	// Use dump-keychain and grep for our service.
	out, err := exec.Command(
		"security", "dump-keychain",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("keychain: listing items: %w", err)
	}

	var paths []string
	lines := strings.Split(string(out), "\n")
	inOurService := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect service name
		if strings.Contains(line, `"svce"`) {
			inOurService = strings.Contains(line, keychainService)
		}

		// Extract account name when we're in our service's block
		if inOurService && strings.Contains(line, `"acct"`) {
			// Format: "acct"<blob>="kv/data/generic/forge/telegram"
			if idx := strings.Index(line, `="`); idx >= 0 {
				account := line[idx+2:]
				account = strings.TrimSuffix(account, `"`)
				if account != "" {
					paths = append(paths, account)
				}
			}
		}
	}

	return paths, nil
}
