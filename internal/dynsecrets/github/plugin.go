// Package github implements the Dynamic Secrets plugin for GitHub App
// ephemeral installation access tokens (Kind="github-pat").
package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// Known permission keys for GitHub installation tokens.
var knownPermissions = map[string]bool{
	"contents":      true,
	"pull_requests": true,
	"issues":        true,
	"actions":       true,
	"metadata":      true,
}

// Plugin implements credentials.ScopeValidator and credentials.CredentialVender
// for Kind="github-pat".
//
// The plugin supports N GitHub Apps registered by name. Each vend request
// must include "app_name" in its Scope.Params to select the target App.
// Apps are registered at startup via RegisterApp; the registry is read-only
// after the first Vend call.
//
// //blog:part-5 references Kind="github-pat" in the "GitHub App tokens" section.
// //blog:part-7 references this plugin as the "dynsecrets-github" bundled plugin.
type Plugin struct {
	mu   sync.RWMutex
	apps map[string]*githubAppClient
}

// New creates a Plugin pre-configured with a single GitHub App.
// This preserves the existing single-App construction API for callers
// that have not yet migrated to RegisterApp.
//
// Returns an error if the private key is malformed or not RSA.
func New(appID int64, privateKey []byte, installationID int64) (*Plugin, error) {
	p := &Plugin{apps: make(map[string]*githubAppClient)}
	if err := p.RegisterApp("default", appID, installationID, privateKey); err != nil {
		return nil, err
	}
	return p, nil
}

// NewMulti creates an empty Plugin with no Apps registered.
// Use RegisterApp to add Apps before the first Vend call.
func NewMulti() *Plugin {
	return &Plugin{apps: make(map[string]*githubAppClient)}
}

// RegisterApp registers a GitHub App under the given name.
// name is the human-readable identifier used in Scope.Params["app_name"].
// privateKeyPEM must be a PEM-encoded RSA private key (PKCS1 or PKCS8).
//
// Returns an error if the key is malformed, not RSA, or if the name is empty.
// Not concurrency-safe during initialization; callers must complete all
// registrations before serving Vend requests.
func (p *Plugin) RegisterApp(name string, appID, installationID int64, privateKeyPEM []byte) error {
	if name == "" {
		return fmt.Errorf("github plugin: app name must not be empty")
	}

	rsaKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("github plugin: registering app %q: %w", name, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.apps[name] = newGitHubAppClient(appID, installationID, rsaKey)
	return nil
}

// Kind returns "github-pat".
func (p *Plugin) Kind() string {
	return "github-pat"
}

// Validate checks structural correctness of a github-pat Scope.
// Requires "repositories" (non-empty list), "permissions" (known keys with
// "read"/"write" values), and a TTL between 0 and 1 hour.
// If "app_name" is present in Params, it must match a registered App.
func (p *Plugin) Validate(_ context.Context, s credentials.Scope) error {
	// Check repositories.
	reposRaw, ok := s.Params["repositories"]
	if !ok {
		return fmt.Errorf("github plugin: missing required param \"repositories\"")
	}
	repos, ok := reposRaw.([]any)
	if !ok || len(repos) == 0 {
		return fmt.Errorf("github plugin: \"repositories\" must be a non-empty list")
	}

	// Check permissions.
	permsRaw, ok := s.Params["permissions"]
	if !ok {
		return fmt.Errorf("github plugin: missing required param \"permissions\"")
	}
	perms, ok := permsRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("github plugin: \"permissions\" must be a map")
	}
	for key, val := range perms {
		if !knownPermissions[key] {
			return fmt.Errorf("github plugin: unknown permission key %q", key)
		}
		v, ok := val.(string)
		if !ok || (v != "read" && v != "write") {
			return fmt.Errorf("github plugin: permission %q must be \"read\" or \"write\"", key)
		}
	}

	// Check TTL.
	if s.TTL <= 0 {
		return fmt.Errorf("github plugin: TTL must be > 0")
	}
	if s.TTL > 1*time.Hour {
		return fmt.Errorf("github plugin: TTL must not exceed 1 hour (got %v)", s.TTL)
	}

	// If app_name is specified, validate it exists.
	if appNameRaw, ok := s.Params["app_name"]; ok {
		appName, ok := appNameRaw.(string)
		if !ok || appName == "" {
			return fmt.Errorf("github plugin: \"app_name\" must be a non-empty string")
		}
		if _, err := p.lookupApp(appName); err != nil {
			return err
		}
	}

	return nil
}

// Narrow intersects a requested Scope with policy bounds.
func (p *Plugin) Narrow(_ context.Context, requested credentials.Scope, bounds credentials.ScopeBounds) (credentials.Scope, error) {
	result := credentials.Scope{
		Kind:   requested.Kind,
		Params: make(map[string]any),
		TTL:    requested.TTL,
	}

	// TTL capping.
	if bounds.MaxTTL > 0 && result.TTL > bounds.MaxTTL {
		result.TTL = bounds.MaxTTL
	}

	// Repository intersection.
	if boundsReposRaw, ok := bounds.MaxParams["repositories"]; ok {
		boundsRepos := toStringSet(boundsReposRaw)
		requestedRepos := toStringSet(requested.Params["repositories"])

		var intersection []any
		for r := range requestedRepos {
			if boundsRepos[r] {
				intersection = append(intersection, r)
			}
		}
		if len(intersection) == 0 {
			return credentials.Scope{}, fmt.Errorf("github plugin: no repository overlap between request and bounds")
		}
		result.Params["repositories"] = intersection
	} else {
		result.Params["repositories"] = requested.Params["repositories"]
	}

	// Permission intersection.
	if boundsPermsRaw, ok := bounds.MaxParams["permissions"]; ok {
		boundsPerms, _ := boundsPermsRaw.(map[string]any)
		requestedPerms, _ := requested.Params["permissions"].(map[string]any)

		narrowedPerms := make(map[string]any)
		for key, val := range requestedPerms {
			if _, allowed := boundsPerms[key]; allowed {
				narrowedPerms[key] = val
			}
		}
		if len(narrowedPerms) == 0 {
			// Keep what was requested (don't error on permissions).
			result.Params["permissions"] = requested.Params["permissions"]
		} else {
			result.Params["permissions"] = narrowedPerms
		}
	} else {
		result.Params["permissions"] = requested.Params["permissions"]
	}

	// Propagate app_name if present.
	if appNameRaw, ok := requested.Params["app_name"]; ok {
		result.Params["app_name"] = appNameRaw
	}

	// Set timestamps.
	result.IssuedAt = time.Now().UTC()
	result.ExpiresAt = result.IssuedAt.Add(result.TTL)

	return result, nil
}

// Vend mints a GitHub installation access token for the App named in
// s.Params["app_name"]. If "app_name" is absent, the "default" App is used
// (for single-App callers that constructed with New).
//
// Returns a credentials.VendedCredential with the token in APIKey.
// The caller must call Zero() on the returned credential after use.
func (p *Plugin) Vend(ctx context.Context, s credentials.Scope) (*credentials.VendedCredential, error) {
	appName := "default"
	if raw, ok := s.Params["app_name"]; ok {
		if name, ok := raw.(string); ok && name != "" {
			appName = name
		}
	}

	client, err := p.lookupApp(appName)
	if err != nil {
		return nil, err
	}

	token, err := client.MintToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("github plugin: vend for app %q: %w", appName, err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.TTL)
	if s.TTL <= 0 || s.TTL > time.Hour {
		expiresAt = now.Add(time.Hour)
	}

	return &credentials.VendedCredential{
		Provider:  "github",
		Type:      "github-pat",
		APIKey:    []byte(token),
		ExpiresAt: expiresAt,
		TTLSeconds: int(time.Until(expiresAt).Seconds()),
	}, nil
}

// Suspend suspends the installation for the named App.
// Calls PUT /app/installations/{installation_id}/suspended.
func (p *Plugin) Suspend(ctx context.Context, appName string) error {
	client, err := p.lookupApp(appName)
	if err != nil {
		return err
	}
	return client.Suspend(ctx)
}

// Unsuspend unsuspends the installation for the named App.
// Calls DELETE /app/installations/{installation_id}/suspended.
func (p *Plugin) Unsuspend(ctx context.Context, appName string) error {
	client, err := p.lookupApp(appName)
	if err != nil {
		return err
	}
	return client.Unsuspend(ctx)
}

// ListApps returns a snapshot of all registered Apps.
func (p *Plugin) ListApps() []AppInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]AppInfo, 0, len(p.apps))
	for name, c := range p.apps {
		out = append(out, AppInfo{
			Name:           name,
			AppID:          c.appID,
			InstallationID: c.installationID,
		})
	}
	return out
}

// ── internal helpers ─────────────────────────────────────────────────────────

// lookupApp returns the client for the named App, or a permanent error.
func (p *Plugin) lookupApp(name string) (*githubAppClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	c, ok := p.apps[name]
	if !ok {
		return nil, fmt.Errorf("github plugin: [permanent] unknown app %q; registered apps: %v", name, p.appNames())
	}
	return c, nil
}

// appNames returns the sorted list of registered App names for diagnostics.
// Must be called with mu held (at least RLock).
func (p *Plugin) appNames() []string {
	names := make([]string, 0, len(p.apps))
	for n := range p.apps {
		names = append(names, n)
	}
	return names
}

// parseRSAPrivateKey decodes a PEM block and parses an RSA private key,
// supporting both PKCS1 and PKCS8 formats.
func parseRSAPrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	// Try PKCS1 first, then PKCS8.
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("private key is not a valid RSA key: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

// toStringSet converts a []any of strings to a map for set operations.
func toStringSet(v any) map[string]bool {
	s, ok := v.([]any)
	if !ok {
		return nil
	}
	m := make(map[string]bool, len(s))
	for _, item := range s {
		if str, ok := item.(string); ok {
			m[str] = true
		}
	}
	return m
}

// Compile-time interface assertions.
var _ credentials.ScopeValidator = (*Plugin)(nil)
var _ credentials.CredentialVender = (*Plugin)(nil)
