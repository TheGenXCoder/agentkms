// Package github implements the Dynamic Secrets plugin for GitHub App
// ephemeral installation access tokens (Kind="github-pat").
package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

// Plugin implements credentials.ScopeValidator for Kind="github-pat".
// It validates scope structure, narrows against policy bounds, and
// (in production) vends ephemeral GitHub installation access tokens.
type Plugin struct {
	appID          int64
	privateKey     *rsa.PrivateKey
	installationID int64
}

// New creates a Plugin configured with GitHub App credentials.
// Returns an error if the private key is malformed or not RSA.
func New(appID int64, privateKey []byte, installationID int64) (*Plugin, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, fmt.Errorf("github plugin: failed to decode PEM block from private key")
	}

	// Try PKCS1 first, then PKCS8.
	var rsaKey *rsa.PrivateKey

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		rsaKey = key
	} else {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("github plugin: private key is not a valid RSA key: %v", err)
		}
		var ok bool
		rsaKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("github plugin: private key is not RSA")
		}
	}

	return &Plugin{
		appID:          appID,
		privateKey:     rsaKey,
		installationID: installationID,
	}, nil
}

// Kind returns "github-pat".
func (p *Plugin) Kind() string {
	return "github-pat"
}

// Validate checks structural correctness of a github-pat Scope.
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

	// Set timestamps.
	result.IssuedAt = time.Now().UTC()
	result.ExpiresAt = result.IssuedAt.Add(result.TTL)

	return result, nil
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

// Compile-time interface assertion.
var _ credentials.ScopeValidator = (*Plugin)(nil)
