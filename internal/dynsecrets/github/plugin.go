// Package github implements the Dynamic Secrets plugin for GitHub App
// ephemeral installation access tokens (Kind="github-pat").
package github

import (
	"context"

	"github.com/agentkms/agentkms/internal/credentials"
)

// Plugin implements credentials.ScopeValidator for Kind="github-pat".
// It validates scope structure, narrows against policy bounds, and
// (in production) vends ephemeral GitHub installation access tokens.
type Plugin struct {
	appID          int64
	privateKey     []byte
	installationID int64
}

// New creates a Plugin configured with GitHub App credentials.
// Returns an error if the private key is malformed.
func New(appID int64, privateKey []byte, installationID int64) (*Plugin, error) {
	return nil, nil
}

// Kind returns "github-pat".
func (p *Plugin) Kind() string {
	return ""
}

// Validate checks structural correctness of a github-pat Scope.
func (p *Plugin) Validate(_ context.Context, _ credentials.Scope) error {
	return nil
}

// Narrow intersects a requested Scope with policy bounds.
func (p *Plugin) Narrow(_ context.Context, requested credentials.Scope, _ credentials.ScopeBounds) (credentials.Scope, error) {
	return requested, nil
}

// Compile-time interface assertion.
var _ credentials.ScopeValidator = (*Plugin)(nil)
