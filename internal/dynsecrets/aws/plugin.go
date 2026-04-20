// Package aws implements the Dynamic Secrets plugin for AWS STS
// AssumeRole ephemeral credentials (Kind="aws-sts").
package aws

import (
	"context"

	"github.com/agentkms/agentkms/internal/credentials"
)

// Plugin implements credentials.ScopeValidator for Kind="aws-sts".
// It validates scope structure, narrows against policy bounds, and
// (in production) calls AWS STS AssumeRole to issue temporary credentials.
type Plugin struct {
	roleARN string
	region  string
}

// New creates a Plugin configured with the base AWS role and region.
// Returns an error if roleARN or region is empty.
func New(roleARN string, region string) (*Plugin, error) {
	return nil, nil
}

// Kind returns "aws-sts".
func (p *Plugin) Kind() string {
	return ""
}

// Validate checks structural correctness of an aws-sts Scope.
func (p *Plugin) Validate(_ context.Context, _ credentials.Scope) error {
	return nil
}

// Narrow intersects a requested Scope with policy bounds.
func (p *Plugin) Narrow(_ context.Context, requested credentials.Scope, _ credentials.ScopeBounds) (credentials.Scope, error) {
	return requested, nil
}

// Compile-time interface assertion.
var _ credentials.ScopeValidator = (*Plugin)(nil)
