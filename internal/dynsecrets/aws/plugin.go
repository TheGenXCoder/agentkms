// Package aws implements the Dynamic Secrets plugin for AWS STS
// AssumeRole ephemeral credentials (Kind="aws-sts").
package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

var (
	roleARNRegex    = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.+$`)
	sessionNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_=,.@-]+$`)
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
	if roleARN == "" {
		return nil, errors.New("aws: roleARN must not be empty")
	}
	if region == "" {
		return nil, errors.New("aws: region must not be empty")
	}
	return &Plugin{roleARN: roleARN, region: region}, nil
}

// Kind returns "aws-sts".
func (p *Plugin) Kind() string {
	return "aws-sts"
}

// Validate checks structural correctness of an aws-sts Scope.
func (p *Plugin) Validate(_ context.Context, s credentials.Scope) error {
	// Validate role_arn
	roleARNVal, ok := s.Params["role_arn"]
	if !ok {
		return errors.New("aws: missing required param role_arn")
	}
	roleARNStr, ok := roleARNVal.(string)
	if !ok {
		return errors.New("aws: role_arn must be a string")
	}
	if !roleARNRegex.MatchString(roleARNStr) {
		return fmt.Errorf("aws: role_arn %q does not match expected ARN format", roleARNStr)
	}

	// Validate session_name
	sessionVal, ok := s.Params["session_name"]
	if !ok {
		return errors.New("aws: missing required param session_name")
	}
	sessionStr, ok := sessionVal.(string)
	if !ok {
		return errors.New("aws: session_name must be a string")
	}
	if len(sessionStr) < 2 || len(sessionStr) > 64 {
		return fmt.Errorf("aws: session_name must be 2-64 characters, got %d", len(sessionStr))
	}
	if !sessionNameRegex.MatchString(sessionStr) {
		return fmt.Errorf("aws: session_name %q contains invalid characters", sessionStr)
	}

	// Validate TTL
	if s.TTL < 15*time.Minute {
		return fmt.Errorf("aws: TTL %v is below minimum 15m", s.TTL)
	}
	if s.TTL > 12*time.Hour {
		return fmt.Errorf("aws: TTL %v exceeds maximum 12h", s.TTL)
	}

	// Validate optional params
	if extID, exists := s.Params["external_id"]; exists {
		if _, ok := extID.(string); !ok {
			return errors.New("aws: external_id must be a string")
		}
	}
	if policy, exists := s.Params["policy"]; exists {
		if _, ok := policy.(string); !ok {
			return errors.New("aws: policy must be a string")
		}
	}

	return nil
}

// Narrow intersects a requested Scope with policy bounds.
func (p *Plugin) Narrow(_ context.Context, requested credentials.Scope, bounds credentials.ScopeBounds) (credentials.Scope, error) {
	narrowed := requested

	// Cap TTL
	if bounds.MaxTTL > 0 && narrowed.TTL > bounds.MaxTTL {
		narrowed.TTL = bounds.MaxTTL
	}

	// Check role_arn constraint
	if bounds.MaxParams != nil {
		if boundRole, ok := bounds.MaxParams["role_arn"]; ok {
			boundRoleStr, _ := boundRole.(string)
			requestedRole, _ := narrowed.Params["role_arn"].(string)
			if requestedRole != boundRoleStr {
				return credentials.Scope{}, fmt.Errorf("aws: requested role_arn %q does not match bound %q", requestedRole, boundRoleStr)
			}
		}
	}

	// Set timestamps
	now := time.Now().UTC()
	narrowed.IssuedAt = now
	narrowed.ExpiresAt = now.Add(narrowed.TTL)

	return narrowed, nil
}

// Compile-time interface assertion.
var _ credentials.ScopeValidator = (*Plugin)(nil)
