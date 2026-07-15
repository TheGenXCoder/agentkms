// Package aws is the reference Dynamic Secrets **provider** for AWS STS
// AssumeRole (Kind="aws-sts").
//
// This package lives under plugins/ (not internal/) so it is the template for
// out-of-tree providers: implement ScopeValidator + CredentialVender, ship a
// go-plugin binary, register with the AgentKMS host.
//
// Build the host-loadable binary:
//
//	go build -o agentkms-plugin-aws ./cmd/agentkms-plugin-aws
//
// //blog:part-5 references Kind="aws-sts".
// //blog:part-7 references "dynsecrets-aws" as a bundled provider plugin.
package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

var (
	roleARNRegex     = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.+$`)
	sessionNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_=,.@-]+$`)
)

// STSClient issues temporary credentials (AssumeRole). Injected for tests and
// for builds that wire a real AWS SDK client without pulling AWS into core.
type STSClient interface {
	AssumeRole(ctx context.Context, roleARN, sessionName, externalID, region string, ttl time.Duration) (token []byte, expiresAt time.Time, err error)
}

// Plugin implements credentials.ScopeValidator and credentials.CredentialVender
// for Kind="aws-sts".
type Plugin struct {
	roleARN string
	region  string
	// STS is optional. When nil, Vend returns a clear configuration error
	// after Validate succeeds — the provider binary is still registerable.
	STS STSClient
}

// New creates a Plugin configured with the base AWS role and region.
func New(roleARN string, region string) (*Plugin, error) {
	if roleARN == "" {
		return nil, errors.New("aws: roleARN must not be empty")
	}
	if region == "" {
		return nil, errors.New("aws: region must not be empty")
	}
	return &Plugin{roleARN: roleARN, region: region}, nil
}

// WithSTS returns a shallow copy that uses client for Vend.
func (p *Plugin) WithSTS(client STSClient) *Plugin {
	cp := *p
	cp.STS = client
	return &cp
}

// Kind returns "aws-sts".
func (p *Plugin) Kind() string {
	return "aws-sts"
}

// Validate checks structural correctness of an aws-sts Scope.
func (p *Plugin) Validate(_ context.Context, s credentials.Scope) error {
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

	if s.TTL < 15*time.Minute {
		return fmt.Errorf("aws: TTL %v is below minimum 15m", s.TTL)
	}
	if s.TTL > 12*time.Hour {
		return fmt.Errorf("aws: TTL %v exceeds maximum 12h", s.TTL)
	}

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

	if bounds.MaxTTL > 0 && narrowed.TTL > bounds.MaxTTL {
		narrowed.TTL = bounds.MaxTTL
	}

	if bounds.MaxParams != nil {
		if boundRole, ok := bounds.MaxParams["role_arn"]; ok {
			boundRoleStr, _ := boundRole.(string)
			requestedRole, _ := narrowed.Params["role_arn"].(string)
			if requestedRole != boundRoleStr {
				return credentials.Scope{}, fmt.Errorf("aws: requested role_arn %q does not match bound %q", requestedRole, boundRoleStr)
			}
		}
	}

	now := time.Now().UTC()
	narrowed.IssuedAt = now
	narrowed.ExpiresAt = now.Add(narrowed.TTL)

	return narrowed, nil
}

// Vend issues short-lived AWS STS credentials for the validated scope.
func (p *Plugin) Vend(ctx context.Context, s credentials.Scope) (*credentials.VendedCredential, error) {
	if err := p.Validate(ctx, s); err != nil {
		return nil, err
	}
	roleARN, _ := s.Params["role_arn"].(string)
	sessionName, _ := s.Params["session_name"].(string)
	externalID, _ := s.Params["external_id"].(string)
	region := p.region
	if r, ok := s.Params["region"].(string); ok && r != "" {
		region = r
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}

	if p.STS == nil {
		return nil, errors.New("aws-sts: no STSClient configured (wire WithSTS / AWS SDK in the provider process)")
	}

	token, expiresAt, err := p.STS.AssumeRole(ctx, roleARN, sessionName, externalID, region, ttl)
	if err != nil {
		return nil, fmt.Errorf("aws-sts: AssumeRole: %w", err)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(ttl)
	}

	uuid, err := randomUUID()
	if err != nil {
		return nil, err
	}

	return &credentials.VendedCredential{
		Provider:   "aws",
		Type:       "aws-sts",
		UUID:       uuid,
		APIKey:     token,
		ExpiresAt:  expiresAt,
		TTLSeconds: int(time.Until(expiresAt).Seconds()),
	}, nil
}

func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("aws-sts: uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:]), nil
}

var (
	_ credentials.ScopeValidator   = (*Plugin)(nil)
	_ credentials.CredentialVender = (*Plugin)(nil)
)
