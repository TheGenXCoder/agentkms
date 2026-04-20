package credentials

import (
	"context"
	"fmt"
	"time"
)

// LLMSessionValidator is the built-in ScopeValidator for Kind="llm-session".
// It wraps the v0.1 credential vending behaviour and ensures backward
// compatibility: existing Vend calls that don't specify scope get the legacy
// llm-session behaviour.
type LLMSessionValidator struct{}

// Kind returns the scope kind this validator owns.
func (v *LLMSessionValidator) Kind() string {
	return "llm-session"
}

// Validate checks structural correctness of an llm-session scope.
func (v *LLMSessionValidator) Validate(ctx context.Context, s Scope) error {
	if s.Kind != "llm-session" {
		return fmt.Errorf("credentials: invalid scope kind %q, expected \"llm-session\"", s.Kind)
	}

	providerRaw, ok := s.Params["provider"]
	if !ok {
		return fmt.Errorf("credentials: missing required param \"provider\"")
	}
	provider, ok := providerRaw.(string)
	if !ok || provider == "" {
		return fmt.Errorf("credentials: param \"provider\" must be a non-empty string")
	}

	if !SupportedProviders[provider] {
		return fmt.Errorf("%w: %q", ErrProviderNotSupported, provider)
	}

	if s.TTL <= 0 {
		return fmt.Errorf("credentials: TTL must be positive, got %v", s.TTL)
	}
	if s.TTL > CredentialTTL {
		return fmt.Errorf("credentials: TTL %v exceeds maximum %v", s.TTL, CredentialTTL)
	}

	return nil
}

// Narrow intersects a requested scope with policy bounds and returns the
// effective scope.
func (v *LLMSessionValidator) Narrow(ctx context.Context, requested Scope, bounds ScopeBounds) (Scope, error) {
	effectiveTTL := requested.TTL

	if bounds.MaxTTL > 0 && effectiveTTL > bounds.MaxTTL {
		effectiveTTL = bounds.MaxTTL
	}

	if bounds.MaxParams != nil {
		if boundProvider, ok := bounds.MaxParams["provider"]; ok {
			reqProvider, _ := requested.Params["provider"]
			if reqProvider != boundProvider {
				return Scope{}, fmt.Errorf("credentials: requested provider %q conflicts with bound %q", reqProvider, boundProvider)
			}
		}
	}

	now := time.Now().UTC()
	return Scope{
		Kind:      requested.Kind,
		Params:    requested.Params,
		TTL:       effectiveTTL,
		IssuedAt:  now,
		ExpiresAt: now.Add(effectiveTTL),
	}, nil
}

// Compile-time interface check.
var _ ScopeValidator = (*LLMSessionValidator)(nil)
