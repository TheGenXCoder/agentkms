package credentials

import "context"

// LLMSessionValidator is the built-in ScopeValidator for Kind="llm-session".
// It wraps the v0.1 credential vending behaviour and ensures backward
// compatibility: existing Vend calls that don't specify scope get the legacy
// llm-session behaviour.
type LLMSessionValidator struct{}

// Kind returns the scope kind this validator owns.
func (v *LLMSessionValidator) Kind() string {
	return "" // TODO: implement
}

// Validate checks structural correctness of an llm-session scope.
func (v *LLMSessionValidator) Validate(ctx context.Context, s Scope) error {
	return nil // TODO: implement
}

// Narrow intersects a requested scope with policy bounds and returns the
// effective scope.
func (v *LLMSessionValidator) Narrow(ctx context.Context, requested Scope, bounds ScopeBounds) (Scope, error) {
	return Scope{}, nil // TODO: implement
}

// Compile-time interface check.
var _ ScopeValidator = (*LLMSessionValidator)(nil)
