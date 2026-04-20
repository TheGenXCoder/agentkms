package credentials

import (
	"context"
	"fmt"
)

// ScopedVender orchestrates the scoped credential vending pipeline.
// It resolves the appropriate ScopeValidator for the requested Kind,
// validates, narrows against policy bounds, and returns a VendedCredential
// annotated with the effective Scope and its canonical hash.
type ScopedVender struct {
	validators map[string]ScopeValidator
}

// NewScopedVender constructs a ScopedVender from the supplied validators.
// Each validator is registered under its Kind().
func NewScopedVender(validators ...ScopeValidator) *ScopedVender {
	m := make(map[string]ScopeValidator, len(validators))
	for _, v := range validators {
		m[v.Kind()] = v
	}
	return &ScopedVender{validators: m}
}

// ScopedResult extends VendedCredential with the effective scope metadata
// produced by the pipeline.
type ScopedResult struct {
	Credential    *VendedCredential
	EffectiveScope Scope
	ScopeHash     string
}

// VendScoped runs the full scoped credential vending pipeline.
func (sv *ScopedVender) VendScoped(ctx context.Context, req VendRequest) (*ScopedResult, error) {
	// Default empty Kind to "llm-session" for back-compat.
	kind := req.DesiredScope.Kind
	if kind == "" {
		kind = "llm-session"
		req.DesiredScope.Kind = kind
	}

	// Look up validator by Kind.
	validator, ok := sv.validators[kind]
	if !ok {
		return nil, fmt.Errorf("unknown scope kind: %q", kind)
	}

	// Validate the requested scope.
	if err := validator.Validate(ctx, req.DesiredScope); err != nil {
		return nil, err
	}

	// Narrow the scope against policy bounds (empty bounds for now).
	narrowedScope, err := validator.Narrow(ctx, req.DesiredScope, ScopeBounds{})
	if err != nil {
		return nil, err
	}

	// Compute canonical hash of the effective scope.
	hash := ScopeHash(narrowedScope)

	return &ScopedResult{
		EffectiveScope: narrowedScope,
		ScopeHash:      hash,
	}, nil
}
