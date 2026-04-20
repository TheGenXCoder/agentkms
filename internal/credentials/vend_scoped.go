package credentials

import "context"

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
	// TODO: implement pipeline
	return nil, nil
}
