// handlers_bindings.go — T3: credential binding endpoints.
//
// Endpoints:
//
//	POST   /bindings              — register (create or replace) a binding
//	GET    /bindings              — list all bindings (summary shape)
//	GET    /bindings/{name}       — full binding JSON
//	DELETE /bindings/{name}       — remove a binding
//	POST   /bindings/{name}/rotate — manual one-shot rotation
//
// All endpoints:
//   - require an authenticated session (existing authMiddleware)
//   - emit an audit event via s.auditLog
//   - return JSON with existing error shapes (writeJSON / writeError)
//
// The rotate endpoint calls the destination registry (plugin.Registry) to deliver
// the fresh credential via the registered DestinationDeliverer for each kind.

package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/destination"
)

// ── SetBindingStore ───────────────────────────────────────────────────────────

// SetBindingStore wires in the binding store after construction.
// Call this from cmd/server/main.go once the KV backend is available.
// If not called, all /bindings/* endpoints return 503 Service Unavailable.
func (s *Server) SetBindingStore(bs binding.BindingStore) {
	s.bindingStore = bs
}

// ── POST /bindings ────────────────────────────────────────────────────────────

// handleRegisterBinding handles POST /bindings.
// Body: JSON CredentialBinding. Creates or replaces the binding.
func (s *Server) handleRegisterBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationBindingRegister
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	populateIdentityFields(&ev, id)

	if s.bindingStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "binding store not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var b binding.CredentialBinding
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid JSON body"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}

	if err := b.Validate(); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "validation failed"
		ev.KeyID = "bindings/" + b.Name
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, err.Error())
		return
	}

	ev.KeyID = "bindings/" + b.Name

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationBindingRegister, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateDecisionFields(&ev, decision)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	// Stamp server-managed metadata.
	now := binding.NowUTC()
	if b.Metadata.CreatedAt == "" {
		b.Metadata.CreatedAt = now
	}

	if err := s.bindingStore.Save(ctx, b); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	populateDecisionFields(&ev, decision)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, b)
}

// ── GET /bindings ─────────────────────────────────────────────────────────────

// handleListBindings handles GET /bindings.
// Returns a JSON array of BindingSummary objects.
// Optional query param: ?tag=<tag> to filter by tag.
func (s *Server) handleListBindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationBindingRegister // list uses same permission as register for now
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "bindings/*"
	populateIdentityFields(&ev, id)

	if s.bindingStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "binding store not configured")
		return
	}

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationBindingRegister, "bindings/*")
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateDecisionFields(&ev, decision)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	all, err := s.bindingStore.List(ctx)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	tagFilter := r.URL.Query().Get("tag")
	summaries := make([]binding.BindingSummary, 0, len(all))
	for _, b := range all {
		if tagFilter != "" && !containsTag(b.Metadata.Tags, tagFilter) {
			continue
		}
		summaries = append(summaries, b.Summary())
	}

	ev.Outcome = audit.OutcomeSuccess
	populateDecisionFields(&ev, decision)
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, map[string]any{"bindings": summaries})
}

// ── GET /bindings/{name} ──────────────────────────────────────────────────────

// handleGetBinding handles GET /bindings/{name}.
// Returns the full CredentialBinding JSON.
func (s *Server) handleGetBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationBindingRegister
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "bindings/" + name
	populateIdentityFields(&ev, id)

	if s.bindingStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "binding store not configured")
		return
	}

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationBindingRegister, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateDecisionFields(&ev, decision)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	b, err := s.bindingStore.Get(ctx, name)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		if isBindingNotFound(err) {
			ev.DenyReason = "binding not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "binding not found")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	populateDecisionFields(&ev, decision)
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, b)
}

// ── DELETE /bindings/{name} ───────────────────────────────────────────────────

// handleDeleteBinding handles DELETE /bindings/{name}.
// Removes the binding (hard delete — bindings have no secret value, so soft
// delete adds no value over the audit log).
func (s *Server) handleDeleteBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationBindingDelete
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "bindings/" + name
	populateIdentityFields(&ev, id)

	if s.bindingStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "binding store not configured")
		return
	}

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationBindingDelete, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateDecisionFields(&ev, decision)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if err := s.bindingStore.Delete(ctx, name); err != nil {
		ev.Outcome = audit.OutcomeError
		if isBindingNotFound(err) {
			ev.DenyReason = "binding not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "binding not found")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	populateDecisionFields(&ev, decision)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── POST /bindings/{name}/rotate ──────────────────────────────────────────────

// rotateResponse is the JSON body returned by POST /bindings/{name}/rotate.
type rotateResponse struct {
	Name       string                     `json:"name"`
	Generation uint64                     `json:"generation"`
	RotatedAt  string                     `json:"rotated_at"`
	Results    []binding.DestinationResult `json:"results"`
}

// handleRotateBinding handles POST /bindings/{name}/rotate.
//
// Manual one-shot rotation:
//  1. Fetch the binding.
//  2. Vend the credential via the existing Vender (LLM/generic provider kinds);
//     non-LLM provider kinds produce a stub value until a provider plugin registry lands.
//  3. For each destination, call Deliver on the destination registry (plugin.Registry).
//     If the registry is not wired or the kind is unknown, the result records the error.
//  4. Update binding metadata (last_rotated_at, last_generation).
//  5. Return per-destination results.
func (s *Server) handleRotateBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationBindingRotate
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "bindings/" + name
	populateIdentityFields(&ev, id)

	if s.bindingStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "binding store not configured")
		return
	}

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationBindingRotate, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateDecisionFields(&ev, decision)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	b, err := s.bindingStore.Get(ctx, name)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		if isBindingNotFound(err) {
			ev.DenyReason = "binding not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "binding not found")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── Step 2: Vend the credential ──────────────────────────────────────────
	//
	// Attempt a vend via the existing Vender for LLM/generic provider kinds.
	// Non-LLM provider kinds (e.g. "github-app-token") produce a stub credential
	// value until a provider plugin registry lands in a future track.
	var credentialValue []byte
	var credentialUUID string

	if s.vender != nil {
		// Attempt LLM-session vend when provider_kind matches a supported LLM provider.
		// This covers the primary OSS use case.
		vendedCred, vendErr := s.vender.Vend(ctx, b.ProviderKind)
		if vendErr == nil {
			credentialValue = vendedCred.APIKey
			credentialUUID = vendedCred.UUID
			ev.CredentialUUID = vendedCred.UUID
			ev.CredentialType = vendedCred.Type
			defer vendedCred.Zero()
		}
		// If vend fails (provider not in SupportedProviders, or key not found),
		// fall through to the stub path below so rotate still exercises destinations.
	}

	if credentialUUID == "" {
		// Stub: generate a placeholder UUID for non-LLM provider kinds.
		// Replace this with s.providerRegistry.LookupVender(b.ProviderKind).Vend(ctx, b.Scope)
		// once a provider plugin registry lands.
		credentialUUID = "stub-" + b.Name + "-rotation"
		credentialValue = []byte("stub-credential-value")

		// Emit a dedicated stub-marker audit event so forensics queries can
		// distinguish real rotations (OperationBindingRotate) from stub-path
		// no-op rotations (OperationBindingRotateStub). B-INT-2 / T3-B-2.
		if stubEv, stubEvErr := audit.New(); stubEvErr == nil {
			stubEv.Operation = audit.OperationBindingRotateStub
			stubEv.Environment = s.env
			stubEv.SourceIP = extractRemoteIP(r)
			stubEv.UserAgent = r.UserAgent()
			stubEv.KeyID = ev.KeyID
			populateIdentityFields(&stubEv, id)
			populateDecisionFields(&stubEv, decision)
			stubEv.Outcome = audit.OutcomeSuccess
			stubEv.ErrorDetail = "provider plugin not available; stub credential used for provider_kind=" + b.ProviderKind
			_ = s.auditLog(ctx, stubEv)
		}
	}

	// ── Step 3: Deliver to each destination ──────────────────────────────────
	//
	// For each destination spec in the binding, look up the deliverer by kind in
	// the destination registry and call Deliver.  If the registry is not wired or
	// the kind is unknown, record the error in the result and continue (partial
	// success is reported per-destination in the response body).

	now := binding.NowUTC()
	newGeneration := b.Metadata.LastGeneration + 1
	results := make([]binding.DestinationResult, len(b.Destinations))
	anySuccess := false

	for i, dest := range b.Destinations {
		if s.destinationRegistry == nil {
			results[i] = binding.DestinationResult{
				Kind:     dest.Kind,
				TargetID: dest.TargetID,
				Success:  false,
				Error:    "destination registry not configured",
			}
			continue
		}

		deliverer, lookupErr := s.destinationRegistry.LookupDeliverer(dest.Kind)
		if lookupErr != nil {
			results[i] = binding.DestinationResult{
				Kind:     dest.Kind,
				TargetID: dest.TargetID,
				Success:  false,
				Error:    "unknown destination kind: " + dest.Kind,
			}
			continue
		}

		req := destination.DeliverRequest{
			TargetID:        dest.TargetID,
			CredentialValue: credentialValue,
			Generation:      newGeneration,
			DeliveryID:      credentialUUID,
			CredentialUUID:  credentialUUID,
			Params:          dest.Params,
		}
		_, deliverErr := deliverer.Deliver(ctx, req)
		if deliverErr != nil {
			results[i] = binding.DestinationResult{
				Kind:     dest.Kind,
				TargetID: dest.TargetID,
				Success:  false,
				Error:    deliverErr.Error(),
			}
			continue
		}

		results[i] = binding.DestinationResult{
			Kind:     dest.Kind,
			TargetID: dest.TargetID,
			Success:  true,
		}
		anySuccess = true
	}

	// ── Step 4: Update metadata ───────────────────────────────────────────────
	if anySuccess {
		b.Metadata.LastRotatedAt = now
		b.Metadata.LastGeneration = newGeneration
		if saveErr := s.bindingStore.Save(ctx, *b); saveErr != nil {
			// Non-fatal: rotation succeeded, metadata update failed. Log and continue.
			ev.ErrorDetail = "metadata update failed after rotation"
		}
	}

	// ── Step 5: Audit and respond ─────────────────────────────────────────────
	ev.Outcome = audit.OutcomeSuccess
	populateDecisionFields(&ev, decision)
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, rotateResponse{
		Name:       name,
		Generation: newGeneration,
		RotatedAt:  now,
		Results:    results,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isBindingNotFound returns true when err is a binding not-found error.
func isBindingNotFound(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "binding: not found"
}

// containsTag returns true when tags contains target.
func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}
