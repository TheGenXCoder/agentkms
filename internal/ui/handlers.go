package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"gopkg.in/yaml.v3"
)

// Handlers holds the dependencies for the UI API.
type Handlers struct {
	Backend backend.Backend
	Auditor audit.Auditor
	Policy  policy.EngineI
	Env     string

	// RequireSignature, when true, rejects unsigned YAML policy updates.
	// Production default is true. Valid signed Bundle JSON is accepted and
	// applied via Policy.Reload after verification.
	RequireSignature bool

	// Trust holds public keys for verifying signed policy bundles submitted
	// via HandleUpdatePolicy. Required when RequireSignature is true.
	Trust *policy.TrustStore
}

// HandleListKeys returns a list of keys in JSON format.
func (h *Handlers) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// No filter for now.
	metas, err := h.Backend.ListKeys(ctx, backend.KeyScope{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, metas)
}

// HandleListAudit returns the recent audit logs.
func (h *Handlers) HandleListAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	exporter, ok := h.Auditor.(audit.Exporter)
	if !ok {
		// If the auditor doesn't support export, we can't show anything.
		// For the UI, we'll return an empty list or an error.
		http.Error(w, "audit export not supported", http.StatusNotImplemented)
		return
	}

	// For the UI, show the last 1 hour of logs.
	end := time.Now().UTC()
	start := end.Add(-1 * time.Hour)

	out, errc := exporter.Export(ctx, start, end)
	var events []audit.AuditEvent
	for ev := range out {
		events = append(events, ev)
		if len(events) > 100 { // limit to last 100 for the UI
			break
		}
	}

	select {
	case err := <-errc:
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
	}

	writeJSON(w, http.StatusOK, events)
}

// HandleGetPolicy returns the current policy in YAML format.
func (h *Handlers) HandleGetPolicy(w http.ResponseWriter, r *http.Request) {
	p := h.Policy.GetPolicy()
	data, err := yaml.Marshal(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// HandleUpdatePolicy updates the policy from a signed Bundle JSON envelope
// or (when signatures are not required) from raw YAML.
//
// When RequireSignature is true, only a valid verified bundle is accepted —
// unsigned YAML is rejected with 400. Fail-closed: verification failure does
// not Reload the engine.
func (h *Handlers) HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	var p *policy.Policy

	// Prefer JSON bundle when the body looks like a JSON object.
	if looksLikeJSONObject(bytes.TrimSpace(body)) {
		if h.Trust == nil || h.Trust.Len() == 0 {
			if h.RequireSignature {
				http.Error(w, "signed policy bundle required but no trust keys configured", http.StatusBadRequest)
				return
			}
			// No trust keys and signatures not required: cannot verify a bundle body.
			http.Error(w, "cannot verify policy bundle: no trust keys configured", http.StatusBadRequest)
			return
		}
		parsed, verr := policy.ParseAndVerify(bytes.TrimSpace(body), h.Trust)
		if verr != nil {
			http.Error(w, "invalid or untrusted policy bundle: "+verr.Error(), http.StatusBadRequest)
			return
		}
		p = parsed
	} else {
		if h.RequireSignature {
			http.Error(w, "unsigned policy YAML rejected (signature required); submit a signed policy.bundle.json", http.StatusBadRequest)
			return
		}
		// Use LoadFromBytes so KnownFields + Validate match the file load path.
		parsed, lerr := policy.LoadFromBytes(body)
		if lerr != nil {
			http.Error(w, "invalid YAML", http.StatusBadRequest)
			return
		}
		p = parsed
	}

	if h.Policy == nil {
		http.Error(w, "policy engine not configured", http.StatusInternalServerError)
		return
	}
	if err := h.Policy.Reload(*p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// looksLikeJSONObject reports whether b appears to be a JSON object (possibly
// after UTF-8 BOM / leading whitespace already stripped by the caller).
func looksLikeJSONObject(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	// Content-Type is not required; detect by first non-space rune.
	i := 0
	for i < len(b) && unicode.IsSpace(rune(b[i])) {
		i++
	}
	if i >= len(b) {
		return false
	}
	if b[i] != '{' {
		return false
	}
	// Cheap guard: bundle envelopes include policy_yaml or signature keys.
	s := string(b)
	return strings.Contains(s, `"policy_yaml"`) || strings.Contains(s, `"signature"`) ||
		strings.Contains(s, `"key_id"`)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
