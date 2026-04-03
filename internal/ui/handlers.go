package ui

import (
	"encoding/json"
	"net/http"
	"time"

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

// HandleUpdatePolicy updates the policy from YAML input.
func (h *Handlers) HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := yaml.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid YAML", http.StatusBadRequest)
		return
	}

	if err := h.Policy.Reload(p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
