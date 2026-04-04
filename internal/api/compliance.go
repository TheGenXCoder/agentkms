package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// soc2Event is a wrapper for AuditEvent that includes SOC 2 control mapping.
type soc2Event struct {
	audit.AuditEvent
	SOC2Controls []string `json:"soc2_controls"`
}

// handleSOC2ComplianceExport handles GET /compliance/soc2.
// Query parameters:
//   - start: start time (RFC 3339), default 24h ago
//   - end: end time (RFC 3339), default now
//
// This endpoint exports audit records mapped directly to SOC 2 control identifiers.
//
// FX-05.
func (s *Server) handleSOC2ComplianceExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	// SECURITY: verify identity has 'auditor' role or is in the 'platform-team'.
	// In AgentKMS, we delegate this to the policy engine.
	decision, err := s.policy.Evaluate(ctx, id, "compliance_export", "soc2")
	if err != nil || !decision.Allow {
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied")
		return
	}

	// 1. Parse query parameters.
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time
	if startStr == "" {
		start = time.Now().Add(-24 * time.Hour)
	} else {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid start time")
			return
		}
	}

	if endStr == "" {
		end = time.Now()
	} else {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid end time")
			return
		}
	}

	// 2. Check if auditor supports export.
	exporter, ok := s.auditor.(audit.Exporter)
	if !ok {
		s.writeError(w, http.StatusNotImplemented, errCodeInternal, "audit export not supported by current sink")
		return
	}

	// 3. Start export stream.
	out, errc := exporter.Export(ctx, start, end)
	if out == nil {
		s.writeError(w, http.StatusNotImplemented, errCodeInternal, "export failed")
		return
	}

	// 4. Set headers and stream NDJSON.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="soc2-compliance-export.json"`)
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	for {
		select {
		case ev, ok := <-out:
			if !ok {
				// End of stream.
				if err := <-errc; err != nil {
					// We already sent 200 OK.
					return
				}
				return
			}

			// Map to SOC 2 controls.
			soc2Ev := soc2Event{
				AuditEvent:   ev,
				SOC2Controls: mapToSOC2(ev),
			}

			if err := enc.Encode(soc2Ev); err != nil {
				return
			}
		case err := <-errc:
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// mapToSOC2 maps an audit event to its corresponding SOC 2 control identifiers.
// References: docs/compliance-controls.md
func mapToSOC2(ev audit.AuditEvent) []string {
	// CC7.2: System monitoring — satisfied by the very existence of the audit record.
	controls := []string{"CC7.2"}

	switch ev.Operation {
	case audit.OperationAuth, audit.OperationAuthRefresh:
		// CC6.1: Logical access controls (authentication)
		controls = append(controls, "CC6.1")
	case audit.OperationRevoke:
		// CC6.3: Least-privilege access removal (revocation)
		controls = append(controls, "CC6.3")
	case audit.OperationRotateKey:
		// CC8.1: Change management (key rotation)
		controls = append(controls, "CC8.1")
	case audit.OperationCredentialVend, audit.OperationCredentialUse:
		// CC6.2: System credentials not in env vars (vending from backend)
		controls = append(controls, "CC6.2")
	}

	// If the operation was denied, it's evidence of logical access control enforcement.
	if ev.Outcome == audit.OutcomeDenied {
		controls = append(controls, "CC6.1")
	}

	// If it contains anomalies, it's evidence of CC7.2 monitoring effectiveness.
	if len(ev.Anomalies) > 0 {
		controls = append(controls, "CC7.2")
	}

	return controls
}
