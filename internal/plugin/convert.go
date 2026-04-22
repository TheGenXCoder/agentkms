package plugin

// convert.go — pure conversion functions between internal/credentials types and
// api/plugin/v1 wire types. No I/O, no side effects.

import (
	"fmt"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/credentials"
)

// scopeToProto converts a credentials.Scope to the wire representation.
func scopeToProto(s credentials.Scope) *pluginv1.Scope {
	return &pluginv1.Scope{
		Kind:       s.Kind,
		Params:     mapToAny(s.Params),
		TtlSeconds: int64(s.TTL.Seconds()),
		IssuedAt:   s.IssuedAt,
		ExpiresAt:  s.ExpiresAt,
	}
}

// protoToScope converts a wire Scope to the internal representation.
func protoToScope(p *pluginv1.Scope) credentials.Scope {
	if p == nil {
		return credentials.Scope{}
	}
	return credentials.Scope{
		Kind:      p.Kind,
		Params:    anyToMap(p.Params),
		IssuedAt:  p.IssuedAt,
		ExpiresAt: p.ExpiresAt,
	}
}

// boundsToProto converts a credentials.ScopeBounds to the wire representation.
func boundsToProto(b credentials.ScopeBounds) *pluginv1.ScopeBounds {
	return &pluginv1.ScopeBounds{
		Kind:          b.Kind,
		MaxParams:     mapToAny(b.MaxParams),
		MaxTtlSeconds: int64(b.MaxTTL.Seconds()),
	}
}

// protoToAnomalies converts wire anomalies to internal ScopeAnomaly slice.
func protoToAnomalies(anomalies []*pluginv1.ScopeAnomaly) []credentials.ScopeAnomaly {
	if len(anomalies) == 0 {
		return nil
	}
	out := make([]credentials.ScopeAnomaly, len(anomalies))
	for i, a := range anomalies {
		out[i] = credentials.ScopeAnomaly{
			Level:   protoToAnomalyLevel(a.Level),
			Code:    a.Code,
			Message: a.Message,
		}
	}
	return out
}

// protoToAnomalyLevel maps wire AnomalyLevel to internal AnomalyLevel.
func protoToAnomalyLevel(l pluginv1.AnomalyLevel) credentials.AnomalyLevel {
	switch l {
	case pluginv1.AnomalyLevelInfo:
		return credentials.AnomalyInfo
	case pluginv1.AnomalyLevelWarn:
		return credentials.AnomalyWarn
	case pluginv1.AnomalyLevelAlert:
		return credentials.AnomalyAlert
	default:
		return credentials.AnomalyInfo
	}
}

// mapToAny converts a map[string]any to the same type (identity for the JSON codec).
func mapToAny(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	return m
}

// anyToMap converts wire params back to map[string]any (identity for the JSON codec).
func anyToMap(m map[string]any) map[string]any {
	return m
}

// errFromField converts a wire error field to a Go error, or nil on success.
func errFromField(errStr string) error {
	if errStr == "" {
		return nil
	}
	return fmt.Errorf("%s", errStr)
}
