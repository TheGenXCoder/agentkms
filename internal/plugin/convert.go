package plugin

// convert.go — pure conversion functions between internal/credentials types and
// api/plugin/v1 wire types. No I/O, no side effects.
//
// Wire encoding is standard protobuf binary (proto3).  The generated types use
// google.protobuf.Struct for map[string]any and google.protobuf.Timestamp for
// time.Time, so conversions go through the structpb and timestamppb helpers.

import (
	"fmt"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/credentials"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// scopeToProto converts a credentials.Scope to the wire representation.
func scopeToProto(s credentials.Scope) *pluginv1.Scope {
	return &pluginv1.Scope{
		Kind:       s.Kind,
		Params:     mapToStruct(s.Params),
		TtlSeconds: int64(s.TTL.Seconds()),
		IssuedAt:   timeToProto(s.IssuedAt),
		ExpiresAt:  timeToProto(s.ExpiresAt),
	}
}

// protoToScope converts a wire Scope to the internal representation.
func protoToScope(p *pluginv1.Scope) credentials.Scope {
	if p == nil {
		return credentials.Scope{}
	}
	ttl := time.Duration(p.GetTtlSeconds()) * time.Second
	return credentials.Scope{
		Kind:      p.GetKind(),
		Params:    structToMap(p.GetParams()),
		TTL:       ttl,
		IssuedAt:  protoToTime(p.GetIssuedAt()),
		ExpiresAt: protoToTime(p.GetExpiresAt()),
	}
}

// boundsToProto converts a credentials.ScopeBounds to the wire representation.
func boundsToProto(b credentials.ScopeBounds) *pluginv1.ScopeBounds {
	return &pluginv1.ScopeBounds{
		Kind:          b.Kind,
		MaxParams:     mapToStruct(b.MaxParams),
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
			Level:   protoToAnomalyLevel(a.GetLevel()),
			Code:    a.GetCode(),
			Message: a.GetMessage(),
		}
	}
	return out
}

// protoToAnomalyLevel maps wire AnomalyLevel to internal AnomalyLevel.
func protoToAnomalyLevel(l pluginv1.AnomalyLevel) credentials.AnomalyLevel {
	switch l {
	case pluginv1.AnomalyLevel_ANOMALY_LEVEL_INFO:
		return credentials.AnomalyInfo
	case pluginv1.AnomalyLevel_ANOMALY_LEVEL_WARN:
		return credentials.AnomalyWarn
	case pluginv1.AnomalyLevel_ANOMALY_LEVEL_ALERT:
		return credentials.AnomalyAlert
	default:
		return credentials.AnomalyInfo
	}
}

// mapToStruct converts a map[string]any to a google.protobuf.Struct.
// Returns nil for nil/empty maps.
func mapToStruct(m map[string]any) *structpb.Struct {
	if len(m) == 0 {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		// structpb.NewStruct only fails for non-JSON-serialisable values.
		// Scope params are always map[string]any from JSON deserialization,
		// so this should never happen in practice.
		panic(fmt.Sprintf("convert: mapToStruct: %v", err))
	}
	return s
}

// structToMap converts a google.protobuf.Struct to map[string]any.
// Returns nil for nil structs.
func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// timeToProto converts a time.Time to a *timestamppb.Timestamp.
// Returns nil for zero times.
func timeToProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// protoToTime converts a *timestamppb.Timestamp to time.Time.
// Returns zero time for nil timestamps.
func protoToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// errFromField converts a wire error field to a Go error, or nil on success.
func errFromField(errStr string) error {
	if errStr == "" {
		return nil
	}
	return fmt.Errorf("%s", errStr)
}
