// Package pluginv1 provides the gRPC message types and service definitions for
// the AgentKMS plugin protocol.
//
// Code generated manually from api/plugin/v1/plugin.proto because protoc is not
// available in this environment. Regenerate with:
//
//	protoc --go_out=. --go-grpc_out=. api/plugin/v1/plugin.proto
//
// This hand-written implementation uses a JSON codec registered at init time.
// Both host and plugin binaries must import this package (or call RegisterJSONCodec)
// to ensure the codec is active.
package pluginv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

// jsonCodec overrides the default "proto" codec with JSON encoding so that
// plain Go structs can be transmitted over gRPC without protoc-generated code.
// Both the host and plugin binaries must register this codec before any RPC calls.
type jsonCodec struct{}

func (jsonCodec) Name() string { return "proto" } // override the default proto codec

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// RegisterJSONCodec installs the JSON codec as the "proto" codec for gRPC.
// This function is idempotent. Call it at process startup (before any gRPC
// connections are established) in both host and plugin binaries.
func RegisterJSONCodec() {
	encoding.RegisterCodec(jsonCodec{})
}

func init() {
	RegisterJSONCodec()
}

// ── Shared types ───────────────────────────────────────────────────────────────

// AnomalyLevel indicates the severity of a ScopeAnomaly.
type AnomalyLevel int32

const (
	AnomalyLevelUnspecified AnomalyLevel = 0
	AnomalyLevelInfo        AnomalyLevel = 1
	AnomalyLevelWarn        AnomalyLevel = 2
	AnomalyLevelAlert       AnomalyLevel = 3
)

// Scope mirrors internal/credentials.Scope over the wire.
type Scope struct {
	Kind       string         `json:"kind,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
	TtlSeconds int64          `json:"ttl_seconds,omitempty"`
	IssuedAt   time.Time      `json:"issued_at,omitempty"`
	ExpiresAt  time.Time      `json:"expires_at,omitempty"`
}

// ScopeBounds is the maximum scope a policy rule allows.
type ScopeBounds struct {
	Kind          string         `json:"kind,omitempty"`
	MaxParams     map[string]any `json:"max_params,omitempty"`
	MaxTtlSeconds int64          `json:"max_ttl_seconds,omitempty"`
}

// ScopeAnomaly is a single risk signal from a ScopeAnalyzer.
type ScopeAnomaly struct {
	Level   AnomalyLevel `json:"level,omitempty"`
	Code    string       `json:"code,omitempty"`
	Message string       `json:"message,omitempty"`
}

// VendedCredential is the output of a CredentialVenderService.Vend call.
type VendedCredential struct {
	ApiKey            []byte    `json:"api_key,omitempty"`
	Uuid              string    `json:"uuid,omitempty"`
	ProviderTokenHash string    `json:"provider_token_hash,omitempty"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
}

// PluginInfoMsg describes a plugin implementation.
type PluginInfoMsg struct {
	Kind       string `json:"kind,omitempty"`
	ApiVersion string `json:"api_version,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
}

// ── Kind RPC messages ──────────────────────────────────────────────────────────

// KindRequest is the input to any Kind RPC. Intentionally empty.
type KindRequest struct{}

// KindResponse carries the Kind string the plugin handles.
type KindResponse struct {
	Kind string `json:"kind,omitempty"`
}

// ── ScopeValidatorService messages ────────────────────────────────────────────

// ValidateRequest is the input to ScopeValidatorService.Validate.
type ValidateRequest struct {
	Scope *Scope `json:"scope,omitempty"`
}

// ValidateResponse is the output of ScopeValidatorService.Validate.
type ValidateResponse struct {
	Error string `json:"error,omitempty"`
}

// NarrowRequest is the input to ScopeValidatorService.Narrow.
type NarrowRequest struct {
	Requested *Scope       `json:"requested,omitempty"`
	Bounds    *ScopeBounds `json:"bounds,omitempty"`
}

// NarrowResponse is the output of ScopeValidatorService.Narrow.
type NarrowResponse struct {
	NarrowedScope *Scope `json:"narrowed_scope,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ── ScopeAnalyzerService messages ─────────────────────────────────────────────

// AnalyzeRequest is the input to ScopeAnalyzerService.Analyze.
type AnalyzeRequest struct {
	Scope *Scope `json:"scope,omitempty"`
}

// AnalyzeResponse is the output of ScopeAnalyzerService.Analyze.
type AnalyzeResponse struct {
	Anomalies []*ScopeAnomaly `json:"anomalies,omitempty"`
}

// ── ScopeSerializerService messages ───────────────────────────────────────────

// SerializeRequest is the input to ScopeSerializerService.Serialize.
type SerializeRequest struct {
	Scope *Scope `json:"scope,omitempty"`
}

// SerializeResponse is the output of ScopeSerializerService.Serialize.
type SerializeResponse struct {
	ProviderBytes []byte `json:"provider_bytes,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ── CredentialVenderService messages ──────────────────────────────────────────

// VendRequest is the input to CredentialVenderService.Vend.
type VendRequest struct {
	Scope *Scope `json:"scope,omitempty"`
}

// VendResponse is the output of CredentialVenderService.Vend.
type VendResponse struct {
	Credential *VendedCredential `json:"credential,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// ── ScopeValidatorService ─────────────────────────────────────────────────────

// ScopeValidatorServiceClient is the client API for ScopeValidatorService.
type ScopeValidatorServiceClient interface {
	Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error)
	Validate(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*ValidateResponse, error)
	Narrow(ctx context.Context, in *NarrowRequest, opts ...grpc.CallOption) (*NarrowResponse, error)
}

type scopeValidatorServiceClient struct {
	cc grpc.ClientConnInterface
}

// NewScopeValidatorServiceClient creates a new ScopeValidatorServiceClient.
func NewScopeValidatorServiceClient(cc grpc.ClientConnInterface) ScopeValidatorServiceClient {
	return &scopeValidatorServiceClient{cc}
}

func (c *scopeValidatorServiceClient) Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error) {
	out := new(KindResponse)
	err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeValidatorService/Kind", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *scopeValidatorServiceClient) Validate(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*ValidateResponse, error) {
	out := new(ValidateResponse)
	err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeValidatorService/Validate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *scopeValidatorServiceClient) Narrow(ctx context.Context, in *NarrowRequest, opts ...grpc.CallOption) (*NarrowResponse, error) {
	out := new(NarrowResponse)
	err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeValidatorService/Narrow", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ScopeValidatorServiceServer is the server API for ScopeValidatorService.
type ScopeValidatorServiceServer interface {
	Kind(context.Context, *KindRequest) (*KindResponse, error)
	Validate(context.Context, *ValidateRequest) (*ValidateResponse, error)
	Narrow(context.Context, *NarrowRequest) (*NarrowResponse, error)
	mustEmbedUnimplementedScopeValidatorServiceServer()
}

// UnimplementedScopeValidatorServiceServer embeds for forward compatibility.
type UnimplementedScopeValidatorServiceServer struct{}

func (UnimplementedScopeValidatorServiceServer) Kind(context.Context, *KindRequest) (*KindResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Kind not implemented")
}
func (UnimplementedScopeValidatorServiceServer) Validate(context.Context, *ValidateRequest) (*ValidateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Validate not implemented")
}
func (UnimplementedScopeValidatorServiceServer) Narrow(context.Context, *NarrowRequest) (*NarrowResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Narrow not implemented")
}
func (UnimplementedScopeValidatorServiceServer) mustEmbedUnimplementedScopeValidatorServiceServer() {
}

// RegisterScopeValidatorServiceServer registers the server implementation.
func RegisterScopeValidatorServiceServer(s grpc.ServiceRegistrar, srv ScopeValidatorServiceServer) {
	s.RegisterService(&ScopeValidatorService_ServiceDesc, srv)
}

func _ScopeValidatorService_Kind_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KindRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeValidatorServiceServer).Kind(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeValidatorService/Kind"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeValidatorServiceServer).Kind(ctx, req.(*KindRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScopeValidatorService_Validate_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(ValidateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeValidatorServiceServer).Validate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeValidatorService/Validate"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeValidatorServiceServer).Validate(ctx, req.(*ValidateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScopeValidatorService_Narrow_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(NarrowRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeValidatorServiceServer).Narrow(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeValidatorService/Narrow"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeValidatorServiceServer).Narrow(ctx, req.(*NarrowRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ScopeValidatorService_ServiceDesc is the grpc.ServiceDesc for ScopeValidatorService.
var ScopeValidatorService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agentkms.plugin.v1.ScopeValidatorService",
	HandlerType: (*ScopeValidatorServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Kind", Handler: _ScopeValidatorService_Kind_Handler},
		{MethodName: "Validate", Handler: _ScopeValidatorService_Validate_Handler},
		{MethodName: "Narrow", Handler: _ScopeValidatorService_Narrow_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "plugin.proto",
}

// ── ScopeAnalyzerService ──────────────────────────────────────────────────────

// ScopeAnalyzerServiceClient is the client API for ScopeAnalyzerService.
type ScopeAnalyzerServiceClient interface {
	Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error)
	Analyze(ctx context.Context, in *AnalyzeRequest, opts ...grpc.CallOption) (*AnalyzeResponse, error)
}

type scopeAnalyzerServiceClient struct{ cc grpc.ClientConnInterface }

// NewScopeAnalyzerServiceClient creates a new ScopeAnalyzerServiceClient.
func NewScopeAnalyzerServiceClient(cc grpc.ClientConnInterface) ScopeAnalyzerServiceClient {
	return &scopeAnalyzerServiceClient{cc}
}

func (c *scopeAnalyzerServiceClient) Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error) {
	out := new(KindResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeAnalyzerService/Kind", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *scopeAnalyzerServiceClient) Analyze(ctx context.Context, in *AnalyzeRequest, opts ...grpc.CallOption) (*AnalyzeResponse, error) {
	out := new(AnalyzeResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeAnalyzerService/Analyze", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// ScopeAnalyzerServiceServer is the server API for ScopeAnalyzerService.
type ScopeAnalyzerServiceServer interface {
	Kind(context.Context, *KindRequest) (*KindResponse, error)
	Analyze(context.Context, *AnalyzeRequest) (*AnalyzeResponse, error)
	mustEmbedUnimplementedScopeAnalyzerServiceServer()
}

// UnimplementedScopeAnalyzerServiceServer embeds for forward compatibility.
type UnimplementedScopeAnalyzerServiceServer struct{}

func (UnimplementedScopeAnalyzerServiceServer) Kind(context.Context, *KindRequest) (*KindResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Kind not implemented")
}
func (UnimplementedScopeAnalyzerServiceServer) Analyze(context.Context, *AnalyzeRequest) (*AnalyzeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Analyze not implemented")
}
func (UnimplementedScopeAnalyzerServiceServer) mustEmbedUnimplementedScopeAnalyzerServiceServer() {}

// RegisterScopeAnalyzerServiceServer registers the server implementation.
func RegisterScopeAnalyzerServiceServer(s grpc.ServiceRegistrar, srv ScopeAnalyzerServiceServer) {
	s.RegisterService(&ScopeAnalyzerService_ServiceDesc, srv)
}

func _ScopeAnalyzerService_Kind_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KindRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeAnalyzerServiceServer).Kind(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeAnalyzerService/Kind"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeAnalyzerServiceServer).Kind(ctx, req.(*KindRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScopeAnalyzerService_Analyze_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(AnalyzeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeAnalyzerServiceServer).Analyze(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeAnalyzerService/Analyze"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeAnalyzerServiceServer).Analyze(ctx, req.(*AnalyzeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ScopeAnalyzerService_ServiceDesc is the grpc.ServiceDesc for ScopeAnalyzerService.
var ScopeAnalyzerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agentkms.plugin.v1.ScopeAnalyzerService",
	HandlerType: (*ScopeAnalyzerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Kind", Handler: _ScopeAnalyzerService_Kind_Handler},
		{MethodName: "Analyze", Handler: _ScopeAnalyzerService_Analyze_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "plugin.proto",
}

// ── ScopeSerializerService ────────────────────────────────────────────────────

// ScopeSerializerServiceClient is the client API for ScopeSerializerService.
type ScopeSerializerServiceClient interface {
	Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error)
	Serialize(ctx context.Context, in *SerializeRequest, opts ...grpc.CallOption) (*SerializeResponse, error)
}

type scopeSerializerServiceClient struct{ cc grpc.ClientConnInterface }

// NewScopeSerializerServiceClient creates a new ScopeSerializerServiceClient.
func NewScopeSerializerServiceClient(cc grpc.ClientConnInterface) ScopeSerializerServiceClient {
	return &scopeSerializerServiceClient{cc}
}

func (c *scopeSerializerServiceClient) Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error) {
	out := new(KindResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeSerializerService/Kind", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *scopeSerializerServiceClient) Serialize(ctx context.Context, in *SerializeRequest, opts ...grpc.CallOption) (*SerializeResponse, error) {
	out := new(SerializeResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.ScopeSerializerService/Serialize", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// ScopeSerializerServiceServer is the server API for ScopeSerializerService.
type ScopeSerializerServiceServer interface {
	Kind(context.Context, *KindRequest) (*KindResponse, error)
	Serialize(context.Context, *SerializeRequest) (*SerializeResponse, error)
	mustEmbedUnimplementedScopeSerializerServiceServer()
}

// UnimplementedScopeSerializerServiceServer embeds for forward compatibility.
type UnimplementedScopeSerializerServiceServer struct{}

func (UnimplementedScopeSerializerServiceServer) Kind(context.Context, *KindRequest) (*KindResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Kind not implemented")
}
func (UnimplementedScopeSerializerServiceServer) Serialize(context.Context, *SerializeRequest) (*SerializeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Serialize not implemented")
}
func (UnimplementedScopeSerializerServiceServer) mustEmbedUnimplementedScopeSerializerServiceServer() {
}

// RegisterScopeSerializerServiceServer registers the server implementation.
func RegisterScopeSerializerServiceServer(s grpc.ServiceRegistrar, srv ScopeSerializerServiceServer) {
	s.RegisterService(&ScopeSerializerService_ServiceDesc, srv)
}

func _ScopeSerializerService_Kind_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KindRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeSerializerServiceServer).Kind(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeSerializerService/Kind"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeSerializerServiceServer).Kind(ctx, req.(*KindRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScopeSerializerService_Serialize_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(SerializeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScopeSerializerServiceServer).Serialize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.ScopeSerializerService/Serialize"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ScopeSerializerServiceServer).Serialize(ctx, req.(*SerializeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ScopeSerializerService_ServiceDesc is the grpc.ServiceDesc for ScopeSerializerService.
var ScopeSerializerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agentkms.plugin.v1.ScopeSerializerService",
	HandlerType: (*ScopeSerializerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Kind", Handler: _ScopeSerializerService_Kind_Handler},
		{MethodName: "Serialize", Handler: _ScopeSerializerService_Serialize_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "plugin.proto",
}

// ── CredentialVenderService ───────────────────────────────────────────────────

// CredentialVenderServiceClient is the client API for CredentialVenderService.
type CredentialVenderServiceClient interface {
	Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error)
	Vend(ctx context.Context, in *VendRequest, opts ...grpc.CallOption) (*VendResponse, error)
}

type credentialVenderServiceClient struct{ cc grpc.ClientConnInterface }

// NewCredentialVenderServiceClient creates a new CredentialVenderServiceClient.
func NewCredentialVenderServiceClient(cc grpc.ClientConnInterface) CredentialVenderServiceClient {
	return &credentialVenderServiceClient{cc}
}

func (c *credentialVenderServiceClient) Kind(ctx context.Context, in *KindRequest, opts ...grpc.CallOption) (*KindResponse, error) {
	out := new(KindResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.CredentialVenderService/Kind", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *credentialVenderServiceClient) Vend(ctx context.Context, in *VendRequest, opts ...grpc.CallOption) (*VendResponse, error) {
	out := new(VendResponse)
	if err := c.cc.Invoke(ctx, "/agentkms.plugin.v1.CredentialVenderService/Vend", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// CredentialVenderServiceServer is the server API for CredentialVenderService.
type CredentialVenderServiceServer interface {
	Kind(context.Context, *KindRequest) (*KindResponse, error)
	Vend(context.Context, *VendRequest) (*VendResponse, error)
	mustEmbedUnimplementedCredentialVenderServiceServer()
}

// UnimplementedCredentialVenderServiceServer embeds for forward compatibility.
type UnimplementedCredentialVenderServiceServer struct{}

func (UnimplementedCredentialVenderServiceServer) Kind(context.Context, *KindRequest) (*KindResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Kind not implemented")
}
func (UnimplementedCredentialVenderServiceServer) Vend(context.Context, *VendRequest) (*VendResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Vend not implemented")
}
func (UnimplementedCredentialVenderServiceServer) mustEmbedUnimplementedCredentialVenderServiceServer() {
}

// RegisterCredentialVenderServiceServer registers the server implementation.
func RegisterCredentialVenderServiceServer(s grpc.ServiceRegistrar, srv CredentialVenderServiceServer) {
	s.RegisterService(&CredentialVenderService_ServiceDesc, srv)
}

func _CredentialVenderService_Kind_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KindRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialVenderServiceServer).Kind(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.CredentialVenderService/Kind"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(CredentialVenderServiceServer).Kind(ctx, req.(*KindRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CredentialVenderService_Vend_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(VendRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialVenderServiceServer).Vend(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/agentkms.plugin.v1.CredentialVenderService/Vend"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(CredentialVenderServiceServer).Vend(ctx, req.(*VendRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CredentialVenderService_ServiceDesc is the grpc.ServiceDesc for CredentialVenderService.
var CredentialVenderService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agentkms.plugin.v1.CredentialVenderService",
	HandlerType: (*CredentialVenderServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Kind", Handler: _CredentialVenderService_Kind_Handler},
		{MethodName: "Vend", Handler: _CredentialVenderService_Vend_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "plugin.proto",
}

// ErrFromResponse converts an RPC error field to a Go error.
func ErrFromResponse(errStr string) error {
	if errStr == "" {
		return nil
	}
	return fmt.Errorf("%s", errStr)
}
