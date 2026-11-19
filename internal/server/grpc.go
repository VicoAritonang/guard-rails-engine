package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/telemetry"
	guardrailsv1 "go.vicoworks.com/guard-rails/pkg/api/guardrailsv1"
)

// GRPC returns a gRPC server carrying guardrails.v1.GuardService, the standard
// health service and reflection (so grpcurl works without the .proto file).
//
// It enforces what the HTTP surface does: the same API keys, the same
// per-key rate limit, the same request timeout and a message size bound
// derived from the body limits. Only the health service is unauthenticated,
// for the same reason /healthz is.
func (s *Server) GRPC(opts ...grpc.ServerOption) *grpc.Server {
	limit := max(s.opts.MaxBodyBytes, s.opts.MediaUploadBytes)
	base := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(int(limit)),
		grpc.ChainUnaryInterceptor(s.grpcRecover, s.grpcObserve, s.grpcGate),
	}
	gs := grpc.NewServer(append(base, opts...)...)
	guardrailsv1.RegisterGuardServiceServer(gs, &guardService{s: s})

	s.health = health.NewServer()
	s.syncHealth()
	healthpb.RegisterHealthServer(gs, s.health)
	reflection.Register(gs)
	return gs
}

// syncHealth mirrors the readiness flag onto the gRPC health service, so a
// draining replica reports NOT_SERVING to gRPC load balancers too.
func (s *Server) syncHealth() {
	if s.health == nil {
		return
	}
	st := healthpb.HealthCheckResponse_SERVING
	if !s.ready.Load() {
		st = healthpb.HealthCheckResponse_NOT_SERVING
	}
	s.health.SetServingStatus("", st)
	s.health.SetServingStatus(guardrailsv1.GuardService_ServiceDesc.ServiceName, st)
}

type guardService struct {
	guardrailsv1.UnimplementedGuardServiceServer
	s *Server
}

func (g *guardService) Guard(ctx context.Context, in *guardrailsv1.GuardRequest) (*guardrailsv1.GuardResponse, error) {
	stage := core.Stage(enumString(in.GetStage().Descriptor(), in.GetStage().Number()))
	if !stage.Valid() {
		return nil, status.Error(grpccodes.InvalidArgument,
			"stage must be STAGE_INBOUND, STAGE_RUNTIME, STAGE_TOOL_RESULT or STAGE_OUTBOUND")
	}
	var req guardRequest
	if err := fromProto(in.ProtoReflect(), &req); err != nil {
		return nil, status.Error(grpccodes.InvalidArgument, err.Error())
	}
	resp, aerr := g.s.guard(ctx, stage, &req)
	if aerr != nil {
		return nil, aerr.grpc()
	}
	out := &guardrailsv1.GuardResponse{}
	if err := toProto(resp, out.ProtoReflect()); err != nil {
		return nil, status.Error(grpccodes.Internal, "encode response: "+err.Error())
	}
	return out, nil
}

func (g *guardService) ListGuards(context.Context, *guardrailsv1.ListGuardsRequest) (*guardrailsv1.ListGuardsResponse, error) {
	out := &guardrailsv1.ListGuardsResponse{}
	if err := toProto(g.s.guardList(), out.ProtoReflect()); err != nil {
		return nil, status.Error(grpccodes.Internal, "encode response: "+err.Error())
	}
	return out, nil
}

// grpc renders an evaluation failure as a gRPC status. The error type string
// travels in the message so a client can match on it as REST clients do.
func (e *apiError) grpc() error {
	code := grpccodes.Internal
	switch e.status {
	case http.StatusBadRequest:
		code = grpccodes.InvalidArgument
	case http.StatusUnauthorized:
		code = grpccodes.Unauthenticated
	case http.StatusForbidden:
		code = grpccodes.PermissionDenied
	case http.StatusNotFound:
		code = grpccodes.NotFound
	case http.StatusTooManyRequests:
		code = grpccodes.ResourceExhausted
	case http.StatusServiceUnavailable:
		code = grpccodes.Unavailable
	}
	return status.Error(code, e.kind+": "+e.msg)
}

// --- interceptors -------------------------------------------------------------

func isHealth(method string) bool {
	return strings.HasPrefix(method, "/grpc.health.v1.Health/")
}

// grpcRecover is withRecovery for gRPC: a panic becomes INTERNAL, not a dead
// process.
func (s *Server) grpcRecover(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("panic in grpc handler", "panic", rec, "method", info.FullMethod,
				"request_id", requestID(ctx))
			err = status.Error(grpccodes.Internal, "internal error")
		}
	}()
	return next(ctx, req)
}

// grpcObserve assigns the request ID, continues the caller's trace, applies
// the request timeout and logs the call: the gRPC side of withRequestID,
// withTracing, withTimeout and withLogging.
func (s *Server) grpcObserve(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	if isHealth(info.FullMethod) {
		return next(ctx, req)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	id := first(md, "x-request-id")
	if !validRequestID(id) {
		id = newID()
	}
	ctx = context.WithValue(ctx, ctxRequestID, id)
	header := metadata.Pairs("x-request-id", id)

	ctx = otel.GetTextMapPropagator().Extract(ctx, mdCarrier(md))
	ctx, span := otel.Tracer("go.vicoworks.com/guard-rails/server").Start(ctx, info.FullMethod,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.method", info.FullMethod),
			attribute.String("guardrails.request_id", id),
		))
	defer span.End()
	if sc := span.SpanContext(); sc.IsValid() {
		header.Append("x-trace-id", sc.TraceID().String())
	}
	_ = grpc.SetHeader(ctx, header)

	ctx, cancel := context.WithTimeout(ctx, s.opts.RequestTimeout)
	defer cancel()

	start := time.Now()
	resp, err := next(ctx, req)
	code := status.Code(err)
	span.SetAttributes(attribute.String("rpc.grpc.status_code", code.String()))
	if code == grpccodes.Internal || code == grpccodes.Unknown {
		span.SetStatus(codes.Error, code.String())
	}
	s.log.Info("grpc request",
		"method", info.FullMethod, "code", code.String(),
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", id, "trace_id", telemetry.TraceID(ctx))
	return resp, err
}

// grpcGate is gate for gRPC: the same keys and the same token buckets, so a
// caller cannot double its rate limit by splitting traffic across transports.
func (s *Server) grpcGate(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	if isHealth(info.FullMethod) {
		return next(ctx, req)
	}
	bucket := "anonymous"
	if len(s.keys) > 0 {
		md, _ := metadata.FromIncomingContext(ctx)
		key := first(md, "x-api-key")
		if after, ok := strings.CutPrefix(first(md, "authorization"), "Bearer "); ok {
			key = after
		}
		key = strings.TrimSpace(key)
		if !validKey(s.keys, key) {
			return nil, status.Error(grpccodes.Unauthenticated,
				"unauthorized: provide a valid key via authorization: Bearer <key> or x-api-key metadata")
		}
		bucket = key
	}
	if !s.limiter.allow(bucket) {
		return nil, status.Error(grpccodes.ResourceExhausted, "rate_limited: too many requests")
	}
	return next(ctx, req)
}

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// mdCarrier lets the OpenTelemetry propagator read traceparent from metadata.
type mdCarrier metadata.MD

func (c mdCarrier) Get(key string) string { return first(metadata.MD(c), key) }
func (c mdCarrier) Set(key, val string)   { metadata.MD(c).Set(key, val) }
func (c mdCarrier) Keys() []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}
