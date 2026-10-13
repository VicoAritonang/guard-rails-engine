package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Tracer adapts OpenTelemetry to the narrow core.Tracer interface.
//
// The indirection keeps the core package free of an OTel dependency, which
// matters for two reasons: core is the package most likely to be vendored into
// someone else's binary through pkg/sdk, and the guard unit tests should not
// need a trace provider to run.
type Tracer struct {
	tr trace.Tracer
}

// NewTracer returns a tracer backed by the global provider. If no provider has
// been installed, OTel supplies a no-op and every span becomes free, so this is
// safe to wire unconditionally.
func NewTracer(name string) *Tracer {
	if name == "" {
		name = "github.com/vicoaritonang/guardrails-engine"
	}
	return &Tracer{tr: otel.Tracer(name)}
}

// Start opens a span and returns a function that closes it, recording an error
// if one is supplied.
func (t *Tracer) Start(ctx context.Context, name string, attrs map[string]string) (context.Context, func(error)) {
	kv := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		if v == "" {
			continue // an empty attribute is noise on every span
		}
		kv = append(kv, attribute.String(k, v))
	}
	ctx, span := t.tr.Start(ctx, name, trace.WithAttributes(kv...))
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			// A policy block is a correct outcome, not a server fault. Marking
			// it Error would make every blocked prompt look like an incident
			// on a service-health dashboard.
			span.SetStatus(codes.Ok, "blocked by policy")
		}
		span.End()
	}
}

// SpanFromContext exposes the active span so the server layer can attach
// request-level attributes without importing OTel itself.
func SpanFromContext(ctx context.Context) trace.Span { return trace.SpanFromContext(ctx) }

// TraceID returns the current trace id, or "" when tracing is not enabled.
// Emitting it in the audit log is what lets an operator jump from a blocked
// request to the full trace.
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
