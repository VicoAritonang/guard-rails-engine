package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TracingOptions configures the OTLP exporter.
type TracingOptions struct {
	ServiceName string
	Version     string
	// Endpoint is host:port of an OTLP/HTTP receiver (Jaeger, Tempo, an OTel
	// collector). Empty falls back to OTEL_EXPORTER_OTLP_ENDPOINT, which the
	// exporter reads itself.
	Endpoint string
	Insecure bool
	// SampleRatio in (0,1]. Guardrail traffic is low-volume relative to what
	// a tracing backend can absorb, and a blocked request that was not sampled
	// is an incident nobody can reconstruct, so the default is 1.
	SampleRatio float64
}

// SetupTracing installs a global tracer provider that exports over OTLP/HTTP.
//
// Before this existed the engine created spans against OTel's no-op global,
// so every span the pipeline opened went nowhere -- tracing was wired and
// invisible. The returned function flushes buffered spans; call it on
// shutdown or the last few seconds of traces before a crash are lost.
func SetupTracing(ctx context.Context, opts TracingOptions) (func(context.Context) error, error) {
	if opts.ServiceName == "" {
		opts.ServiceName = "guardrails-engine"
	}
	if opts.SampleRatio <= 0 || opts.SampleRatio > 1 {
		opts.SampleRatio = 1
	}
	var expOpts []otlptracehttp.Option
	if opts.Endpoint != "" {
		expOpts = append(expOpts, otlptracehttp.WithEndpoint(opts.Endpoint))
	} else if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return nil, fmt.Errorf("tracing: no OTLP endpoint (set GUARDRAILS_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT)")
	}
	if opts.Insecure {
		expOpts = append(expOpts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, expOpts...)
	if err != nil {
		return nil, fmt.Errorf("tracing: exporter: %w", err)
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", opts.ServiceName),
		attribute.String("service.version", opts.Version),
	))
	if err != nil {
		return nil, fmt.Errorf("tracing: resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(opts.SampleRatio))),
	)
	otel.SetTracerProvider(tp)
	// W3C trace context in and out, so a caller that already traces can see
	// the gateway's spans inside its own trace instead of a disconnected one.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	return tp.Shutdown, nil
}
