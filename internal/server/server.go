// Package server exposes the guardrail engine over HTTP, in two modes.
//
// Validate mode (/v1/guard/*) is a sidecar: the caller keeps its own provider
// integration and asks the engine for a decision. Proxy mode
// (/v1/chat/completions) sits in the request path and enforces the decision
// itself. Both exist because organisations adopt guardrails in that order --
// first observe, then enforce -- and forcing a proxy on day one is how these
// projects get rejected.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/agent"
	"github.com/VicoAritonang/guard-rails-engine/internal/cache"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
	"github.com/VicoAritonang/guard-rails-engine/internal/judge"
	"github.com/VicoAritonang/guard-rails-engine/internal/mcp"
	"github.com/VicoAritonang/guard-rails-engine/internal/providers"
	"github.com/VicoAritonang/guard-rails-engine/internal/telemetry"
)

// Options configures the HTTP surface.
type Options struct {
	Engine   *guards.Engine
	Policy   *config.Policy
	Provider providers.Provider
	Pricing  *telemetry.Pricing
	Metrics  *telemetry.Metrics
	Auditor  *telemetry.Auditor
	Logger   *slog.Logger

	// Secret keys the redaction vault. It must be identical across replicas.
	Secret []byte

	// APIKeys gates every /v1 route. An empty set disables authentication,
	// which is only appropriate behind a trusted mesh.
	APIKeys []string

	// AdminKeys, when set, are the only keys accepted on the routes that grant
	// authority: minting an approval, re-pinning a quarantined tool, starting
	// an experiment. Empty leaves those routes on APIKeys.
	AdminKeys []string

	// RequestTimeout bounds a whole request including the upstream call.
	RequestTimeout time.Duration

	// MaxBodyBytes rejects oversized payloads before they are parsed. Without
	// it, the quota guard would only run after the process had already
	// allocated the whole body.
	MaxBodyBytes int64

	// EnableDashboard serves the embedded operator console at /.
	EnableDashboard bool

	// Router, when the provider is one, powers /v1/models and fallback
	// reporting. Provider is still what the proxy calls.
	Router *providers.Router
	// Exact and Semantic are the response caches; either may be nil.
	Exact    *cache.Exact
	Semantic *cache.Semantic
	// Tier is the semantic (model-based) classifier tier; nil means off.
	Tier *judge.Tier

	// MCP is the guarded MCP gateway; nil when no MCP config is loaded. It
	// also powers /v1/agent/run, the gateway's own function-calling agent.
	MCP *mcp.Gateway
	// Bus streams gateway events to the live console; nil disables /v1/events.
	Bus *Bus
	// Lab runs experiments from the web; nil leaves the page read-only.
	Lab *Lab

	// ExperimentsDir, when set, is served read-only to the showcase so it can
	// render the latest experiment results.
	ExperimentsDir string

	Version string
}

// Server is the HTTP entry point.
type Server struct {
	opts Options
	log  *slog.Logger
	mux  *http.ServeMux
	keys map[string]struct{}
	// adminKeys gate the routes that grant authority; see Options.AdminKeys.
	adminKeys map[string]struct{}

	// broker executes tool calls that pass the tool-level controls. Nil when
	// the tool_safety guard is disabled, in which case /v1/agent/* returns 503
	// rather than quietly executing without the controls.
	broker  *agent.Broker
	limiter *rateLimiter
	bus     *Bus

	ready atomicBool
}

// New builds the server and its routes.
func New(opts Options) (*Server, error) {
	if opts.Engine == nil {
		return nil, errors.New("server: Engine is required")
	}
	if opts.Policy == nil {
		return nil, errors.New("server: Policy is required")
	}
	if len(opts.Secret) == 0 {
		return nil, errors.New("server: Secret is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 60 * time.Second
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 8 << 20 // 8 MiB
	}
	if opts.Pricing == nil {
		opts.Pricing = telemetry.NewPricing()
	}

	s := &Server{
		opts:    opts,
		log:     opts.Logger,
		mux:     http.NewServeMux(),
		keys:    keySet(opts.APIKeys),
		limiter: newRateLimiter(),
		bus:     opts.Bus,

		adminKeys: keySet(opts.AdminKeys),
	}

	// The broker is built from the engine's own tool-safety evaluator, not
	// from a second read of the policy. /v1/agent/execute and the runtime
	// pipeline therefore cannot disagree about what a session may do -- and
	// "the validate endpoint says no but the execute endpoint says yes" is the
	// exact failure a governance gateway must not have.
	if ev := opts.Engine.ToolEvaluator(); ev != nil {
		exec := agent.NewSimulator(nil)
		b, err := agent.NewBroker(ev, exec, auditSink{s})
		if err != nil {
			return nil, fmt.Errorf("server: tool broker: %w", err)
		}
		s.broker = b
	}
	if len(s.keys) == 0 {
		s.log.Warn("no API keys configured: every /v1 route is unauthenticated")
	}

	s.routes()
	s.ready.Store(true)
	return s, nil
}

func (s *Server) routes() {
	// Liveness and readiness are unauthenticated and unmetered: a probe that
	// needs a credential is a probe that fails during a credential rotation.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)

	// Scrape exactly the registry the collectors were registered on. Taking it
	// from the Metrics object rather than a separate field makes it impossible
	// to serve an endpoint that does not contain the engine's own series.
	registry := prometheus.NewRegistry()
	if s.opts.Metrics != nil {
		registry = s.opts.Metrics.Registry()
	}
	s.mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	s.mux.Handle("POST /v1/guard/{stage}", s.protect(http.HandlerFunc(s.handleGuard)))
	s.mux.Handle("POST /v1/chat/completions", s.protect(http.HandlerFunc(s.handleChat)))
	s.mux.Handle("GET /v1/policy", s.protect(http.HandlerFunc(s.handlePolicy)))
	s.mux.Handle("GET /v1/guards", s.protect(http.HandlerFunc(s.handleGuards)))
	s.mux.Handle("GET /v1/models", s.protect(http.HandlerFunc(s.handleModels)))

	// Tool-level control plane. The catalog is readable by anyone who can
	// reach the API; execute and approve are the two routes that can cause an
	// effect, so they carry the same protection as everything else in /v1.
	s.mux.Handle("GET /v1/agent/tools", s.protect(http.HandlerFunc(s.handleAgentTools)))
	s.mux.Handle("POST /v1/agent/execute", s.protect(http.HandlerFunc(s.handleAgentExecute)))
	s.mux.Handle("POST /v1/agent/approve", s.protectAdmin(http.HandlerFunc(s.handleAgentApprove)))
	s.mux.Handle("POST /v1/agent/run", s.protect(http.HandlerFunc(s.handleAgentRun)))

	// MCP: the gateway is an MCP server (Streamable HTTP) in front of the
	// configured upstream MCP servers.
	if s.opts.MCP != nil {
		s.mux.Handle("POST /mcp", s.protect(s.opts.MCP))
		s.mux.Handle("DELETE /mcp", s.protect(s.opts.MCP))
		s.mux.Handle("GET /v1/mcp/servers", s.protect(http.HandlerFunc(s.handleMCPServers)))
		s.mux.Handle("POST /v1/mcp/repin", s.protectAdmin(http.HandlerFunc(s.handleMCPRepin)))
	}
	s.mux.Handle("GET /v1/events", s.protect(http.HandlerFunc(s.handleEvents)))
	s.mux.Handle("GET /v1/lab", s.protect(http.HandlerFunc(s.handleLab)))
	s.mux.Handle("POST /v1/lab/run", s.protectAdmin(http.HandlerFunc(s.handleLabRun)))

	if s.opts.EnableDashboard {
		// The showcase is the front door; the operator console sits beside it.
		s.mux.HandleFunc("GET /{$}", s.handleShowcase)
		s.mux.HandleFunc("GET /console", s.handleDashboard)
		s.mux.HandleFunc("GET /showcase", s.handleShowcase)
		// The pages are static and open, but everything that returns data goes
		// through protect. With no API keys that is only a rate and size limit,
		// so the console works on localhost; with keys, turning on the dashboard
		// must not open a way around them. Without a key the pages fall back to
		// their labelled simulation.
		s.mux.Handle("POST /playground", s.protect(http.HandlerFunc(s.handleGuard)))
		s.mux.Handle("GET /events", s.protect(http.HandlerFunc(s.handleEvents)))
		if s.opts.ExperimentsDir != "" {
			s.mux.Handle("GET /showcase/experiments/", s.protect(http.StripPrefix("/showcase/experiments/",
				reportFiles(http.FileServer(http.Dir(s.opts.ExperimentsDir))))))
		}
	}
}

// reportFiles serves experiment output. Dot paths stay private, because
// .callcache holds recorded model calls, and a report renders as a sandboxed
// document: it embeds model output, and a script in it must not run with this
// origin's access to the API.
func reportFiles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, seg := range strings.Split(r.URL.Path, "/") {
			if strings.HasPrefix(seg, ".") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// Handler returns the fully-wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	// Without this, any web page open in a browser on the same machine can POST
	// to a local gateway. API clients send no Origin or Sec-Fetch-Site headers
	// and are unaffected.
	h = http.NewCrossOriginProtection().Handler(h)
	h = s.withTimeout(h)
	h = s.withLogging(h)
	h = s.withTracing(h)
	h = s.withRequestID(h)
	h = s.withRecovery(h) // outermost: it must survive a panic in any layer
	return h
}

// SetReady flips the readiness probe, so a rolling deploy can drain a replica
// before it stops accepting connections.
func (s *Server) SetReady(v bool) { s.ready.Store(v) }

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.opts.Version,
	})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
		"policy": s.opts.Policy.Version,
	})
}

func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	out, err := s.opts.Policy.Marshal()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (s *Server) handleGuards(w http.ResponseWriter, _ *http.Request) {
	type guardInfo struct {
		Name      string  `json:"name"`
		Stage     string  `json:"stage"`
		Enabled   bool    `json:"enabled"`
		FailMode  string  `json:"fail_mode"`
		Timeout   string  `json:"timeout"`
		Threshold float64 `json:"threshold,omitempty"`
	}
	var out []guardInfo
	for _, name := range config.KnownGuards() {
		stage, _ := config.GuardStage(name)
		g := s.opts.Policy.Guard(name)
		out = append(out, guardInfo{
			Name: name, Stage: stage, Enabled: g.Enabled,
			FailMode:  string(s.opts.Policy.EffectiveFailMode(name)),
			Timeout:   s.opts.Policy.EffectiveTimeout(name).String(),
			Threshold: g.Threshold,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":  s.opts.Policy.Name,
		"version": s.opts.Policy.Version,
		"guards":  out,
	})
}

// --- middleware ---------------------------------------------------------------

type ctxKey string

const ctxRequestID ctxKey = "request_id"

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			id = newID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

// withTracing opens the server span every other span hangs off, and continues
// a caller's trace when it sends W3C traceparent. The trace id goes back in a
// response header so a caller holding a surprising response can jump straight
// to its trace.
func (s *Server) withTracing(next http.Handler) http.Handler {
	tr := otel.Tracer("github.com/VicoAritonang/guard-rails-engine/server")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tr.Start(ctx, r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
				attribute.String("guardrails.request_id", requestID(r.Context())),
			))
		defer span.End()
		if sc := span.SpanContext(); sc.IsValid() {
			w.Header().Set("X-Trace-Id", sc.TraceID().String())
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.response.status_code", rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}
	})
}

// validRequestID bounds a caller-supplied ID. It is echoed in a response header
// and written to every log line, and it defaults the trace an approval binds to.
func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// withRecovery converts a panic into a 500 instead of killing the process.
//
// A gateway that dies on a malformed request is a denial-of-service primitive
// handed to anyone who can reach it. The pipeline already contains panics per
// guard; this catches everything else.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler",
					"panic", rec, "path", r.URL.Path, "request_id", requestID(r.Context()))
				writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStream(r) {
			// An event stream is long-lived by design; the request timeout
			// and the server's write deadline would cut it every minute.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.opts.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush and Unwrap let streaming handlers (SSE) work through the recorder.
func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func isStream(r *http.Request) bool {
	return r.URL.Path == "/events" || r.URL.Path == "/v1/events"
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Probes and the metrics scrape would otherwise dominate the log.
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r)
		s.log.Info("http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", rec.bytes, "request_id", requestID(r.Context()),
			"trace_id", telemetry.TraceID(r.Context()))
	})
}

// protect applies authentication and per-key rate limiting.
func (s *Server) protect(next http.Handler) http.Handler { return s.gate(s.keys, next) }

// protectAdmin is protect for the routes that grant authority.
func (s *Server) protectAdmin(next http.Handler) http.Handler {
	if len(s.adminKeys) == 0 {
		return s.protect(next)
	}
	return s.gate(s.adminKeys, next)
}

func (s *Server) gate(keys map[string]struct{}, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a verified key names a bucket. Taking the header's word for it
		// would let a caller reset its own limit by sending a new value.
		bucket := "anonymous"
		if len(keys) > 0 {
			key := extractKey(r)
			if !validKey(keys, key) {
				writeError(w, http.StatusUnauthorized, "unauthorized",
					"provide a valid key via Authorization: Bearer <key> or X-Api-Key")
				return
			}
			bucket = key
		}
		if !s.limiter.allow(bucket) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// validKey compares in constant time. A timing-variable comparison on an API
// key is a small leak, but it is a free one to close.
func validKey(keys map[string]struct{}, candidate string) bool {
	if candidate == "" {
		return false
	}
	ok := false
	for k := range keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(candidate)) == 1 {
			ok = true
		}
	}
	return ok
}

func keySet(keys []string) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = struct{}{}
		}
	}
	return out
}

func extractKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, found := strings.CutPrefix(h, "Bearer "); found {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// --- helpers -------------------------------------------------------------------

// errorBody is the single error shape every endpoint returns.
type errorBody struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Details any    `json:"details,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent; all that is left is to not hang.
		slog.Default().Error("failed to encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, code int, kind, msg string) {
	var body errorBody
	body.Error.Type = kind
	body.Error.Message = msg
	writeJSON(w, code, body)
}

func writeErrorDetails(w http.ResponseWriter, code int, kind, msg string, details any) {
	var body errorBody
	body.Error.Type = kind
	body.Error.Message = msg
	body.Error.Details = details
	writeJSON(w, code, body)
}

// rateLimiter is a per-key token bucket.
//
// It is intentionally in-process. A distributed limiter needs shared state,
// which would break the stateless-execution requirement; the correct place for
// a global limit is the ingress in front of this service. What this provides is
// a local safety valve so one misbehaving client cannot saturate one replica.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, rate: 100, burst: 200}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		// Bound the map so an attacker rotating keys cannot grow it forever.
		if len(l.buckets) > 10000 {
			l.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*l.rate, l.burst)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type atomicBool struct {
	mu sync.RWMutex
	v  bool
}

func (a *atomicBool) Store(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicBool) Load() bool   { a.mu.RLock(); defer a.mu.RUnlock(); return a.v }

var idCounter struct {
	sync.Mutex
	n uint64
}

func newID() string {
	idCounter.Lock()
	idCounter.n++
	n := idCounter.n
	idCounter.Unlock()
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), n)
}

// handleModels lists what the proxy can route to, and the live state behind it.
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	// object and data are the OpenAI list shape; the rest is this gateway's.
	data := []modelEntry{}
	out := map[string]any{"object": "list", "provider": s.opts.Provider.Name()}
	if s.opts.Router != nil {
		routes := s.opts.Router.Routes()
		for _, rt := range routes {
			if rt.Tier != "classifier" {
				data = append(data, modelEntry{ID: rt.Alias, Object: "model", OwnedBy: rt.Provider})
			}
		}
		out["providers"] = s.opts.Router.Providers()
		out["routes"] = routes
		out["unavailable"] = s.opts.Router.Unavailable()
		out["circuits"] = s.opts.Router.CircuitStates()
	}
	out["cache"] = map[string]any{
		"exact":              s.opts.Exact.Stats(),
		"semantic":           s.opts.Semantic != nil,
		"semantic_threshold": s.opts.Semantic.Threshold(),
	}
	tier := map[string]any{"mode": string(s.opts.Tier.Mode())}
	if s.opts.Tier != nil && s.opts.Tier.Mode() != judge.ModeOff {
		o := s.opts.Tier.Options()
		names := make([]string, 0, len(o.Classifiers))
		for _, c := range o.Classifiers {
			names = append(names, c.Name())
		}
		tier["classifiers"] = names
		tier["stages"] = o.Stages
		tier["escalate_above"] = o.EscalateAbove
		tier["parallel"] = o.Parallel
		tier["combine"] = o.Combine
	}
	out["semantic_tier"] = tier
	out["data"] = data
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMCPServers(w http.ResponseWriter, _ *http.Request) {
	exposed, quarantined := s.opts.MCP.Inventory()
	writeJSON(w, http.StatusOK, map[string]any{"tools": exposed, "quarantined": quarantined})
}

func (s *Server) handleMCPRepin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool string `json:"tool"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Tool == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tool is required")
		return
	}
	if !s.opts.MCP.Repin(req.Tool) {
		writeError(w, http.StatusNotFound, "not_quarantined", "no quarantined tool by that name")
		return
	}
	s.log.Warn("mcp tool re-pinned by operator", "tool", req.Tool, "request_id", requestID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"repinned": req.Tool})
}
