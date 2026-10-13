package telemetry

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/providers"
)

// Metrics implements core.Observer and exports Prometheus series.
//
// Label cardinality is the design constraint. Tenant is included because
// per-tenant attribution is the whole point of a multi-tenant gateway, but
// nothing per-request ever becomes a label -- no transaction id, no model
// string that a client could set freely, no finding message. A metrics
// endpoint that a caller can grow without bound is a denial-of-service vector
// dressed up as observability.
type Metrics struct {
	requests    *prometheus.CounterVec
	guardRuns   *prometheus.CounterVec
	guardErrors *prometheus.CounterVec
	findings    *prometheus.CounterVec
	mutations   *prometheus.CounterVec

	guardLatency *prometheus.HistogramVec
	stageLatency *prometheus.HistogramVec

	tokens *prometheus.CounterVec
	cost   *prometheus.CounterVec

	budgetBreaches prometheus.Counter
	degraded       *prometheus.CounterVec

	// Upstream, cache and semantic-tier series. The guardrail series above say
	// what the engine decided; these say what the decisions cost and how the
	// providers behind them are holding up.
	upstreamCalls   *prometheus.CounterVec
	upstreamLatency *prometheus.HistogramVec
	fallbacks       *prometheus.CounterVec
	circuit         *prometheus.GaugeVec
	cacheLookups    *prometheus.CounterVec
	cacheSavedCost  *prometheus.CounterVec
	cacheSavedTime  *prometheus.CounterVec
	judgeCalls      *prometheus.CounterVec
	judgeLatency    *prometheus.HistogramVec
	judgeCost       *prometheus.CounterVec
	tierDecisions   *prometheus.CounterVec
	tierDisagree    *prometheus.CounterVec
	e2eLatency      *prometheus.HistogramVec
	toolCalls       *prometheus.CounterVec
	mcpQuarantine   *prometheus.CounterVec

	// tenantLabel is disabled when an operator has too many tenants to make
	// per-tenant series affordable.
	tenantLabel bool
	log         *slog.Logger
	registry    *prometheus.Registry
}

// MetricsOptions configures the collector set.
type MetricsOptions struct {
	Namespace   string
	TenantLabel bool

	// Registry both receives the collectors and serves /metrics. It is one
	// concrete registry rather than a Registerer plus a separate Gatherer on
	// purpose: when those were two fields, it was possible to register
	// collectors on one registry and scrape another, and the result was a
	// /metrics endpoint that returned 200 with none of the engine's series in
	// it -- a monitoring gap with no error anywhere to reveal it.
	Registry *prometheus.Registry

	Logger *slog.Logger
}

// latencyBuckets are tuned to the engine's stated budget. Default Prometheus
// buckets start at 5ms, which would put every guard in the first bucket and
// make the p99 unmeasurable for a component whose whole promise is sub-50ms.
var latencyBuckets = []float64{
	0.000_01, 0.000_05, 0.000_1, 0.000_25, 0.000_5,
	0.001, 0.002_5, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250,
}

// NewMetrics registers the collectors.
func NewMetrics(opts MetricsOptions) (*Metrics, error) {
	if opts.Namespace == "" {
		opts.Namespace = "guardrails"
	}
	if opts.Registry == nil {
		opts.Registry = prometheus.NewRegistry()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	ns := opts.Namespace

	base := []string{"stage", "action"}
	if opts.TenantLabel {
		base = append(base, "tenant")
	}

	m := &Metrics{tenantLabel: opts.TenantLabel, log: opts.Logger, registry: opts.Registry}

	m.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "requests_total",
		Help: "Guardrail decisions by stage and final action.",
	}, base)

	m.guardRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "guard_runs_total",
		Help: "Guard invocations by stage, guard and resulting action.",
	}, []string{"stage", "guard", "action"})

	m.guardErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "guard_errors_total",
		Help: "Guard failures by kind and configured fail mode. A non-zero rate here means detection coverage is silently reduced.",
	}, []string{"guard", "kind", "fail_mode"})

	m.findings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "findings_total",
		Help: "Findings by guard, category and severity.",
	}, []string{"guard", "category", "severity"})

	m.mutations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "mutations_total",
		Help: "Payload rewrites applied, by guard and reason.",
	}, []string{"guard", "reason"})

	m.guardLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "guard_duration_seconds",
		Help: "Per-guard evaluation latency.", Buckets: latencyBuckets,
	}, []string{"stage", "guard"})

	m.stageLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "stage_duration_seconds",
		Help: "End-to-end pipeline latency per stage.", Buckets: latencyBuckets,
	}, []string{"stage"})

	m.tokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "tokens_total",
		Help: "Tokens accounted, by model and kind.",
	}, []string{"model", "kind"})

	m.cost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "cost_usd_total",
		Help: "Attributed spend in USD.",
	}, costLabels(opts.TenantLabel))

	m.budgetBreaches = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "budget_breaches_total",
		Help: "Requests or traces stopped for exceeding a cost or token budget.",
	})

	m.degraded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "degraded_decisions_total",
		Help: "Decisions returned while at least one guard had failed open.",
	}, []string{"stage"})

	m.upstreamCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "upstream_requests_total",
		Help: "Upstream model calls by provider, catalog route and outcome (ok | error | circuit_open).",
	}, []string{"provider", "route", "outcome", "status"})

	m.upstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "upstream_duration_seconds",
		Help:    "Upstream model call latency. Seconds-scale buckets: this is the LLM, not the guards.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 15, 30, 60},
	}, []string{"provider", "route"})

	m.fallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "upstream_fallbacks_total",
		Help: "Attempts made on a fallback route because an earlier route in the chain failed.",
	}, []string{"route", "outcome"})

	m.circuit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns, Name: "circuit_open",
		Help: "1 while the circuit breaker for an upstream is open or half-open.",
	}, []string{"upstream"})

	m.cacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "cache_lookups_total",
		Help: "Response cache lookups by kind (exact | semantic) and result (hit | miss | bypass).",
	}, []string{"kind", "result"})

	m.cacheSavedCost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "cache_saved_usd_total",
		Help: "Upstream spend avoided by serving from cache.",
	}, []string{"kind"})

	m.cacheSavedTime = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "cache_saved_seconds_total",
		Help: "Upstream latency avoided by serving from cache.",
	}, []string{"kind"})

	m.judgeCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "judge_calls_total",
		Help: "Semantic-tier classifier calls by classifier and verdict (safe | unsafe | error).",
	}, []string{"stage", "classifier", "verdict"})

	m.judgeLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "judge_duration_seconds",
		Help:    "Semantic-tier classifier latency.",
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4},
	}, []string{"classifier"})

	m.judgeCost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "judge_cost_usd_total",
		Help: "Spend on semantic-tier classifier calls.",
	}, []string{"classifier"})

	m.tierDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "semantic_tier_decisions_total",
		Help: "Semantic-tier escalation decisions: why it did or did not run, and the outcome.",
	}, []string{"stage", "mode", "reason", "outcome"})

	m.tierDisagree = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "semantic_tier_disagreements_total",
		Help: "Requests where exactly one tier saw a problem. judge_only is coverage the rules lack; heuristic_only is a candidate false positive.",
	}, []string{"stage", "direction"})

	m.e2eLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "proxy_duration_seconds",
		Help:    "End-to-end proxy latency by outcome (served | cached | blocked_inbound | blocked_semantic | blocked_outbound | error).",
		Buckets: []float64{0.001, 0.005, 0.025, 0.1, 0.25, 0.5, 1, 2, 4, 8, 15, 30, 60},
	}, []string{"outcome"})

	m.toolCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "tool_calls_total",
		Help: "Brokered tool calls (MCP and agent) by server, risk tier and outcome (executed | refused | approval_required | quarantined | result_blocked | ...).",
	}, []string{"server", "tier", "status"})

	m.mcpQuarantine = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "mcp_quarantined_total",
		Help: "MCP tools withheld from agents, by reason (poisoned_definition | rug_pull | invalid_grade).",
	}, []string{"server", "reason"})

	for _, c := range m.collectors() {
		if err := opts.Registry.Register(c); err != nil {
			// An already-registered collector is expected when the process
			// builds more than one engine (tests, the eval harness); reuse is
			// preferable to failing startup.
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				_ = are
				continue
			}
			return nil, err
		}
	}
	return m, nil
}

func costLabels(tenant bool) []string {
	if tenant {
		return []string{"model", "tenant"}
	}
	return []string{"model"}
}

func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.requests, m.guardRuns, m.guardErrors, m.findings, m.mutations,
		m.guardLatency, m.stageLatency, m.tokens, m.cost,
		m.budgetBreaches, m.degraded,
		m.upstreamCalls, m.upstreamLatency, m.fallbacks, m.circuit,
		m.cacheLookups, m.cacheSavedCost, m.cacheSavedTime,
		m.judgeCalls, m.judgeLatency, m.judgeCost, m.tierDecisions, m.tierDisagree,
		m.e2eLatency, m.toolCalls, m.mcpQuarantine,
	}
}

// GuardObserved records one guard invocation.
func (m *Metrics) GuardObserved(stage core.Stage, run core.GuardRun) {
	if run.Skipped {
		return
	}
	action := string(run.Action)
	if action == "" {
		action = string(core.ActionAllow)
	}
	m.guardRuns.WithLabelValues(string(stage), run.Guard, action).Inc()
	m.guardLatency.WithLabelValues(string(stage), run.Guard).Observe(run.Duration.Seconds())

	if run.Error != "" {
		kind := "error"
		if run.TimedOut {
			kind = "timeout"
		}
		m.guardErrors.WithLabelValues(run.Guard, kind, run.FailMode).Inc()
		// A guard failure is an availability event for the security posture,
		// not a debug detail: log it at warn so it reaches an on-call channel.
		m.log.Warn("guardrail failed",
			"guard", run.Guard, "stage", stage, "kind", kind,
			"fail_mode", run.FailMode, "error", run.Error,
			"duration_ms", run.Duration.Milliseconds())
	}
}

// DecisionObserved records the aggregated stage outcome.
func (m *Metrics) DecisionObserved(tx *core.Transaction, d *core.Decision) {
	labels := []string{string(d.Stage), string(d.Action)}
	if m.tenantLabel {
		labels = append(labels, tenantOf(tx))
	}
	m.requests.WithLabelValues(labels...).Inc()
	m.stageLatency.WithLabelValues(string(d.Stage)).Observe(d.Duration.Seconds())

	if d.Degraded {
		m.degraded.WithLabelValues(string(d.Stage)).Inc()
	}
	for _, f := range d.Findings {
		m.findings.WithLabelValues(f.Guard, f.Category, f.SeverityName).Inc()
		switch f.Category {
		case "quota.cost", "runtime.budget_cost", "runtime.budget_tokens", "quota.tokens":
			m.budgetBreaches.Inc()
		}
	}
	for _, mu := range d.Mutations {
		m.mutations.WithLabelValues(mu.Guard, mu.Reason).Inc()
	}
}

// RecordUsage attributes tokens and cost after a provider call completes.
//
// This is separate from DecisionObserved because usage is only known after the
// upstream responds, which is after the outbound stage has already run.
func (m *Metrics) RecordUsage(tenant, model string, u core.Usage, costUSD float64) {
	if model == "" {
		model = "unknown"
	}
	m.tokens.WithLabelValues(model, "input").Add(float64(u.InputTokens))
	m.tokens.WithLabelValues(model, "output").Add(float64(u.OutputTokens))
	if u.CacheReadTokens > 0 {
		m.tokens.WithLabelValues(model, "cache_read").Add(float64(u.CacheReadTokens))
	}
	if u.CacheWriteTokens > 0 {
		m.tokens.WithLabelValues(model, "cache_write").Add(float64(u.CacheWriteTokens))
	}
	if m.tenantLabel {
		m.cost.WithLabelValues(model, orDefault(tenant, "default")).Add(costUSD)
	} else {
		m.cost.WithLabelValues(model).Add(costUSD)
	}
}

func tenantOf(tx *core.Transaction) string {
	if tx == nil {
		return "default"
	}
	return orDefault(tx.Tenant, "default")
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Timer is a small helper for measuring ad-hoc spans in the server layer.
func Timer() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

// Registry returns the registry these collectors were registered on. The HTTP
// layer scrapes exactly this, so the exposition can never diverge from what was
// registered.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// UpstreamObserved implements providers.UpstreamObserver.
//
// Route rather than the upstream model id is the label: routes come from the
// operator's catalog and are bounded, whereas a "provider:model" request can
// name anything, and a label a client can grow is a cardinality attack.
func (m *Metrics) UpstreamObserved(ev providers.UpstreamEvent) {
	route := ev.Route
	if strings.Contains(route, ":") {
		route = "direct"
	}
	status := "-"
	if ev.Status > 0 {
		status = strconv.Itoa(ev.Status)
	}
	m.upstreamCalls.WithLabelValues(ev.Provider, route, ev.Outcome, status).Inc()
	if ev.Outcome != "circuit_open" {
		m.upstreamLatency.WithLabelValues(ev.Provider, route).Observe(ev.Duration.Seconds())
	}
	if ev.Fallback {
		m.fallbacks.WithLabelValues(route, ev.Outcome).Inc()
	}
	if ev.Outcome == "error" {
		m.log.Warn("upstream call failed", "provider", ev.Provider, "route", ev.Route,
			"status", ev.Status, "fallback", ev.Fallback, "duration_ms", ev.Duration.Milliseconds())
	}
}

// CircuitChanged implements providers.UpstreamObserver.
func (m *Metrics) CircuitChanged(key string, st providers.CircuitState) {
	v := 0.0
	if st != providers.CircuitClosed {
		v = 1
	}
	m.circuit.WithLabelValues(key).Set(v)
	m.log.Warn("circuit breaker transition", "upstream", key, "state", string(st))
}

// CacheObserved records one cache lookup.
func (m *Metrics) CacheObserved(kind, result string, savedUSD float64, saved time.Duration) {
	m.cacheLookups.WithLabelValues(kind, result).Inc()
	if result == "hit" {
		m.cacheSavedCost.WithLabelValues(kind).Add(savedUSD)
		m.cacheSavedTime.WithLabelValues(kind).Add(saved.Seconds())
	}
}

// JudgeObserved records one classifier call.
func (m *Metrics) JudgeObserved(stage, classifier, verdict string, d time.Duration, costUSD float64) {
	m.judgeCalls.WithLabelValues(stage, classifier, verdict).Inc()
	m.judgeLatency.WithLabelValues(classifier).Observe(d.Seconds())
	m.judgeCost.WithLabelValues(classifier).Add(costUSD)
}

// TierDecided records one semantic-tier decision.
func (m *Metrics) TierDecided(stage, mode, reason, outcome, disagreement string) {
	m.tierDecisions.WithLabelValues(stage, mode, reason, outcome).Inc()
	if disagreement != "" {
		m.tierDisagree.WithLabelValues(stage, disagreement).Inc()
	}
}

// ProxyObserved records end-to-end proxy latency by outcome.
func (m *Metrics) ProxyObserved(outcome string, d time.Duration) {
	m.e2eLatency.WithLabelValues(outcome).Observe(d.Seconds())
}

// ToolCallObserved counts one brokered tool call.
func (m *Metrics) ToolCallObserved(server, tier, status string) {
	if server == "" {
		server = "builtin"
	}
	if tier == "" {
		tier = "none"
	}
	m.toolCalls.WithLabelValues(server, tier, status).Inc()
}

// QuarantineObserved counts one MCP tool quarantine.
func (m *Metrics) QuarantineObserved(server, reason string) {
	m.mcpQuarantine.WithLabelValues(server, reason).Inc()
}
