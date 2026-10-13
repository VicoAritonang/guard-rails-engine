package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"
)

// Route is one entry in the model catalog: a stable alias the client asks for,
// mapped to the upstream that serves it and what to try when that upstream is
// unavailable.
//
// Aliases exist because upstream ids are not a contract. "openai/gpt-oss-20b"
// on Groq and "gpt-5-mini-2025-08-07" on OpenAI are vendor naming decisions; a
// client hard-coding them breaks the day a vendor renames a snapshot, and a
// client cannot be told to fail over to a model whose id it never knew.
type Route struct {
	Alias     string   `yaml:"-" json:"alias"`
	Provider  string   `yaml:"provider" json:"provider"`
	Model     string   `yaml:"model" json:"model"`
	Effort    string   `yaml:"effort,omitempty" json:"effort,omitempty"`
	MaxTokens int      `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
	Fallbacks []string `yaml:"fallbacks,omitempty" json:"fallbacks,omitempty"`
	// Tier is descriptive (small | medium | large | classifier). The cost-aware
	// router and the console use it; the router itself never reads it.
	Tier        string `yaml:"tier,omitempty" json:"tier,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Catalog is the parsed model catalog.
type Catalog struct {
	Default string            `yaml:"default"`
	Models  map[string]*Route `yaml:"models"`
}

// LoadCatalog reads a catalog file. Unknown fields are rejected for the same
// reason the policy loader rejects them: a misspelt "fallbacks" is a failover
// plan that silently does not exist.
func LoadCatalog(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read model catalog: %w", err)
	}
	var c Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse model catalog %s: %w", path, err)
	}
	for alias, r := range c.Models {
		if r == nil {
			return nil, fmt.Errorf("model catalog: %q has no body", alias)
		}
		r.Alias = alias
	}
	return &c, nil
}

// Attempt records one upstream call made while serving a request.
type Attempt struct {
	Route      string `json:"route"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	Status     int    `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Skipped means the circuit breaker refused to try this upstream at all.
	Skipped bool `json:"skipped,omitempty"`
}

// UpstreamEvent is emitted for every attempt, so the metrics layer can count
// fallbacks and failures per upstream without the router importing Prometheus.
type UpstreamEvent struct {
	Route    string
	Provider string
	Model    string
	// Outcome is ok | error | circuit_open.
	Outcome  string
	Status   int
	Duration time.Duration
	// Fallback is true for every attempt after the first.
	Fallback bool
}

// UpstreamObserver receives router events.
type UpstreamObserver interface {
	UpstreamObserved(UpstreamEvent)
	CircuitChanged(key string, state CircuitState)
}

// RouterOptions configures a Router.
type RouterOptions struct {
	Providers map[string]Provider
	Catalog   *Catalog
	// DefaultProvider serves model names that are neither an alias nor in
	// "provider:model" form, which keeps a router-backed gateway compatible
	// with clients written against the single-provider one.
	DefaultProvider string
	Observer        UpstreamObserver
	Breaker         BreakerOptions
}

// Router serves a request from the first healthy upstream in its route's
// fallback chain.
//
// What it deliberately does not do is retry the same upstream: the SDKs
// already retry with backoff, and stacking a second retry loop on top turns a
// 30-second provider brown-out into minutes of queued requests. The router's
// only job is to move to a different upstream, and to stop sending traffic to
// one that is plainly down.
type Router struct {
	opts     RouterOptions
	breakers sync.Map // key -> *breaker
	tracer   trace.Tracer
}

// NewRouter validates the catalog against the configured providers.
func NewRouter(opts RouterOptions) (*Router, error) {
	if len(opts.Providers) == 0 {
		return nil, errors.New("router: no providers configured")
	}
	if opts.Catalog == nil {
		opts.Catalog = &Catalog{}
	}
	if opts.Catalog.Models == nil {
		opts.Catalog.Models = map[string]*Route{}
	}
	if opts.DefaultProvider == "" {
		for name := range opts.Providers {
			opts.DefaultProvider = name
			break
		}
	}
	if _, ok := opts.Providers[opts.DefaultProvider]; !ok {
		return nil, fmt.Errorf("router: default provider %q is not configured", opts.DefaultProvider)
	}

	// Drop routes whose provider is not configured rather than failing: a
	// catalog lists every model the team uses, and a developer with only an
	// OpenAI key should still be able to start the gateway. The dropped routes
	// are reported by Unavailable so the gap is visible.
	for alias, r := range opts.Catalog.Models {
		for _, fb := range r.Fallbacks {
			if _, ok := opts.Catalog.Models[fb]; !ok {
				return nil, fmt.Errorf("router: %q falls back to unknown alias %q", alias, fb)
			}
		}
	}
	if d := opts.Catalog.Default; d != "" {
		if _, ok := opts.Catalog.Models[d]; !ok {
			return nil, fmt.Errorf("router: default alias %q is not in the catalog", d)
		}
	}
	opts.Breaker = opts.Breaker.withDefaults()
	return &Router{opts: opts, tracer: otel.Tracer("github.com/vicoaritonang/guardrails-engine/providers")}, nil
}

func (r *Router) Name() string { return "router" }

// Routes lists the catalog entries whose provider is configured, sorted.
func (r *Router) Routes() []Route {
	var out []Route
	for _, rt := range r.opts.Catalog.Models {
		if _, ok := r.opts.Providers[rt.Provider]; ok {
			out = append(out, *rt)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// Unavailable lists catalog aliases whose provider has no credentials.
func (r *Router) Unavailable() []string {
	var out []string
	for alias, rt := range r.opts.Catalog.Models {
		if _, ok := r.opts.Providers[rt.Provider]; !ok {
			out = append(out, alias+" ("+rt.Provider+")")
		}
	}
	sort.Strings(out)
	return out
}

// Providers lists configured provider names.
func (r *Router) Providers() []string {
	out := make([]string, 0, len(r.opts.Providers))
	for n := range r.opts.Providers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Resolve expands a requested model into the ordered chain of routes to try.
func (r *Router) Resolve(model string) ([]Route, error) {
	if model == "" {
		if r.opts.Catalog.Default == "" {
			return []Route{{Alias: "default", Provider: r.opts.DefaultProvider}}, nil
		}
		model = r.opts.Catalog.Default
	}

	if rt, ok := r.opts.Catalog.Models[model]; ok {
		var chain []Route
		seen := map[string]bool{}
		var walk func(alias string)
		walk = func(alias string) {
			if seen[alias] {
				return // a fallback cycle is harmless once deduplicated
			}
			seen[alias] = true
			e := r.opts.Catalog.Models[alias]
			if _, ok := r.opts.Providers[e.Provider]; ok {
				chain = append(chain, *e)
			}
			for _, fb := range e.Fallbacks {
				walk(fb)
			}
		}
		walk(rt.Alias)
		if len(chain) == 0 {
			return nil, fmt.Errorf("router: no configured provider can serve %q (wants %s)", model, rt.Provider)
		}
		return chain, nil
	}

	// "provider:model" addresses an upstream directly. A colon rather than a
	// slash because Groq's own ids contain slashes ("openai/gpt-oss-20b"), and
	// "openai/..." would be ambiguous between a provider and a model family.
	if prov, m, ok := strings.Cut(model, ":"); ok {
		if _, known := r.opts.Providers[prov]; known {
			return []Route{{Alias: model, Provider: prov, Model: m}}, nil
		}
	}
	return []Route{{Alias: model, Provider: r.opts.DefaultProvider, Model: model}}, nil
}

// Complete serves req from the first upstream in the chain that answers.
func (r *Router) Complete(ctx context.Context, req Request) (*Response, error) {
	chain, err := r.Resolve(req.Model)
	if err != nil {
		return nil, &UpstreamError{StatusCode: 400, Err: err}
	}

	var attempts []Attempt
	var lastErr error
	for i, rt := range chain {
		if ctx.Err() != nil {
			break
		}
		key := rt.Provider + ":" + rt.Model
		br := r.breaker(key)
		if !br.allow() {
			attempts = append(attempts, Attempt{Route: rt.Alias, Provider: rt.Provider, Model: rt.Model, Skipped: true})
			r.observe(UpstreamEvent{Route: rt.Alias, Provider: rt.Provider, Model: rt.Model,
				Outcome: "circuit_open", Fallback: i > 0})
			lastErr = &UpstreamError{StatusCode: 503, Retryable: true,
				Err: fmt.Errorf("circuit open for %s", key)}
			continue
		}

		sub := req
		sub.Model = rt.Model
		if rt.Effort != "" {
			sub.Effort = rt.Effort
		}
		if sub.MaxTokens <= 0 && rt.MaxTokens > 0 {
			sub.MaxTokens = rt.MaxTokens
		}

		resp, dur, err := r.call(ctx, rt, sub, i > 0)
		att := Attempt{Route: rt.Alias, Provider: rt.Provider, Model: rt.Model, DurationMS: dur.Milliseconds()}
		if err == nil {
			r.transition(key, br.success())
			attempts = append(attempts, att)
			resp.Provider, resp.Route, resp.Attempts, resp.Latency = rt.Provider, rt.Alias, attempts, dur
			return resp, nil
		}

		var ue *UpstreamError
		retryable := true
		if errors.As(err, &ue) {
			att.Status = ue.StatusCode
			retryable = ue.Retryable
		}
		att.Error = err.Error()
		attempts = append(attempts, att)
		lastErr = err

		// Only an upstream fault counts against the breaker. A 400 is the
		// caller's mistake and would be the same mistake on every upstream, so
		// it neither trips the circuit nor triggers a fallback.
		if !retryable {
			return nil, &RouteError{Attempts: attempts, Err: err}
		}
		r.transition(key, br.failure())
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, &RouteError{Attempts: attempts, Err: lastErr}
}

func (r *Router) call(ctx context.Context, rt Route, req Request, fallback bool) (*Response, time.Duration, error) {
	p := r.opts.Providers[rt.Provider]

	// GenAI semantic conventions, so the span renders as an LLM call in any
	// OTel backend that understands them, not as an anonymous function.
	ctx, span := r.tracer.Start(ctx, "chat "+rt.Model,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("gen_ai.operation.name", "chat"),
			attribute.String("gen_ai.system", rt.Provider),
			attribute.String("gen_ai.request.model", rt.Model),
			attribute.String("guardrails.route", rt.Alias),
			attribute.Bool("guardrails.fallback", fallback),
		))
	defer span.End()

	start := time.Now()
	resp, err := p.Complete(ctx, req)
	dur := time.Since(start)

	ev := UpstreamEvent{Route: rt.Alias, Provider: rt.Provider, Model: rt.Model, Duration: dur, Fallback: fallback}
	if err != nil {
		ev.Outcome = "error"
		var ue *UpstreamError
		if errors.As(err, &ue) {
			ev.Status = ue.StatusCode
			span.SetAttributes(attribute.Int("http.response.status_code", ue.StatusCode))
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "upstream error")
		r.observe(ev)
		return nil, dur, err
	}
	ev.Outcome = "ok"
	span.SetAttributes(
		attribute.String("gen_ai.response.model", resp.Model),
		attribute.Int("gen_ai.usage.input_tokens", resp.Usage.InputTokens+resp.Usage.CacheReadTokens),
		attribute.Int("gen_ai.usage.output_tokens", resp.Usage.OutputTokens),
		attribute.StringSlice("gen_ai.response.finish_reasons", []string{resp.StopReason}),
	)
	r.observe(ev)
	return resp, dur, nil
}

func (r *Router) observe(ev UpstreamEvent) {
	if r.opts.Observer != nil {
		r.opts.Observer.UpstreamObserved(ev)
	}
}

func (r *Router) transition(key string, changed CircuitState) {
	if changed != "" && r.opts.Observer != nil {
		r.opts.Observer.CircuitChanged(key, changed)
	}
}

func (r *Router) breaker(key string) *breaker {
	if b, ok := r.breakers.Load(key); ok {
		return b.(*breaker)
	}
	b, _ := r.breakers.LoadOrStore(key, &breaker{opts: r.opts.Breaker})
	return b.(*breaker)
}

// CircuitStates reports every breaker the router has created.
func (r *Router) CircuitStates() map[string]CircuitState {
	out := map[string]CircuitState{}
	r.breakers.Range(func(k, v any) bool {
		out[k.(string)] = v.(*breaker).state()
		return true
	})
	return out
}

// RouteError carries the full attempt history of a request that no upstream
// could serve, so the 502 a caller sees says which upstreams were tried.
type RouteError struct {
	Attempts []Attempt
	Err      error
}

func (e *RouteError) Error() string {
	return fmt.Sprintf("all %d upstream attempt(s) failed; last: %v", len(e.Attempts), e.Err)
}
func (e *RouteError) Unwrap() error { return e.Err }

// --- circuit breaker ----------------------------------------------------------

// CircuitState is closed | open | half_open. The empty value means "no change"
// when returned from a transition.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// BreakerOptions tunes the per-upstream circuit breaker.
type BreakerOptions struct {
	// FailureThreshold consecutive retryable failures open the circuit.
	FailureThreshold int
	// Cooldown is how long an open circuit refuses traffic before letting a
	// single probe through.
	Cooldown time.Duration
	// Disabled turns the breaker into a pass-through, for experiments that
	// measure what it buys.
	Disabled bool
	// Now is injectable so the resilience experiment can run on a virtual
	// clock.
	Now func() time.Time
}

func (o BreakerOptions) withDefaults() BreakerOptions {
	if o.FailureThreshold <= 0 {
		o.FailureThreshold = 5
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// breaker exists so that a provider outage costs one timeout per cooldown
// rather than one timeout per request. Without it every request during an
// outage pays the full SDK retry budget against a dead upstream before it
// falls back, and p99 latency becomes "the retry budget".
type breaker struct {
	opts     BreakerOptions
	mu       sync.Mutex
	fails    int
	st       CircuitState
	openedAt time.Time
	probing  bool
}

func (b *breaker) state() CircuitState {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st == "" {
		return CircuitClosed
	}
	return b.st
}

func (b *breaker) allow() bool {
	if b.opts.Disabled {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.st {
	case CircuitOpen:
		if b.opts.Now().Sub(b.openedAt) < b.opts.Cooldown {
			return false
		}
		b.st, b.probing = CircuitHalfOpen, true
		return true
	case CircuitHalfOpen:
		// Exactly one probe at a time: a recovering upstream that is hit by
		// the whole backlog at once tends to fall straight over again.
		if b.probing {
			return false
		}
		b.probing = true
		return true
	}
	return true
}

func (b *breaker) success() CircuitState {
	if b.opts.Disabled {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.st
	b.fails, b.st, b.probing = 0, CircuitClosed, false
	if prev != "" && prev != CircuitClosed {
		return CircuitClosed
	}
	return ""
}

func (b *breaker) failure() CircuitState {
	if b.opts.Disabled {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	if b.st == CircuitHalfOpen {
		b.st, b.openedAt = CircuitOpen, b.opts.Now()
		return CircuitOpen
	}
	b.fails++
	if b.fails >= b.opts.FailureThreshold && b.st != CircuitOpen {
		b.st, b.openedAt = CircuitOpen, b.opts.Now()
		return CircuitOpen
	}
	return ""
}
