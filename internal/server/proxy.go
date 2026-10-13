package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vicoaritonang/guardrails-engine/internal/cache"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/judge"
	"github.com/vicoaritonang/guardrails-engine/internal/providers"
	"github.com/vicoaritonang/guardrails-engine/internal/telemetry"
)

type chatRequest struct {
	Model     string         `json:"model"`
	Tenant    string         `json:"tenant,omitempty"`
	System    string         `json:"system,omitempty"`
	Messages  []core.Message `json:"messages"`
	MaxTokens int            `json:"max_tokens,omitempty"`
	Context   []string       `json:"context,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	// Cache set to false bypasses the response cache for this request, as
	// does a Cache-Control: no-cache request header.
	Cache *bool `json:"cache,omitempty"`
}

type chatResponse struct {
	ID         string         `json:"id"`
	Model      string         `json:"model"`
	Provider   string         `json:"provider,omitempty"`
	Route      string         `json:"route,omitempty"`
	Content    string         `json:"content"`
	StopReason string         `json:"stop_reason,omitempty"`
	Usage      core.Usage     `json:"usage"`
	CostUSD    float64        `json:"cost_usd"`
	Guardrails guardrailsMeta `json:"guardrails"`
}

// guardrailsMeta is attached to every proxied response.
//
// Surfacing what the engine did -- even when it did nothing -- is what turns a
// proxy from a black box into something a team will actually put in the request
// path. "Why was my answer different today" has to be answerable, and so does
// "why was it slow" and "why did it cost that much", which is what the timing,
// cache and routing fields are for.
type guardrailsMeta struct {
	PolicyVersion string         `json:"policy_version"`
	Inbound       *core.Decision `json:"inbound,omitempty"`
	Outbound      *core.Decision `json:"outbound,omitempty"`
	Redactions    int            `json:"redactions"`
	Restored      int            `json:"restored"`
	OverheadUS    int64          `json:"overhead_us"`
	Degraded      bool           `json:"degraded,omitempty"`

	// Semantic tier outcomes, when the tier is enabled.
	SemanticInbound  *judge.Outcome `json:"semantic_inbound,omitempty"`
	SemanticOutbound *judge.Outcome `json:"semantic_outbound,omitempty"`

	// Cache is miss | hit_exact | hit_semantic | bypass | off.
	Cache           string  `json:"cache"`
	CacheSimilarity float64 `json:"cache_similarity,omitempty"`

	Attempts []providers.Attempt `json:"attempts,omitempty"`
	Fallback bool                `json:"fallback,omitempty"`

	// Timing breaks the total down so the guard overhead can be read against
	// the model latency it sits in front of.
	Timing timing `json:"timing"`

	// JudgeCostUSD is spend on classifier calls, reported separately from the
	// completion's cost so the price of the semantic tier is visible.
	JudgeCostUSD float64 `json:"judge_cost_usd,omitempty"`
	// WastedCostUSD is spend on a completion that was discarded because the
	// parallel semantic verdict came back unsafe.
	WastedCostUSD float64 `json:"wasted_cost_usd,omitempty"`

	TraceID string `json:"trace_id,omitempty"`

	id string
}

func (m *guardrailsMeta) idOr() string { return m.id }

type timing struct {
	GuardsUS   int64 `json:"guards_us"`
	SemanticMS int64 `json:"semantic_ms"`
	UpstreamMS int64 `json:"upstream_ms"`
	TotalMS    int64 `json:"total_ms"`
}

var proxyTracer = otel.Tracer("github.com/vicoaritonang/guardrails-engine/server")

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provider == nil {
		writeError(w, http.StatusNotImplemented, "no_provider",
			"proxy mode is disabled; no upstream provider is configured")
		return
	}
	began := time.Now()

	var req chatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "messages must not be empty")
		return
	}

	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("gen_ai.request.model", req.Model),
		attribute.String("guardrails.tenant", req.Tenant))

	vault := core.NewVault(s.opts.Secret)
	meta := guardrailsMeta{PolicyVersion: s.opts.Policy.Version, Cache: "off", TraceID: telemetry.TraceID(ctx)}
	var (
		cost      float64
		resp      *providers.Response
		maskedFor []core.Message
	)
	finish := func(outcome string) {
		meta.Timing.TotalMS = time.Since(began).Milliseconds()
		route, provider := "", ""
		if resp != nil {
			route, provider = resp.Route, resp.Provider
		}
		s.publishRequest(meta.idOr(), &req, maskedFor, &meta, outcome, route, provider, cost)
		if s.opts.Metrics != nil {
			s.opts.Metrics.ProxyObserved(outcome, time.Since(began))
		}
		span.SetAttributes(attribute.String("guardrails.outcome", outcome))
	}

	// --- inbound: deterministic tier ----------------------------------------
	inTx := &core.Transaction{
		ID: newID(), Tenant: req.Tenant, Stage: core.StageInbound,
		Model: req.Model, System: req.System, Messages: req.Messages,
		Meta: req.Meta, StartedAt: time.Now(), Vault: vault,
	}
	inDec, _ := s.opts.Engine.Inbound.Execute(ctx, inTx)
	s.opts.Auditor.Record(ctx, inTx, inDec)
	maskedFor = inTx.Messages
	meta.id = inTx.ID

	meta.Inbound = inDec
	meta.Redactions = len(inDec.Mutations)
	meta.Degraded = inDec.Degraded
	overhead := inDec.Duration

	if inDec.Blocked() {
		// 422 rather than 400: the request was well-formed and the engine
		// understood it perfectly. It was refused on policy grounds, and that
		// distinction matters to whoever reads the caller's error dashboard.
		meta.OverheadUS = overhead.Microseconds()
		meta.Timing.GuardsUS = meta.OverheadUS
		finish("blocked_inbound")
		writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy", inDec.Reason(), meta)
		return
	}

	// --- inbound: semantic tier -----------------------------------------------
	// Classifiers see the masked text: the semantic tier is an upstream like
	// any other, and PII redaction exists so upstreams never see raw values.
	tier := s.opts.Tier
	var pending <-chan *judge.Outcome
	if tier.Applies(core.StageInbound) {
		text := judge.UserText(inTx.Messages)
		switch {
		case tier.Mode() == judge.ModeShadow:
			// Shadow never delays or alters the response. The detached
			// context keeps the classifier running after the handler returns,
			// which is the point: its verdict is for the logs.
			go s.semantic(context.WithoutCancel(ctx), core.StageInbound, text, inDec, inTx)
		case tier.Parallel():
			ch := make(chan *judge.Outcome, 1)
			go func() { ch <- s.semantic(ctx, core.StageInbound, text, inDec, inTx) }()
			pending = ch
		default:
			out := s.semantic(ctx, core.StageInbound, text, inDec, inTx)
			meta.SemanticInbound = out
			meta.JudgeCostUSD += out.CostUSD
			meta.Timing.SemanticMS += out.Duration.Milliseconds()
			if out.Enforced {
				meta.OverheadUS = overhead.Microseconds()
				meta.Timing.GuardsUS = meta.OverheadUS
				finish("blocked_semantic")
				writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy",
					out.Finding().Message, meta)
				return
			}
		}
	}

	// --- cache -----------------------------------------------------------------
	cacheOn := s.opts.Exact.Enabled() || s.opts.Semantic != nil
	bypass := (req.Cache != nil && !*req.Cache) ||
		strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-cache")
	key := cache.Key(cache.KeyInput{Tenant: req.Tenant, Model: req.Model, System: inTx.System,
		Messages: inTx.Messages, MaxTokens: req.MaxTokens})
	bucket := cache.Bucket(req.Tenant, req.Model, inTx.System)
	semQuery, semEligible := singleTurn(inTx.Messages)

	var (
		entry    cache.Entry
		hit      bool
		semVec   []float32
		fresh    bool
		upstream time.Duration
	)
	switch {
	case !cacheOn:
	case bypass:
		meta.Cache = "bypass"
		s.cacheObserved("exact", "bypass", 0, 0)
	default:
		meta.Cache = "miss"
		if entry, hit = s.opts.Exact.Get(key); hit {
			meta.Cache = "hit_exact"
			s.cacheObserved("exact", "hit", entry.CostUSD, time.Duration(entry.LatencyMS)*time.Millisecond)
		} else {
			if s.opts.Exact.Enabled() {
				s.cacheObserved("exact", "miss", 0, 0)
			}
			if s.opts.Semantic != nil && semEligible {
				_, csp := proxyTracer.Start(ctx, "cache.semantic_lookup")
				m, vec, _, err := s.opts.Semantic.Lookup(ctx, bucket, semQuery)
				csp.End()
				semVec = vec
				switch {
				case err != nil:
					s.log.Warn("semantic cache lookup failed", "error", err, "request_id", requestID(ctx))
				case m != nil:
					entry, hit = m.Entry, true
					meta.Cache, meta.CacheSimilarity = "hit_semantic", m.Similarity
					s.cacheObserved("semantic", "hit", entry.CostUSD, time.Duration(entry.LatencyMS)*time.Millisecond)
				default:
					s.cacheObserved("semantic", "miss", 0, 0)
				}
			}
		}
	}

	// --- upstream ---------------------------------------------------------------
	if hit {
		resp = &providers.Response{Model: entry.Model, Text: entry.Text, StopReason: entry.StopReason,
			Provider: entry.Provider, Route: entry.Route}
	} else {
		start := time.Now()
		var err error
		resp, err = s.opts.Provider.Complete(ctx, providers.Request{
			Model:     req.Model,
			System:    inTx.System,
			Messages:  inTx.Messages, // masked payload, not the original
			MaxTokens: req.MaxTokens,
		})
		upstream = time.Since(start)
		meta.Timing.UpstreamMS = upstream.Milliseconds()
		if err != nil {
			var re *providers.RouteError
			if errors.As(err, &re) {
				meta.Attempts = re.Attempts
			}
			var ue *providers.UpstreamError
			status := http.StatusBadGateway
			if errors.As(err, &ue) {
				status = ue.StatusCode
			}
			s.log.Error("upstream call failed",
				"error", err, "model", req.Model, "request_id", requestID(ctx))
			finish("error")
			writeErrorDetails(w, status, "upstream_error", err.Error(), meta)
			return
		}
		fresh = true
		cost = s.opts.Pricing.Cost(resp.Model, resp.Usage)
		if s.opts.Metrics != nil {
			s.opts.Metrics.RecordUsage(req.Tenant, resp.Model, resp.Usage, cost)
		}
		s.opts.Auditor.RecordUsage(ctx, inTx, resp.Usage, cost, upstream)
	}
	meta.Attempts = resp.Attempts
	meta.Fallback = len(resp.Attempts) > 1

	// --- parallel semantic verdict ------------------------------------------------
	if pending != nil {
		out := <-pending
		meta.SemanticInbound = out
		meta.JudgeCostUSD += out.CostUSD
		meta.Timing.SemanticMS += out.Duration.Milliseconds()
		if out.Enforced {
			if fresh {
				meta.WastedCostUSD = cost
			}
			meta.OverheadUS = overhead.Microseconds()
			meta.Timing.GuardsUS = meta.OverheadUS
			finish("blocked_semantic")
			writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy",
				out.Finding().Message, meta)
			return
		}
	}

	// --- outbound -------------------------------------------------------------------
	// A cache hit replays through the outbound stage like a fresh completion:
	// the policy may have tightened since the entry was written, and the
	// placeholders must restore against this request's vault.
	outTx := &core.Transaction{
		ID: inTx.ID, Tenant: req.Tenant, Stage: core.StageOutbound,
		Model: resp.Model, System: req.System, Completion: resp.Text,
		Context: req.Context, Usage: resp.Usage, CostUSD: cost,
		Meta: req.Meta, StartedAt: inTx.StartedAt, Vault: vault,
	}
	outDec, _ := s.opts.Engine.Outbound.Execute(ctx, outTx)
	s.opts.Auditor.Record(ctx, outTx, outDec)

	meta.Outbound = outDec
	meta.Degraded = meta.Degraded || outDec.Degraded
	overhead += outDec.Duration
	meta.OverheadUS = overhead.Microseconds()
	meta.Timing.GuardsUS = meta.OverheadUS
	for _, m := range outDec.Mutations {
		if m.Reason == "privacy.restore" {
			meta.Restored = vault.Len()
		}
	}

	if outDec.Blocked() {
		finish("blocked_outbound")
		writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy",
			"the model response was blocked: "+outDec.Reason(), meta)
		return
	}

	if tier.Applies(core.StageOutbound) && tier.Mode() != judge.ModeShadow {
		// The raw completion, before restore: it still carries placeholders,
		// so the classifier sees no more PII than the model did.
		out := s.semantic(ctx, core.StageOutbound, resp.Text, outDec, outTx)
		meta.SemanticOutbound = out
		meta.JudgeCostUSD += out.CostUSD
		meta.Timing.SemanticMS += out.Duration.Milliseconds()
		if out.Enforced {
			finish("blocked_semantic")
			writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy",
				"the model response was blocked: "+out.Finding().Message, meta)
			return
		}
	} else if tier.Applies(core.StageOutbound) {
		go s.semantic(context.WithoutCancel(ctx), core.StageOutbound, resp.Text, outDec, outTx)
	}

	// Store only what passed every outbound check, and only fresh, complete
	// answers. A refusal or a truncated completion is not worth replaying.
	if fresh && cacheOn && !bypass && resp.RefusalCategory == "" && resp.StopReason != "length" &&
		!providers.LooksLikeRefusal(resp.Text) {
		e := cache.Entry{Text: resp.Text, Model: resp.Model, Provider: resp.Provider, Route: resp.Route,
			StopReason: resp.StopReason, Usage: resp.Usage, CostUSD: cost, LatencyMS: upstream.Milliseconds()}
		s.opts.Exact.Put(key, e)
		if semVec != nil {
			s.opts.Semantic.Store(bucket, semQuery, semVec, e)
		}
	}

	outcome := "served"
	if hit {
		outcome = "cached"
	}
	finish(outcome)
	if meta.SemanticInbound != nil && meta.SemanticInbound.Ran {
		span.SetAttributes(attribute.Bool("guardrails.semantic.unsafe", meta.SemanticInbound.Unsafe))
	}
	span.SetAttributes(attribute.String("guardrails.cache", meta.Cache),
		attribute.String("gen_ai.response.model", resp.Model))

	usage := resp.Usage
	if hit {
		usage = core.Usage{} // nothing was consumed upstream for this request
	}
	writeJSON(w, http.StatusOK, chatResponse{
		ID:         inTx.ID,
		Model:      resp.Model,
		Provider:   resp.Provider,
		Route:      resp.Route,
		Content:    outTx.Completion,
		StopReason: resp.StopReason,
		Usage:      usage,
		CostUSD:    cost + meta.JudgeCostUSD,
		Guardrails: meta,
	})
}

// semantic runs the semantic tier and audits an enforced verdict exactly like
// a deterministic block, so the audit trail has one shape for both tiers.
func (s *Server) semantic(ctx context.Context, stage core.Stage, text string, d *core.Decision, tx *core.Transaction) *judge.Outcome {
	ctx, span := proxyTracer.Start(ctx, "guardrails.semantic."+string(stage))
	defer span.End()
	out := s.opts.Tier.Evaluate(ctx, stage, text, d)
	span.SetAttributes(attribute.Bool("guardrails.semantic.ran", out.Ran),
		attribute.String("guardrails.semantic.reason", out.Reason),
		attribute.Bool("guardrails.semantic.unsafe", out.Unsafe))
	if out.Ran && (out.Unsafe || out.Disagreement != "") {
		action := core.ActionFlag
		if out.Enforced {
			action = core.ActionBlock
		}
		s.opts.Auditor.Record(ctx, tx, &core.Decision{
			TransactionID: tx.ID, Stage: stage, Action: action,
			Findings: []core.Finding{out.Finding()}, Duration: out.Duration,
			PolicyVersion: s.opts.Policy.Version,
		})
	}
	return out
}

func (s *Server) cacheObserved(kind, result string, saved float64, dur time.Duration) {
	if s.opts.Metrics != nil {
		s.opts.Metrics.CacheObserved(kind, result, saved, dur)
	}
}

// singleTurn returns the user message of a one-question conversation. The
// semantic cache only serves those: a follow-up means something different in
// every conversation, and its embedding alone cannot tell.
func singleTurn(msgs []core.Message) (string, bool) {
	var user string
	n := 0
	for _, m := range msgs {
		switch m.Role {
		case core.RoleUser:
			n++
			user = m.Content
		case core.RoleAssistant, core.RoleTool:
			return "", false
		}
	}
	return user, n == 1
}
