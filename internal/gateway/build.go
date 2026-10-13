// Package gateway assembles the upstream side of the engine -- providers,
// router, response cache and semantic tier -- from configuration.
//
// It exists so the server and the experiment runner build these from one
// code path. An experiment that wires its own router is measuring a gateway
// nobody deploys.
package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/cache"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/judge"
	"github.com/vicoaritonang/guardrails-engine/internal/providers"
	"github.com/vicoaritonang/guardrails-engine/internal/telemetry"
)

// Upstream bundles everything on the provider side of the gateway.
type Upstream struct {
	Router   *providers.Router
	Exact    *cache.Exact
	Semantic *cache.Semantic
	Tier     *judge.Tier
}

// BuildRouter creates every provider that has credentials and puts a router
// in front of them.
func BuildRouter(cfg *config.Config, logger *slog.Logger, obs providers.UpstreamObserver) (*providers.Router, error) {
	if logger == nil {
		logger = slog.Default()
	}
	ps := map[string]providers.Provider{"mock": providers.NewMock(providers.MockOptions{})}

	// The configured default provider is always built, credentials or not:
	// the SDKs can resolve keys from sources this process cannot see, and
	// failing here would break deployments that rely on that.
	want := map[string]bool{cfg.Provider: true}
	if cfg.OpenAIAPIKey != "" {
		want["openai"] = true
	}
	if cfg.GroqAPIKey != "" {
		want["groq"] = true
	}
	if cfg.AnthropicAPIKey != "" {
		want["anthropic"] = true
	}
	if cfg.ReplayPath != "" {
		want["replay"] = true
	}
	for name := range want {
		if name == "mock" {
			continue
		}
		p, err := providers.New(name, providerOptions(cfg))
		if err != nil {
			if name == cfg.Provider {
				return nil, err
			}
			logger.Warn("provider not available", "provider", name, "error", err)
			continue
		}
		ps[name] = p
	}

	var catalog *providers.Catalog
	if cfg.ModelsPath != "" {
		c, err := providers.LoadCatalog(cfg.ModelsPath)
		if err != nil {
			return nil, err
		}
		catalog = c
	}
	r, err := providers.NewRouter(providers.RouterOptions{
		Providers:       ps,
		Catalog:         catalog,
		DefaultProvider: cfg.Provider,
		Observer:        obs,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("upstream router ready",
		"providers", r.Providers(), "routes", len(r.Routes()), "default_provider", cfg.Provider)
	if u := r.Unavailable(); len(u) > 0 {
		logger.Warn("catalog routes without credentials were dropped", "routes", u)
	}
	return r, nil
}

func providerOptions(cfg *config.Config) providers.Options {
	// The default model applies only to the default provider. Handing
	// "gpt-5" to Groq because it was the global default is the coupling bug
	// defaultModelFor exists to prevent.
	model := func(p string) string {
		if p == cfg.Provider {
			return cfg.DefaultModel
		}
		return ""
	}
	effort := func(p string) string {
		if p == cfg.Provider {
			return cfg.Effort
		}
		return ""
	}
	return providers.Options{
		OpenAI: providers.OpenAIOptions{
			APIKey: cfg.OpenAIAPIKey, BaseURL: cfg.OpenAIBaseURL,
			Organization: cfg.OpenAIOrganization, Project: cfg.OpenAIProject,
			DefaultModel: model("openai"), DefaultMaxTokens: cfg.DefaultMaxTokens,
			Timeout: cfg.RequestTimeout, ReasoningEffort: effort("openai"),
			MaxRetries: cfg.UpstreamMaxRetries,
		},
		Groq: providers.OpenAIOptions{
			APIKey: cfg.GroqAPIKey, BaseURL: cfg.GroqBaseURL,
			DefaultModel: model("groq"), Timeout: cfg.RequestTimeout,
			ReasoningEffort: effort("groq"), MaxRetries: cfg.UpstreamMaxRetries,
		},
		Anthropic: providers.AnthropicOptions{
			APIKey: cfg.AnthropicAPIKey, BaseURL: cfg.AnthropicBaseURL,
			DefaultModel: model("anthropic"), DefaultMaxTokens: cfg.DefaultMaxTokens,
			Timeout: cfg.RequestTimeout, Effort: effort("anthropic"),
		},
		ReplayPath: cfg.ReplayPath,
	}
}

// BuildClassifier constructs one semantic-tier classifier by name.
//
// Names are catalog aliases ("prompt-guard-86m", "safeguard-20b", "gpt-5-nano")
// plus the special name "moderation". An alias whose tier is "classifier" and
// whose upstream is a Prompt Guard model gets the probability parser; every
// other alias is driven as a policy judge.
func BuildClassifier(name string, r *providers.Router, cfg *config.Config, pricing *telemetry.Pricing) (judge.Classifier, error) {
	if name == "moderation" || name == "openai-moderation" {
		m, err := providers.NewModeration(cfg.OpenAIAPIKey)
		if err != nil {
			return nil, err
		}
		return &judge.ModerationClassifier{Client: m}, nil
	}
	chain, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	if strings.Contains(chain[0].Model, "prompt-guard") {
		return &judge.PromptGuard{Router: r, Route: name, Threshold: 0.5, Pricing: pricing, WindowChars: 1500}, nil
	}
	return &judge.PolicyJudge{Router: r, Route: name, Pricing: pricing}, nil
}

// BuildTier constructs the semantic tier from configuration.
func BuildTier(cfg *config.Config, r *providers.Router, pricing *telemetry.Pricing, obs judge.Observer, logger *slog.Logger) (*judge.Tier, error) {
	mode, err := judge.ParseMode(cfg.JudgeMode)
	if err != nil {
		return nil, err
	}
	if mode == judge.ModeOff {
		return judge.NewTier(judge.Options{Mode: judge.ModeOff})
	}
	var cls []judge.Classifier
	for _, name := range cfg.JudgeClassifiers {
		c, err := BuildClassifier(name, r, cfg, pricing)
		if err != nil {
			logger.Warn("semantic classifier unavailable", "classifier", name, "error", err)
			continue
		}
		cls = append(cls, c)
	}
	if len(cls) == 0 {
		return nil, fmt.Errorf("GUARDRAILS_JUDGE_MODE=%s but no classifier could be built: %w", mode, judge.ErrNoClassifiers)
	}
	var stages []core.Stage
	for _, s := range cfg.JudgeStages {
		st := core.Stage(s)
		if st != core.StageInbound && st != core.StageOutbound {
			return nil, fmt.Errorf("GUARDRAILS_JUDGE_STAGES: %q must be inbound or outbound", s)
		}
		stages = append(stages, st)
	}
	return judge.NewTier(judge.Options{
		Mode: mode, Classifiers: cls, EscalateAbove: cfg.JudgeEscalateAbove,
		Combine: cfg.JudgeCombine, Timeout: cfg.JudgeTimeout, FailClosed: cfg.JudgeFailClosed,
		Parallel: cfg.JudgeParallel, Stages: stages, Observer: obs,
	})
}

// BuildCaches constructs the exact and (optionally) semantic caches.
func BuildCaches(cfg *config.Config, logger *slog.Logger) (*cache.Exact, *cache.Semantic) {
	exact := cache.NewExact(cfg.CacheSize, cfg.CacheTTL)
	if !cfg.SemanticCache {
		return exact, nil
	}
	emb, err := providers.NewOpenAIEmbedder(cfg.OpenAIAPIKey, "")
	if err != nil {
		logger.Warn("semantic cache disabled", "error", err)
		return exact, nil
	}
	return exact, cache.NewSemantic(emb, cache.SemanticOptions{Threshold: cfg.SemanticCacheThreshold, TTL: cfg.CacheTTL})
}

// JudgeObserver adapts telemetry.Metrics and the logger to judge.Observer.
// It lives here rather than in telemetry because judge imports telemetry for
// pricing, and the reverse import would be a cycle.
type JudgeObserver struct {
	Metrics *telemetry.Metrics
	Logger  *slog.Logger
}

func (o JudgeObserver) JudgeObserved(stage core.Stage, v judge.Verdict) {
	verdict := "safe"
	switch {
	case v.Error != "":
		verdict = "error"
	case v.Unsafe:
		verdict = "unsafe"
	}
	if o.Metrics != nil {
		o.Metrics.JudgeObserved(string(stage), v.Classifier, verdict, v.Latency, v.CostUSD)
	}
	if v.Error != "" && o.Logger != nil {
		o.Logger.Warn("semantic classifier failed", "classifier", v.Classifier, "stage", stage, "error", v.Error)
	}
}

func (o JudgeObserver) TierDecided(stage core.Stage, mode judge.Mode, out *judge.Outcome) {
	outcome := "skipped"
	switch {
	case out.Ran && out.Degraded:
		outcome = "degraded"
	case out.Ran && out.Unsafe:
		outcome = "unsafe"
	case out.Ran:
		outcome = "safe"
	}
	if o.Metrics != nil {
		o.Metrics.TierDecided(string(stage), string(mode), out.Reason, outcome, out.Disagreement)
	}
	if out.Ran && o.Logger != nil {
		o.Logger.Info("semantic tier decision",
			"event", "guardrail.semantic", "stage", stage, "mode", mode, "reason", out.Reason,
			"unsafe", out.Unsafe, "enforced", out.Enforced, "disagreement", out.Disagreement,
			"heuristic_score", out.Heuristic, "duration_ms", out.Duration.Milliseconds(),
			"cost_usd", out.CostUSD)
	}
}

// ErrNoUpstream is returned when proxy mode has nothing to call.
var ErrNoUpstream = errors.New("gateway: no upstream configured")
