package inbound

import (
	"context"
	"fmt"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/telemetry"
	"github.com/vicoaritonang/guardrails-engine/internal/tokenize"
)

// Quota enforces the size and cost envelope of a single request.
//
// This is the guard that stops a bill, not an attack. A prompt-injection
// detector protects the model's behaviour; this protects the operator's budget
// against the far more common failure of a client bug that loops a conversation
// into itself until the context window fills. It fails closed by default,
// because a quota guard that fails open is not a quota guard.
type Quota struct {
	cfg *config.GuardConfig

	maxTokens   int
	maxMessages int
	maxChars    int
	maxCostUSD  float64
	pricing     *telemetry.Pricing
}

func NewQuota(cfg *config.GuardConfig, pricing *telemetry.Pricing) (*Quota, error) {
	q := &Quota{
		cfg:         cfg,
		maxTokens:   cfg.Int("max_input_tokens", 200000),
		maxMessages: cfg.Int("max_messages", 200),
		maxChars:    cfg.Int("max_message_chars", 400000),
		maxCostUSD:  cfg.Float("max_cost_usd", 2.50),
		pricing:     pricing,
	}
	if q.maxTokens <= 0 {
		return nil, fmt.Errorf("quota: max_input_tokens must be positive")
	}
	return q, nil
}

func (g *Quota) Name() string      { return config.GuardQuota }
func (g *Quota) Stage() core.Stage { return core.StageInbound }

func (g *Quota) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	if n := len(tx.Messages); n > g.maxMessages {
		f := core.NewFinding(g.Name(), "max_messages", "quota.messages", core.SeverityHigh, 1.0,
			fmt.Sprintf("conversation has %d messages, limit is %d", n, g.maxMessages))
		f.Meta = map[string]string{"count": fmt.Sprint(n), "limit": fmt.Sprint(g.maxMessages)}
		res.Findings = append(res.Findings, f)
	}

	contents := make([]string, 0, len(tx.Messages))
	for i, m := range tx.Messages {
		if len(m.Content) > g.maxChars {
			f := core.NewFinding(g.Name(), "max_message_chars", "quota.message_size", core.SeverityHigh, 1.0,
				fmt.Sprintf("message %d is %d chars, limit is %d", i, len(m.Content), g.maxChars))
			f.Spans = []core.Span{{Field: fmt.Sprintf("messages[%d].content", i), Start: 0, End: g.maxChars}}
			res.Findings = append(res.Findings, f)
		}
		contents = append(contents, m.Content)
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	est := tokenize.EstimateMessages(tx.System, contents)
	if res.Metrics == nil {
		res.Metrics = map[string]float64{}
	}
	res.Metrics["quota.estimated_input_tokens"] = float64(est)

	if est > g.maxTokens {
		f := core.NewFinding(g.Name(), "max_input_tokens", "quota.tokens", core.SeverityHigh, 1.0,
			fmt.Sprintf("estimated %d input tokens, limit is %d", est, g.maxTokens))
		f.Meta = map[string]string{
			"estimated": fmt.Sprint(est),
			"limit":     fmt.Sprint(g.maxTokens),
			"method":    "heuristic", // exact counts come from the provider post-hoc
		}
		res.Findings = append(res.Findings, f)
	} else if float64(est) > 0.85*float64(g.maxTokens) {
		// Warn before the wall, so an operator sees the trend in telemetry
		// rather than discovering the limit through a wave of 4xx responses.
		f := core.NewFinding(g.Name(), "approaching_token_limit", "quota.tokens_warning", core.SeverityMedium, 0.8,
			fmt.Sprintf("estimated %d input tokens is within 15%% of the %d limit", est, g.maxTokens))
		res.Findings = append(res.Findings, f)
	}

	if g.maxCostUSD > 0 && tx.Model != "" && g.pricing != nil {
		cost := g.pricing.InputCost(tx.Model, est)
		res.Metrics["quota.estimated_input_cost_usd"] = cost
		if cost > g.maxCostUSD {
			f := core.NewFinding(g.Name(), "max_cost", "quota.cost", core.SeverityHigh, 1.0,
				fmt.Sprintf("estimated input cost $%.4f exceeds per-request limit $%.2f", cost, g.maxCostUSD))
			f.Meta = map[string]string{
				"model":     tx.Model,
				"estimated": fmt.Sprintf("%.4f", cost),
				"limit":     fmt.Sprintf("%.2f", g.maxCostUSD),
			}
			res.Findings = append(res.Findings, f)
		}
	}

	return res, nil
}
