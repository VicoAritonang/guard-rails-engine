package runtime

import (
	"context"
	"fmt"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// BudgetBreaker caps the cumulative spend of a single agent trace.
//
// The per-request quota guard bounds one call; this bounds the whole
// trajectory. They are separate guards because they fail differently: a single
// oversized request is a client bug, while a trace that creeps past its budget
// over forty small steps is a working agent doing more work than it was funded
// for -- and the second is far more common and far harder to notice.
//
// Cumulative usage is supplied by the caller in tx.Usage and tx.CostUSD, which
// keeps this guard stateless. Holding the running total inside the guard would
// require sticky routing and defeat horizontal scaling.
type BudgetBreaker struct {
	cfg *config.GuardConfig

	maxCostUSD float64
	maxTokens  int
	warnAt     float64
}

func NewBudgetBreaker(cfg *config.GuardConfig) (*BudgetBreaker, error) {
	g := &BudgetBreaker{
		cfg:        cfg,
		maxCostUSD: cfg.Float("max_trace_cost_usd", 5.0),
		maxTokens:  cfg.Int("max_trace_tokens", 1_000_000),
		warnAt:     cfg.Float("warn_at_fraction", 0.80),
	}
	if g.maxCostUSD <= 0 && g.maxTokens <= 0 {
		return nil, fmt.Errorf("budget_breaker: set at least one of max_trace_cost_usd or max_trace_tokens")
	}
	if g.warnAt <= 0 || g.warnAt >= 1 {
		g.warnAt = 0.80
	}
	return g, nil
}

func (g *BudgetBreaker) Name() string      { return config.GuardBudget }
func (g *BudgetBreaker) Stage() core.Stage { return core.StageRuntime }

func (g *BudgetBreaker) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	res.Metrics = map[string]float64{}

	total := tx.Usage.InputTokens + tx.Usage.OutputTokens +
		tx.Usage.CacheReadTokens + tx.Usage.CacheWriteTokens
	res.Metrics["budget.trace_tokens"] = float64(total)
	res.Metrics["budget.trace_cost_usd"] = tx.CostUSD

	if g.maxTokens > 0 {
		switch {
		case total >= g.maxTokens:
			f := core.NewFinding(g.Name(), "trace_token_limit", "runtime.budget_tokens",
				core.SeverityHigh, 1.0,
				fmt.Sprintf("trace consumed %d tokens, limit is %d", total, g.maxTokens))
			f.Meta = map[string]string{"consumed": fmt.Sprint(total), "limit": fmt.Sprint(g.maxTokens)}
			res.Findings = append(res.Findings, f)
		case float64(total) >= g.warnAt*float64(g.maxTokens):
			res.Findings = append(res.Findings, core.NewFinding(
				g.Name(), "trace_token_warning", "runtime.budget_warning",
				core.SeverityMedium, 0.7,
				fmt.Sprintf("trace has used %d of %d tokens", total, g.maxTokens)))
		}
	}

	if g.maxCostUSD > 0 {
		switch {
		case tx.CostUSD >= g.maxCostUSD:
			f := core.NewFinding(g.Name(), "trace_cost_limit", "runtime.budget_cost",
				core.SeverityCritical, 1.0,
				fmt.Sprintf("trace spent $%.4f, limit is $%.2f", tx.CostUSD, g.maxCostUSD))
			f.Meta = map[string]string{
				"spent": fmt.Sprintf("%.4f", tx.CostUSD),
				"limit": fmt.Sprintf("%.2f", g.maxCostUSD),
				"step":  fmt.Sprint(tx.Step),
			}
			res.Findings = append(res.Findings, f)
		case tx.CostUSD >= g.warnAt*g.maxCostUSD:
			res.Findings = append(res.Findings, core.NewFinding(
				g.Name(), "trace_cost_warning", "runtime.budget_warning",
				core.SeverityMedium, 0.7,
				fmt.Sprintf("trace has spent $%.4f of $%.2f", tx.CostUSD, g.maxCostUSD)))
		}
	}

	_ = ctx
	return res, nil
}
