package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/agent"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// ToolSafety applies the tool-level control plane to a proposed call.
//
// It is a thin adapter on purpose. Every rule it enforces lives in
// internal/agent, which is also what the /v1/agent/execute broker calls, so a
// caller that validates through the gateway and a caller that executes through
// the broker get the same answer from the same code. Two implementations of
// "may this tool run" is how a system ends up with a validate endpoint that
// says no and an execute endpoint that says yes.
//
// It fails closed. The failure mode of an open tool rail is an executed action.
type ToolSafety struct {
	cfg  *config.GuardConfig
	eval *agent.Evaluator
}

// NewToolSafety builds the guard from policy.
func NewToolSafety(cfg *config.GuardConfig, secret []byte) (*ToolSafety, error) {
	cat, err := agent.DefaultCatalog()
	if err != nil {
		return nil, err
	}
	if path := cfg.String("catalog_file", ""); path != "" {
		if cat, err = agent.LoadCatalog(path); err != nil {
			return nil, fmt.Errorf("tool_safety: %w", err)
		}
	}

	maxTier, err := agent.ParseTier(cfg.String("max_tier", "T4"))
	if err != nil {
		return nil, fmt.Errorf("tool_safety: %w", err)
	}

	var disabled agent.Control
	for _, name := range cfg.Strings("disabled_controls") {
		c, err := agent.ParseControl(name)
		if err != nil {
			return nil, fmt.Errorf("tool_safety: %w", err)
		}
		disabled |= c
	}

	opts := agent.Options{
		Catalog:         cat,
		EgressAllowlist: cfg.Strings("egress_allowlist"),
		MaxTier:         maxTier,
		Disabled:        disabled,
	}
	// A secret too weak to sign approvals leaves the approver nil rather than
	// failing startup. That is the safe direction of failure: with no approver
	// the approval control cannot be satisfied, so every T4 tool is refused
	// with a finding that names the remedy. Failing startup instead would take
	// down a deployment whose T0-T3 traffic is fine, and -- worse -- would
	// tempt whoever is paged into lowering max_tier to get service back.
	ttl := time.Duration(cfg.Int("approval_ttl_seconds", 600)) * time.Second
	if app, aerr := agent.NewApprover(secret, ttl); aerr == nil {
		opts.Approver = app
	}

	ev, err := agent.NewEvaluator(opts)
	if err != nil {
		return nil, fmt.Errorf("tool_safety: %w", err)
	}
	return &ToolSafety{cfg: cfg, eval: ev}, nil
}

func (g *ToolSafety) Name() string      { return config.GuardToolSafety }
func (g *ToolSafety) Stage() core.Stage { return core.StageRuntime }

// Evaluator exposes the configured evaluator so the broker and the catalog
// endpoint share this guard's configuration rather than reconstructing it.
func (g *ToolSafety) Evaluator() *agent.Evaluator { return g.eval }

func (g *ToolSafety) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	if len(tx.ToolCalls) == 0 {
		return res, nil
	}

	// The approval token and idempotency key ride in transaction metadata
	// rather than in the tool call itself, because they are properties of the
	// request the runtime is making, not arguments the model chose. A model
	// that could put its own approval token in a tool call would be approving
	// its own actions.
	idem := metaString(tx, "idempotency_key")
	token := metaString(tx, "approval_token")
	dryRun := metaBool(tx, "dry_run")

	session := tx.Session
	if session == nil {
		session = &core.SessionState{TraceID: tx.ID, Step: tx.Step}
	}

	res.Metrics = map[string]float64{}
	highest := 0

	for i, call := range tx.ToolCalls {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		a := g.eval.Assess(agent.Request{
			Trace:          tx.ID,
			Call:           call,
			Session:        session,
			IdempotencyKey: idem,
			ApprovalToken:  token,
			DryRun:         dryRun,
		})
		field := fmt.Sprintf("tool_calls[%d].raw", i)
		for _, f := range a.Findings {
			f.Spans = []core.Span{{Field: field}}
			res.Findings = append(res.Findings, f)
		}
		if t, ok := g.eval.Catalog().Lookup(call.Name); ok && int(t.Tier()) > highest {
			highest = int(t.Tier())
		}
	}

	res.Metrics["tool.max_tier"] = float64(highest)
	res.Metrics["tool.calls"] = float64(len(tx.ToolCalls))
	return res, nil
}

func metaString(tx *core.Transaction, key string) string {
	if tx.Meta == nil {
		return ""
	}
	s, _ := tx.Meta[key].(string)
	return s
}

func metaBool(tx *core.Transaction, key string) bool {
	if tx.Meta == nil {
		return false
	}
	b, _ := tx.Meta[key].(bool)
	return b
}
