// Package guards wires policy into concrete guard instances.
//
// Construction is explicit rather than init()-based registration. Import side
// effects make it possible to silently lose a guard by dropping an import, and
// "the detector was never loaded" is the worst class of guardrail bug: the
// system reports success while protecting nothing.
package guards

import (
	"fmt"
	"sort"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/agent"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/guards/inbound"
	"github.com/vicoaritonang/guardrails-engine/internal/guards/outbound"
	"github.com/vicoaritonang/guardrails-engine/internal/guards/runtime"
	"github.com/vicoaritonang/guardrails-engine/internal/guards/toolresult"
	"github.com/vicoaritonang/guardrails-engine/internal/telemetry"
)

// Deps are the collaborators guards need beyond their own config.
type Deps struct {
	// Secret keys the redaction vault and the audit-log fingerprints. It must
	// be stable across the fleet, or the same value masked on two instances
	// produces two different placeholders.
	Secret  []byte
	Pricing *telemetry.Pricing
}

// factory builds one guard from its config.
type factory func(cfg *config.GuardConfig, deps Deps) (core.Guard, error)

var factories = map[string]factory{
	config.GuardPII: func(c *config.GuardConfig, d Deps) (core.Guard, error) {
		return inbound.NewPII(c, d.Secret)
	},
	config.GuardSecrets: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return inbound.NewSecrets(c)
	},
	config.GuardInjection: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return inbound.NewInjection(c)
	},
	config.GuardTopic: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return inbound.NewTopic(c)
	},
	config.GuardQuota: func(c *config.GuardConfig, d Deps) (core.Guard, error) {
		return inbound.NewQuota(c, d.Pricing)
	},
	config.GuardLoop: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return runtime.NewLoopBreaker(c)
	},
	config.GuardToolPolicy: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return runtime.NewToolPolicy(c)
	},
	config.GuardToolSafety: func(c *config.GuardConfig, d Deps) (core.Guard, error) {
		return runtime.NewToolSafety(c, d.Secret)
	},
	config.GuardToolResult: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return toolresult.New(c)
	},
	config.GuardBudget: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return runtime.NewBudgetBreaker(c)
	},
	config.GuardSchema: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return outbound.NewSchema(c)
	},
	config.GuardLeak: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return outbound.NewLeak(c)
	},
	config.GuardGrounding: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return outbound.NewGrounding(c)
	},
	config.GuardFormat: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return outbound.NewFormat(c)
	},
	config.GuardRestore: func(c *config.GuardConfig, _ Deps) (core.Guard, error) {
		return outbound.NewRestore(c)
	},
}

// Engine holds the four stage pipelines.
type Engine struct {
	Inbound    *core.Pipeline
	Runtime    *core.Pipeline
	ToolResult *core.Pipeline
	Outbound   *core.Pipeline

	policy *config.Policy

	// toolSafety is kept by reference so the agent broker and the catalog
	// endpoint share the guard's configuration instead of rebuilding it from
	// policy a second time. Two constructions would be two chances to diverge,
	// and the divergence would be an endpoint that permits what the pipeline
	// refuses.
	toolSafety *runtime.ToolSafety
}

// Build constructs every enabled guard and assembles the stage pipelines.
//
// Guards are constructed even when disabled, so that a bad parameter in a
// switched-off block still fails at startup. Discovering a malformed policy at
// the moment an operator enables a guard during an incident is exactly the
// wrong time.
func Build(pol *config.Policy, deps Deps, opts ...core.PipelineOption) (*Engine, error) {
	if pol == nil {
		return nil, fmt.Errorf("guards: nil policy")
	}
	if len(deps.Secret) == 0 {
		return nil, fmt.Errorf("guards: Deps.Secret is required (it keys the redaction vault)")
	}
	if deps.Pricing == nil {
		deps.Pricing = telemetry.NewPricing()
	}

	// Reject unknown guard names rather than ignoring them: a typo'd guard in
	// a policy file is a coverage gap the operator believes they have closed.
	names := make([]string, 0, len(pol.Guards))
	for name := range pol.Guards {
		if _, ok := factories[name]; !ok {
			return nil, fmt.Errorf("guards: policy references unknown guard %q (known: %v)",
				name, knownNames())
		}
		names = append(names, name)
	}
	sort.Strings(names)

	byStage := map[core.Stage][]core.Guard{}
	var toolSafety *runtime.ToolSafety
	for _, name := range names {
		g, err := factories[name](pol.Guards[name], deps)
		if err != nil {
			return nil, fmt.Errorf("guards: %s: %w", name, err)
		}
		declared, _ := config.GuardStage(name)
		if string(g.Stage()) != declared {
			return nil, fmt.Errorf("guards: %s reports stage %q but the registry declares %q",
				name, g.Stage(), declared)
		}
		byStage[g.Stage()] = append(byStage[g.Stage()], g)
		if ts, ok := g.(*runtime.ToolSafety); ok {
			toolSafety = ts
		}
	}

	e := &Engine{policy: pol, toolSafety: toolSafety}
	var err error
	if e.Inbound, err = core.NewPipeline(core.StageInbound, byStage[core.StageInbound], pol, opts...); err != nil {
		return nil, err
	}
	if e.Runtime, err = core.NewPipeline(core.StageRuntime, byStage[core.StageRuntime], pol, opts...); err != nil {
		return nil, err
	}
	if e.ToolResult, err = core.NewPipeline(core.StageToolResult, byStage[core.StageToolResult], pol, opts...); err != nil {
		return nil, err
	}
	if e.Outbound, err = core.NewPipeline(core.StageOutbound, byStage[core.StageOutbound], pol, opts...); err != nil {
		return nil, err
	}
	return e, nil
}

// Pipeline returns the pipeline for a stage.
func (e *Engine) Pipeline(s core.Stage) (*core.Pipeline, error) {
	switch s {
	case core.StageInbound:
		return e.Inbound, nil
	case core.StageRuntime:
		return e.Runtime, nil
	case core.StageToolResult:
		return e.ToolResult, nil
	case core.StageOutbound:
		return e.Outbound, nil
	}
	return nil, fmt.Errorf("guards: unknown stage %q", s)
}

// Policy exposes the effective policy for introspection endpoints.
func (e *Engine) Policy() *config.Policy { return e.policy }

// ToolEvaluator returns the tool-safety evaluator, or nil when the guard is
// disabled. The agent broker is built from this rather than from a second read
// of the policy, so the /v1/agent endpoints and the runtime pipeline can never
// disagree about what a session is allowed to do.
func (e *Engine) ToolEvaluator() *agent.Evaluator {
	if e.toolSafety == nil {
		return nil
	}
	return e.toolSafety.Evaluator()
}

func knownNames() []string {
	out := make([]string, 0, len(factories))
	for n := range factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Known reports whether a guard name can be constructed.
func Known(name string) bool {
	_, ok := factories[name]
	return ok
}
