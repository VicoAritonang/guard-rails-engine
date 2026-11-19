// Package guards builds the complete engine: every guard the project ships,
// wired from policy. The gateway, the CLI and the evaluation harness use it.
//
// The embeddable library does not: it assembles only the modules a program
// asks for (see internal/guards/registry and pkg/guardrails/engine), so that
// importing it does not compile guards the program never runs.
//
// Construction is explicit rather than init()-based registration. Import side
// effects make it possible to silently lose a guard by dropping an import, and
// "the detector was never loaded" is the worst class of guardrail bug: the
// system reports success while protecting nothing.
package guards

import (
	"go.vicoworks.com/guard-rails/config"
	"go.vicoworks.com/guard-rails/internal/agent"
	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/guards/inbound"
	"go.vicoworks.com/guard-rails/internal/guards/outbound"
	"go.vicoworks.com/guard-rails/internal/guards/registry"
	"go.vicoworks.com/guard-rails/internal/guards/rules"
	"go.vicoworks.com/guard-rails/internal/guards/runtime"
	"go.vicoworks.com/guard-rails/internal/guards/toolresult"
	"go.vicoworks.com/guard-rails/internal/media"
	"go.vicoworks.com/guard-rails/internal/prices"
)

// Deps are the collaborators guards need beyond their own config.
type Deps struct {
	// Secret keys the redaction vault and the audit-log fingerprints. It must
	// be stable across the fleet, or the same value masked on two instances
	// produces two different placeholders.
	Secret  []byte
	Pricing *prices.Table
	// Media are the model-backed readers for attachments (OCR, speech to
	// text, image safety). All optional: without them documents and image
	// metadata are still read, and what cannot be read is reported.
	Media media.Backends
}

// Modules lists every module the project ships.
func Modules(b media.Backends) []registry.Module {
	return []registry.Module{
		inbound.Module(),
		outbound.Module(),
		toolresult.Module(),
		rules.Module(),
		runtime.Module(),
		media.Module(b),
	}
}

// Engine holds the four stage pipelines.
type Engine struct {
	*registry.Engine
}

// Build constructs every guard and assembles the stage pipelines. Every
// guard name in the policy must be one this build provides.
func Build(pol *config.Policy, deps Deps, opts ...core.PipelineOption) (*Engine, error) {
	e, err := registry.Assemble(pol, registry.Deps{Secret: deps.Secret, Pricing: deps.Pricing},
		Modules(deps.Media), opts...)
	if err != nil {
		return nil, err
	}
	return &Engine{e}, nil
}

// Media exposes the ingest processor, for capability reporting.
func (e *Engine) Media() *media.Processor {
	p, _ := e.Ingestor().(*media.Processor)
	return p
}

// ToolEvaluator returns the tool-safety evaluator, or nil when the policy has
// no tool_safety guard. The agent broker is built from this rather than from a
// second read of the policy, so the /v1/agent endpoints and the runtime
// pipeline can never disagree about what a session is allowed to do.
func (e *Engine) ToolEvaluator() *agent.Evaluator { return runtime.Evaluator(e.Engine) }

// Known reports whether a guard name can be constructed.
func Known(name string) bool {
	_, ok := config.GuardStage(name)
	return ok
}
