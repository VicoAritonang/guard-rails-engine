// Package registry assembles stage pipelines from modules: named sets of
// guard factories that a build includes or leaves out.
//
// It imports no guard. That is the point of it: the embeddable library
// compiles only the guards a program asked for, so a service that masks PII
// does not link a PDF parser. Each guard package exports its own Module, and
// internal/guards combines all of them for the gateway.
//
// Modules are passed explicitly rather than registered from init(), for the
// reason internal/guards gives: a guard that silently fails to load is the
// worst class of guardrail bug.
package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/prices"
)

// Deps are the collaborators guards need beyond their own config.
type Deps struct {
	// Secret keys the redaction vault and the audit-log fingerprints. It must
	// be stable across the fleet, or the same value masked on two instances
	// produces two different placeholders.
	Secret []byte
	// Pricing prices the quota guard's estimate. Nil uses the built-in table.
	Pricing *prices.Table
}

// Factory builds one guard from its config.
type Factory func(cfg *config.GuardConfig, deps Deps) (core.Guard, error)

// Module is a set of guards that a build includes as a unit.
type Module struct {
	Name   string
	Guards map[string]Factory
	// Ingestor, when set, builds the attachment ingest step that runs before
	// the inbound and tool-result guards. At most one module may set it.
	Ingestor func(pol *config.Policy) (core.Ingestor, error)

	err error
}

// Select narrows a module to the named guards. No names keeps all of them.
// An unknown name is reported when the module is assembled, so a typo fails
// at startup instead of leaving the guard out.
func Select(m Module, names ...string) Module {
	if len(names) == 0 || m.err != nil {
		return m
	}
	out := Module{Name: m.Name, Guards: make(map[string]Factory, len(names)), Ingestor: m.Ingestor}
	for _, n := range names {
		f, ok := m.Guards[n]
		if !ok {
			out.err = fmt.Errorf("module %s has no guard %q (it has: %s)", m.Name, n, strings.Join(m.names(), ", "))
			return out
		}
		out.Guards[n] = f
	}
	return out
}

// Merge combines modules into one under a new name.
func Merge(name string, mods ...Module) Module {
	out := Module{Name: name, Guards: map[string]Factory{}}
	for _, m := range mods {
		if m.err != nil {
			out.err = m.err
			return out
		}
		for n, f := range m.Guards {
			out.Guards[n] = f
		}
		if m.Ingestor != nil {
			out.Ingestor = m.Ingestor
		}
	}
	return out
}

func (m Module) names() []string {
	out := make([]string, 0, len(m.Guards))
	for n := range m.Guards {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Engine holds the four stage pipelines.
type Engine struct {
	Inbound    *core.Pipeline
	Runtime    *core.Pipeline
	ToolResult *core.Pipeline
	Outbound   *core.Pipeline

	policy   *config.Policy
	guards   map[string]core.Guard
	provides map[core.Stage]bool
	ingestor core.Ingestor
}

// Assemble constructs the guards the modules provide and builds the stage
// pipelines.
//
// Guards are constructed even when disabled, so that a bad parameter in a
// switched-off block still fails at startup. Discovering a malformed policy at
// the moment an operator enables a guard during an incident is exactly the
// wrong time.
//
// A policy entry for a guard no module provides is skipped: the program chose
// not to compile it, and the default policy configures every guard. A name
// the engine does not know at all is still an error, since a typo'd guard in
// a policy file is a coverage gap the operator believes they have closed.
func Assemble(pol *config.Policy, deps Deps, mods []Module, opts ...core.PipelineOption) (*Engine, error) {
	if pol == nil {
		return nil, errors.New("guards: nil policy")
	}
	if len(deps.Secret) == 0 {
		return nil, errors.New("guards: Deps.Secret is required (it keys the redaction vault)")
	}
	if deps.Pricing == nil {
		deps.Pricing = prices.New()
	}

	factories := map[string]Factory{}
	owner := map[string]string{}
	var ingest func(*config.Policy) (core.Ingestor, error)
	ingestOwner := ""
	for _, m := range mods {
		if m.err != nil {
			return nil, fmt.Errorf("guards: %w", m.err)
		}
		for name, f := range m.Guards {
			if _, ok := config.GuardStage(name); !ok {
				return nil, fmt.Errorf("guards: module %s provides unknown guard %q", m.Name, name)
			}
			if prev, dup := owner[name]; dup {
				return nil, fmt.Errorf("guards: guard %q is provided by both %s and %s", name, prev, m.Name)
			}
			factories[name], owner[name] = f, m.Name
		}
		if m.Ingestor != nil {
			if ingest != nil {
				return nil, fmt.Errorf("guards: both %s and %s provide an ingest step", ingestOwner, m.Name)
			}
			ingest, ingestOwner = m.Ingestor, m.Name
		}
	}

	names := make([]string, 0, len(pol.Guards))
	for name := range pol.Guards {
		if _, ok := config.GuardStage(name); !ok {
			known := config.KnownGuards()
			sort.Strings(known)
			return nil, fmt.Errorf("guards: policy references unknown guard %q (known: %v)", name, known)
		}
		if _, ok := factories[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	e := &Engine{policy: pol, guards: map[string]core.Guard{}, provides: map[core.Stage]bool{}}
	for name := range factories {
		stage, _ := config.GuardStage(name)
		e.provides[core.Stage(stage)] = true
	}

	byStage := map[core.Stage][]core.Guard{}
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
		e.guards[name] = g
	}

	// The ingest step is installed whether or not the media guards are
	// enabled. Disabling them silences the file-specific findings; it must not
	// turn a PDF into something the injection guard never reads.
	ingestOpts := opts
	if ingest != nil {
		in, err := ingest(pol)
		if err != nil {
			return nil, fmt.Errorf("guards: %w", err)
		}
		e.ingestor = in
		ingestOpts = append(append([]core.PipelineOption{}, opts...), core.WithIngestor(in))
	}

	var err error
	if e.Inbound, err = core.NewPipeline(core.StageInbound, byStage[core.StageInbound], pol, ingestOpts...); err != nil {
		return nil, err
	}
	if e.Runtime, err = core.NewPipeline(core.StageRuntime, byStage[core.StageRuntime], pol, opts...); err != nil {
		return nil, err
	}
	if e.ToolResult, err = core.NewPipeline(core.StageToolResult, byStage[core.StageToolResult], pol, ingestOpts...); err != nil {
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

// Guard returns a constructed guard by name, or nil when no module provided it.
func (e *Engine) Guard(name string) core.Guard { return e.guards[name] }

// Guards lists the constructed guards, enabled or not, sorted by name.
func (e *Engine) Guards() []string {
	out := make([]string, 0, len(e.guards))
	for n := range e.guards {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Provides reports whether any loaded module has a guard for the stage. A
// stage nothing could check is a wiring mistake, unlike a stage whose guards
// the policy switched off.
func (e *Engine) Provides(s core.Stage) bool { return e.provides[s] }

// Ingestor returns the ingest step, or nil when no module provides one.
func (e *Engine) Ingestor() core.Ingestor { return e.ingestor }
