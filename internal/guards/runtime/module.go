package runtime

import (
	"go.vicoworks.com/guard-rails/config"
	"go.vicoworks.com/guard-rails/internal/agent"
	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/guards/registry"
)

// Module provides the agent-loop guards.
func Module() registry.Module {
	return registry.Module{Name: "runtime", Guards: map[string]registry.Factory{
		config.GuardLoop: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewLoopBreaker(c)
		},
		config.GuardToolPolicy: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewToolPolicy(c)
		},
		config.GuardToolSafety: func(c *config.GuardConfig, d registry.Deps) (core.Guard, error) {
			return NewToolSafety(c, d.Secret)
		},
		config.GuardBudget: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewBudgetBreaker(c)
		},
	}}
}

// Evaluator returns the tool-safety evaluator of an assembled engine, or nil
// when it has no tool_safety guard.
func Evaluator(e *registry.Engine) *agent.Evaluator {
	ts, ok := e.Guard(config.GuardToolSafety).(*ToolSafety)
	if !ok {
		return nil
	}
	return ts.Evaluator()
}
