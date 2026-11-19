package toolresult

import (
	"go.vicoworks.com/guard-rails/config"
	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/guards/registry"
)

// Module provides the tool-result guard.
func Module() registry.Module {
	return registry.Module{Name: "tool_result", Guards: map[string]registry.Factory{
		config.GuardToolResult: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return New(c)
		},
	}}
}
