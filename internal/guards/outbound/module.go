package outbound

import (
	"go.vicoworks.com/guard-rails/config"
	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/guards/registry"
)

// Module provides the outbound guards.
func Module() registry.Module {
	return registry.Module{Name: "outbound", Guards: map[string]registry.Factory{
		config.GuardSchema: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewSchema(c)
		},
		config.GuardLeak: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewLeak(c)
		},
		config.GuardGrounding: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewGrounding(c)
		},
		config.GuardFormat: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewFormat(c)
		},
		config.GuardRestore: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewRestore(c)
		},
	}}
}
