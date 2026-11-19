package inbound

import (
	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
)

// Module provides the inbound text guards.
func Module() registry.Module {
	return registry.Module{Name: "inbound", Guards: map[string]registry.Factory{
		config.GuardPII: func(c *config.GuardConfig, d registry.Deps) (core.Guard, error) {
			return NewPII(c, d.Secret)
		},
		config.GuardSecrets: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewSecrets(c)
		},
		config.GuardInjection: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewInjection(c)
		},
		config.GuardTopic: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewTopic(c)
		},
		config.GuardQuota: func(c *config.GuardConfig, d registry.Deps) (core.Guard, error) {
			return NewQuota(c, d.Pricing)
		},
	}}
}
