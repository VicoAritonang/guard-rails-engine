package rules

import (
	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
)

// Module provides the policy-defined keyword, regex and URL rules on every
// stage they apply to.
func Module() registry.Module {
	return registry.Module{Name: "rules", Guards: map[string]registry.Factory{
		config.GuardCustomRules: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return New(config.GuardCustomRules, core.StageInbound, c)
		},
		config.GuardCustomRulesOutbound: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return New(config.GuardCustomRulesOutbound, core.StageOutbound, c)
		},
		config.GuardCustomRulesToolResult: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return New(config.GuardCustomRulesToolResult, core.StageToolResult, c)
		},
		config.GuardURLFilter: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewURLFilter(config.GuardURLFilter, core.StageInbound, c)
		},
		config.GuardURLFilterOutbound: func(c *config.GuardConfig, _ registry.Deps) (core.Guard, error) {
			return NewURLFilter(config.GuardURLFilterOutbound, core.StageOutbound, c)
		},
	}}
}
