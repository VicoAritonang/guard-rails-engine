// Package ruleguard is the rules module of the embeddable engine: keyword,
// regex and URL rules you write in the policy, on every stage they apply to.
//
//	g, err := engine.New(engine.Options{Policy: pol}, textguard.Module(), ruleguard.Module())
//
// The rules themselves live in the policy (custom_rules*, url_filter*); see
// config/policies/balanced.yaml. The module compiles the guards that read
// them, and like the rest of the engine it uses the standard library only.
package ruleguard

import (
	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
	"go.vicoworks.com/guard-rails-engine/internal/guards/rules"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/engine"
)

// Guard names, for Module.
const (
	CustomRules           = config.GuardCustomRules
	CustomRulesOutbound   = config.GuardCustomRulesOutbound
	CustomRulesToolResult = config.GuardCustomRulesToolResult
	URLFilter             = config.GuardURLFilter
	URLFilterOutbound     = config.GuardURLFilterOutbound
)

// Module returns the rule guards, or only the named ones. An unknown name
// makes engine.New fail.
func Module(guards ...string) engine.Module {
	return registry.Select(registry.Merge("ruleguard", rules.Module()), guards...)
}
