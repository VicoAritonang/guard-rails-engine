// Package textguard is the text module of the embeddable engine: the guards
// a chat feature needs, in the standard library only.
//
//	g, err := engine.New(engine.Options{}, textguard.Module())
//
// Pass guard names to compile in fewer of them:
//
//	textguard.Module(textguard.PII, textguard.Secrets, textguard.Restore)
//
// Restore is what puts masked values back into the answer, so keep it
// alongside PII unless the model's output should keep the placeholders.
// To switch a guard off without recompiling, disable it in the policy instead.
package textguard

import (
	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/guards/inbound"
	"go.vicoworks.com/guard-rails-engine/internal/guards/outbound"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
	"go.vicoworks.com/guard-rails-engine/internal/guards/toolresult"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/engine"
)

// Guard names, for Module.
const (
	// Inbound: the prompt, before it reaches a provider.
	PII       = config.GuardPII
	Secrets   = config.GuardSecrets
	Injection = config.GuardInjection
	Topic     = config.GuardTopic
	Quota     = config.GuardQuota

	// Tool result: retrieved content (RAG, web, email), before the model reads it.
	ToolResult = config.GuardToolResult

	// Outbound: the completion, before it reaches the user.
	Leak      = config.GuardLeak
	Restore   = config.GuardRestore
	Format    = config.GuardFormat
	Schema    = config.GuardSchema
	Grounding = config.GuardGrounding
)

// Module returns the text guards, or only the named ones. An unknown name
// makes engine.New fail.
func Module(guards ...string) engine.Module {
	return registry.Select(registry.Merge("textguard",
		inbound.Module(), toolresult.Module(), outbound.Module()), guards...)
}
