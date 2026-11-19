package media

import (
	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
)

// Module provides the ingest step and the two guards that report its
// findings. The backends are optional; see Backends.
func Module(b Backends) registry.Module {
	return registry.Module{
		Name: "media",
		Guards: map[string]registry.Factory{
			config.GuardMedia: func(*config.GuardConfig, registry.Deps) (core.Guard, error) {
				return NewGuard(core.StageInbound), nil
			},
			config.GuardMediaResult: func(*config.GuardConfig, registry.Deps) (core.Guard, error) {
				return NewGuard(core.StageToolResult), nil
			},
		},
		Ingestor: func(pol *config.Policy) (core.Ingestor, error) {
			opts, err := OptionsFromPolicy(pol.Guard(config.GuardMedia))
			if err != nil {
				return nil, err
			}
			return New(opts, b), nil
		},
	}
}
