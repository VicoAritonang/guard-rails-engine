// Package link lets the module packages reach the assembled engine behind a
// public *engine.Engine, which keeps it unexported. toolguard needs it to find
// the tool-safety evaluator that signs approvals.
package link

import "go.vicoworks.com/guard-rails/internal/guards/registry"

// Core returns the assembled engine behind an *engine.Engine, or nil for any
// other value. Package engine sets it at init, which runs before any package
// that imports engine can call it.
var Core func(e any) *registry.Engine
