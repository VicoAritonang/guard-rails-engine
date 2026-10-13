// Package config owns everything an operator can change without recompiling:
// YAML policy documents, environment-derived runtime settings, and the model
// price table used for cost attribution.
package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FailMode decides what happens when a guard errors or exceeds its deadline.
//
// This is the single most consequential knob in the system. Fail-open keeps a
// consumer product available when a detector regresses; fail-closed keeps a
// regulated workload compliant when a detector regresses. There is no correct
// global default, so the policy must state it explicitly per guard, and the
// engine refuses to guess.
type FailMode string

const (
	FailOpen   FailMode = "open"   // guard error => traffic proceeds, decision marked degraded
	FailClosed FailMode = "closed" // guard error => traffic blocked
)

func (f FailMode) Valid() bool { return f == FailOpen || f == FailClosed }

// GuardConfig is the per-guard slice of policy.
type GuardConfig struct {
	Name string `yaml:"-"`

	Enabled bool `yaml:"enabled"`

	// Threshold gates score-based detectors. Detectors that emit a calibrated
	// score suppress findings below it; deterministic detectors ignore it.
	Threshold float64 `yaml:"threshold"`

	// Timeout bounds a single guard invocation. A guard that blows its budget
	// is resolved by FailMode rather than being allowed to stall the request.
	Timeout time.Duration `yaml:"timeout"`

	FailMode FailMode `yaml:"fail_mode"`

	// Actions maps a severity name to the enforcement action. Missing entries
	// fall back to the policy-level DefaultActions.
	Actions map[string]string `yaml:"actions"`

	// Categories allows per-category overrides of severity, letting an
	// operator downgrade "pii.ip_address" without touching the detector.
	Categories map[string]CategoryOverride `yaml:"categories"`

	// Params carries detector-specific settings, validated by each guard.
	Params map[string]any `yaml:"params"`
}

// CategoryOverride retunes a single detection category.
type CategoryOverride struct {
	Severity  string  `yaml:"severity"`
	Action    string  `yaml:"action"`
	Disabled  bool    `yaml:"disabled"`
	Threshold float64 `yaml:"threshold"`
}

// Policy is a complete, versioned rule set.
type Policy struct {
	Version     string `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// DefaultActions is the severity -> action fallback for every guard.
	DefaultActions map[string]string `yaml:"default_actions"`

	// DefaultTimeout and DefaultFailMode apply to guards that omit their own.
	DefaultTimeout  time.Duration `yaml:"default_timeout"`
	DefaultFailMode FailMode      `yaml:"default_fail_mode"`

	// StageBudget caps total wall-clock per stage. The blueprint's <50ms
	// end-to-end target is enforced here, not merely documented.
	StageBudget map[string]time.Duration `yaml:"stage_budget"`

	Guards map[string]*GuardConfig `yaml:"guards"`

	// path records where the policy was loaded from, for /v1/policy output.
	path string `yaml:"-"`
}

// Path returns the file the policy was loaded from ("<builtin>" if default).
func (p *Policy) Path() string {
	if p.path == "" {
		return "<builtin>"
	}
	return p.path
}

// Guard returns the config for name, or a disabled placeholder.
func (p *Policy) Guard(name string) *GuardConfig {
	if g, ok := p.Guards[name]; ok && g != nil {
		return g
	}
	return &GuardConfig{Name: name, Enabled: false}
}

// EnabledGuards lists enabled guard names in deterministic order. Determinism
// matters: mutation application order is derived from it, so a map iteration
// here would make redaction output non-reproducible across runs.
func (p *Policy) EnabledGuards() []string {
	out := make([]string, 0, len(p.Guards))
	for name, g := range p.Guards {
		if g != nil && g.Enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Budget returns the wall-clock budget for a stage.
func (p *Policy) Budget(stage string) time.Duration {
	if d, ok := p.StageBudget[stage]; ok && d > 0 {
		return d
	}
	return 50 * time.Millisecond
}

// ActionFor resolves severity -> action for a guard, honouring per-category
// overrides, then per-guard actions, then the policy default.
func (p *Policy) ActionFor(guard, category, severity string) string {
	g := p.Guard(guard)
	if ov, ok := g.Categories[category]; ok && ov.Action != "" {
		return ov.Action
	}
	if a, ok := g.Actions[severity]; ok && a != "" {
		return a
	}
	if a, ok := p.DefaultActions[severity]; ok && a != "" {
		return a
	}
	return "flag"
}

// SeverityFor resolves the effective severity for a category, allowing an
// operator to retune a detector's grading without a code change.
func (p *Policy) SeverityFor(guard, category, detected string) string {
	if ov, ok := p.Guard(guard).Categories[category]; ok && ov.Severity != "" {
		return ov.Severity
	}
	return detected
}

// CategoryEnabled reports whether a category is switched on.
func (p *Policy) CategoryEnabled(guard, category string) bool {
	if ov, ok := p.Guard(guard).Categories[category]; ok {
		return !ov.Disabled
	}
	return true
}

// ThresholdFor resolves the score threshold for a category.
func (p *Policy) ThresholdFor(guard, category string) float64 {
	g := p.Guard(guard)
	if ov, ok := g.Categories[category]; ok && ov.Threshold > 0 {
		return ov.Threshold
	}
	return g.Threshold
}

// LoadPolicy reads and validates a YAML policy, layering it over the built-in
// defaults so a short operator file does not have to restate everything.
func LoadPolicy(path string) (*Policy, error) {
	base := DefaultPolicy()
	if path == "" {
		return base, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var overlay Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // typo in a policy file must fail loudly, not silently disable a guard
	if err := dec.Decode(&overlay); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	merged := base.merge(&overlay)
	merged.path = path
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	return merged, nil
}

// merge layers overlay on top of p, returning a new policy.
func (p *Policy) merge(overlay *Policy) *Policy {
	out := *p
	if overlay.Version != "" {
		out.Version = overlay.Version
	}
	if overlay.Name != "" {
		out.Name = overlay.Name
	}
	if overlay.Description != "" {
		out.Description = overlay.Description
	}
	if overlay.DefaultTimeout > 0 {
		out.DefaultTimeout = overlay.DefaultTimeout
	}
	if overlay.DefaultFailMode != "" {
		out.DefaultFailMode = overlay.DefaultFailMode
	}
	if len(overlay.DefaultActions) > 0 {
		out.DefaultActions = mergeStrMap(p.DefaultActions, overlay.DefaultActions)
	}
	if len(overlay.StageBudget) > 0 {
		out.StageBudget = mergeDurMap(p.StageBudget, overlay.StageBudget)
	}

	out.Guards = make(map[string]*GuardConfig, len(p.Guards))
	for k, v := range p.Guards {
		cp := *v
		cp.Actions = mergeStrMap(nil, v.Actions)
		cp.Categories = mergeCatMap(nil, v.Categories)
		cp.Params = mergeAnyMap(nil, v.Params)
		out.Guards[k] = &cp
	}
	for name, og := range overlay.Guards {
		if og == nil {
			continue
		}
		base, ok := out.Guards[name]
		if !ok {
			cp := *og
			cp.Name = name
			out.Guards[name] = &cp
			continue
		}
		base.Enabled = og.Enabled
		if og.Threshold > 0 {
			base.Threshold = og.Threshold
		}
		if og.Timeout > 0 {
			base.Timeout = og.Timeout
		}
		if og.FailMode != "" {
			base.FailMode = og.FailMode
		}
		base.Actions = mergeStrMap(base.Actions, og.Actions)
		base.Categories = mergeCatMap(base.Categories, og.Categories)
		base.Params = mergeAnyMap(base.Params, og.Params)
	}
	return &out
}

// Validate rejects a policy that would behave surprisingly at runtime. Catching
// this at load time is the difference between a startup failure and a silent
// hole in production coverage.
func (p *Policy) Validate() error {
	var errs []string
	if p.Version == "" {
		errs = append(errs, "version is required")
	}
	if !p.DefaultFailMode.Valid() {
		errs = append(errs, fmt.Sprintf("default_fail_mode %q must be open|closed", p.DefaultFailMode))
	}
	for sev, act := range p.DefaultActions {
		if !validSeverity(sev) {
			errs = append(errs, fmt.Sprintf("default_actions: unknown severity %q", sev))
		}
		if !validAction(act) {
			errs = append(errs, fmt.Sprintf("default_actions[%s]: unknown action %q", sev, act))
		}
	}
	for stage, d := range p.StageBudget {
		switch stage {
		case "inbound", "runtime", "tool_result", "outbound":
		default:
			errs = append(errs, fmt.Sprintf("stage_budget: unknown stage %q", stage))
		}
		if d <= 0 {
			errs = append(errs, fmt.Sprintf("stage_budget[%s] must be positive", stage))
		}
	}

	names := make([]string, 0, len(p.Guards))
	for n := range p.Guards {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		g := p.Guards[name]
		if g == nil {
			errs = append(errs, fmt.Sprintf("guard %q: empty definition", name))
			continue
		}
		g.Name = name
		if g.Threshold < 0 || g.Threshold > 1 {
			errs = append(errs, fmt.Sprintf("guard %q: threshold %.3f outside [0,1]", name, g.Threshold))
		}
		if g.FailMode != "" && !g.FailMode.Valid() {
			errs = append(errs, fmt.Sprintf("guard %q: fail_mode %q must be open|closed", name, g.FailMode))
		}
		if g.Timeout < 0 {
			errs = append(errs, fmt.Sprintf("guard %q: negative timeout", name))
		}
		for sev, act := range g.Actions {
			if !validSeverity(sev) {
				errs = append(errs, fmt.Sprintf("guard %q: unknown severity %q", name, sev))
			}
			if !validAction(act) {
				errs = append(errs, fmt.Sprintf("guard %q actions[%s]: unknown action %q", name, sev, act))
			}
		}
		for cat, ov := range g.Categories {
			if ov.Severity != "" && !validSeverity(ov.Severity) {
				errs = append(errs, fmt.Sprintf("guard %q category %q: unknown severity %q", name, cat, ov.Severity))
			}
			if ov.Action != "" && !validAction(ov.Action) {
				errs = append(errs, fmt.Sprintf("guard %q category %q: unknown action %q", name, cat, ov.Action))
			}
			if ov.Threshold < 0 || ov.Threshold > 1 {
				errs = append(errs, fmt.Sprintf("guard %q category %q: threshold outside [0,1]", name, cat))
			}
		}
	}

	// A guard budget larger than its stage budget is always a misconfiguration:
	// the stage deadline would fire first and the guard timeout would be dead
	// configuration that never takes effect.
	for _, name := range names {
		g := p.Guards[name]
		if g == nil || !g.Enabled {
			continue
		}
		to := g.Timeout
		if to == 0 {
			to = p.DefaultTimeout
		}
		for stage, budget := range p.StageBudget {
			if to > budget && guardStage(name) == stage {
				errs = append(errs, fmt.Sprintf(
					"guard %q timeout %s exceeds %s stage budget %s (guard timeout would never fire)",
					name, to, stage, budget))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func validSeverity(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	}
	return false
}

func validAction(s string) bool {
	switch s {
	case "allow", "flag", "redact", "block":
		return true
	}
	return false
}

func mergeStrMap(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func mergeDurMap(base, overlay map[string]time.Duration) map[string]time.Duration {
	out := make(map[string]time.Duration, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func mergeCatMap(base, overlay map[string]CategoryOverride) map[string]CategoryOverride {
	out := make(map[string]CategoryOverride, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func mergeAnyMap(base, overlay map[string]any) map[string]any {
	if base == nil && overlay == nil {
		return nil
	}
	out := make(map[string]any, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// Marshal renders the effective policy, which is what /v1/policy serves. An
// operator debugging "why did this get blocked" needs the merged view, not the
// file they wrote.
func (p *Policy) Marshal() ([]byte, error) { return yaml.Marshal(p) }
