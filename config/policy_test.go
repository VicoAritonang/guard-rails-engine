package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuiltinPoliciesAreValid(t *testing.T) {
	for name, p := range map[string]*Policy{
		"default": DefaultPolicy(),
		"strict":  StrictPolicy(),
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s policy is invalid: %v", name, err)
		}
	}
}

// TestShippedPolicyFilesLoad guards against the documentation drifting from the
// code: the YAML in config/policies is what operators copy, so it has to parse
// and validate exactly like the built-ins.
func TestShippedPolicyFilesLoad(t *testing.T) {
	entries, err := os.ReadDir("policies")
	if err != nil {
		t.Skipf("no policies directory: %v", err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		found++
		path := filepath.Join("policies", e.Name())
		p, err := LoadPolicy(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if p.Version == "" {
			t.Errorf("%s: no version", path)
		}
	}
	if found == 0 {
		t.Error("no policy files found to validate")
	}
}

// TestUnknownFieldIsRejected is the single most important property of the
// loader. A typo'd key that silently does nothing means an operator believes a
// guard is configured when it is not.
func TestUnknownFieldIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.yaml")
	body := "version: \"1.0\"\nguards:\n  injection:\n    enabled: true\n    threshhold: 0.5\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("a misspelled field was accepted silently")
	}
}

func TestOverlayMergesOntoDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	body := "" +
		"version: \"2.0.0\"\n" +
		"name: custom\n" +
		"guards:\n" +
		"  injection:\n" +
		"    enabled: true\n" +
		"    threshold: 0.25\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "2.0.0" || p.Name != "custom" {
		t.Errorf("overlay did not take effect: %s/%s", p.Version, p.Name)
	}
	if got := p.Guard(GuardInjection).Threshold; got != 0.25 {
		t.Errorf("threshold = %v, want 0.25", got)
	}
	// A short overlay must not wipe out the guards it did not mention.
	if !p.Guard(GuardPII).Enabled {
		t.Error("pii was disabled by an overlay that never mentioned it")
	}
	if p.Guard(GuardPII).String("mask_mode", "") != "vault" {
		t.Error("default guard params were lost during the merge")
	}
	if p.Path() != path {
		t.Errorf("Path() = %q, want %q", p.Path(), path)
	}
}

func TestValidateCatchesBadValues(t *testing.T) {
	cases := map[string]func(*Policy){
		"missing version":       func(p *Policy) { p.Version = "" },
		"bad default fail mode": func(p *Policy) { p.DefaultFailMode = "sideways" },
		"unknown severity":      func(p *Policy) { p.DefaultActions["catastrophic"] = "block" },
		"unknown action":        func(p *Policy) { p.DefaultActions["high"] = "vaporise" },
		"threshold above one":   func(p *Policy) { p.Guards[GuardInjection].Threshold = 1.5 },
		"negative threshold":    func(p *Policy) { p.Guards[GuardInjection].Threshold = -0.2 },
		"bad guard fail mode":   func(p *Policy) { p.Guards[GuardPII].FailMode = "maybe" },
		"unknown stage budget":  func(p *Policy) { p.StageBudget["sideways"] = time.Second },
		"bad category action":   func(p *Policy) { p.Guards[GuardPII].Categories["pii.email"] = CategoryOverride{Action: "nope"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := DefaultPolicy()
			mutate(p)
			if err := p.Validate(); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

// TestGuardTimeoutCannotExceedStageBudget catches dead configuration: a guard
// timeout longer than its stage budget would never fire, so the operator's
// intended per-guard bound simply would not exist.
func TestGuardTimeoutCannotExceedStageBudget(t *testing.T) {
	p := DefaultPolicy()
	p.Guards[GuardPII].Timeout = 5 * time.Second // stage budget is 50ms
	err := p.Validate()
	if err == nil {
		t.Fatal("expected an error for a guard timeout above the stage budget")
	}
	if !strings.Contains(err.Error(), "stage budget") {
		t.Errorf("error should name the conflict, got: %v", err)
	}
}

// TestActionResolutionPrecedence pins the three-layer lookup that answers
// "why was this blocked".
func TestActionResolutionPrecedence(t *testing.T) {
	p := DefaultPolicy()
	p.DefaultActions["medium"] = "flag"
	p.Guards[GuardPII].Actions["medium"] = "redact"
	p.Guards[GuardPII].Categories["pii.ip_address"] = CategoryOverride{Action: "allow"}

	if got := p.ActionFor(GuardPII, "pii.ip_address", "medium"); got != "allow" {
		t.Errorf("category override should win, got %q", got)
	}
	if got := p.ActionFor(GuardPII, "pii.email", "medium"); got != "redact" {
		t.Errorf("guard action should win over the policy default, got %q", got)
	}
	if got := p.ActionFor(GuardTopic, "content.fraud", "low"); got != "flag" {
		t.Errorf("policy default should apply, got %q", got)
	}
}

func TestStrictPolicyDiffersMeaningfully(t *testing.T) {
	strict := StrictPolicy()

	if strict.DefaultFailMode != FailClosed {
		t.Error("strict must default to fail-closed")
	}
	for name := range strict.Guards {
		if strict.EffectiveFailMode(name) != FailClosed {
			t.Errorf("guard %s is not fail-closed under the strict policy", name)
		}
	}
	if strict.Guard(GuardRestore).Enabled {
		t.Error("strict must not restore masked values on egress")
	}
	if strict.Guard(GuardInjection).Threshold >= DefaultPolicy().Guard(GuardInjection).Threshold {
		t.Error("strict should lower the injection threshold, trading precision for recall")
	}
	if strict.ActionFor(GuardTopic, "", "medium") != "block" {
		t.Error("strict should block at medium severity")
	}
}

func TestTypedParamAccessors(t *testing.T) {
	g := &GuardConfig{Params: map[string]any{
		"i": 42, "f": 0.5, "b": true, "s": "hello",
		"list":     []any{"a", "b"},
		"floatInt": float64(7), // YAML numbers decode as float64
	}}
	if g.Int("i", 0) != 42 || g.Int("floatInt", 0) != 7 || g.Int("missing", 9) != 9 {
		t.Error("Int accessor is wrong")
	}
	if g.Float("f", 0) != 0.5 || g.Float("i", 0) != 42 || g.Float("missing", 1.5) != 1.5 {
		t.Error("Float accessor is wrong")
	}
	if !g.Bool("b", false) || g.Bool("missing", true) != true {
		t.Error("Bool accessor is wrong")
	}
	if g.String("s", "") != "hello" || g.String("missing", "def") != "def" {
		t.Error("String accessor is wrong")
	}
	if got := g.Strings("list"); len(got) != 2 || got[0] != "a" {
		t.Errorf("Strings accessor is wrong: %v", got)
	}
	// A wrong type must fall back rather than panic.
	if g.Int("s", 3) != 3 {
		t.Error("a type mismatch should fall back to the default")
	}
}

func TestEnabledGuardsIsSorted(t *testing.T) {
	// Determinism matters: mutation precedence is derived from guard order.
	p := DefaultPolicy()
	first := p.EnabledGuards()
	for range 20 {
		next := p.EnabledGuards()
		if len(next) != len(first) {
			t.Fatal("EnabledGuards returned a different length between calls")
		}
		for i := range next {
			if next[i] != first[i] {
				t.Fatalf("EnabledGuards order is not stable: %v vs %v", next, first)
			}
		}
	}
}

func TestKnownGuardsMatchStages(t *testing.T) {
	p := DefaultPolicy()
	for _, name := range KnownGuards() {
		stage, ok := GuardStage(name)
		if !ok || stage == "" {
			t.Errorf("guard %q has no stage", name)
		}
		if _, defined := p.Guards[name]; !defined {
			t.Errorf("guard %q is known but absent from the default policy", name)
		}
	}
	for name := range p.Guards {
		if _, ok := GuardStage(name); !ok {
			t.Errorf("default policy defines unknown guard %q", name)
		}
	}
}
