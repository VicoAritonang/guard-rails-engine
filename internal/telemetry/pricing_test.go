package telemetry

import (
	"math"
	"testing"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

func approx(t *testing.T, got, want float64, label string) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %.10f, want %.10f", label, got, want)
	}
}

func TestOpenAICost(t *testing.T) {
	p := NewPricing()

	// gpt-5: $1.25 input / $10 output per 1M tokens.
	cost := p.Cost("gpt-5", core.Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000})
	approx(t, cost, 11.25, "gpt-5 1M in + 1M out")

	cost = p.Cost("gpt-4o-mini", core.Usage{InputTokens: 500_000, OutputTokens: 100_000})
	approx(t, cost, 0.5*0.15+0.1*0.60, "gpt-4o-mini")
}

// TestCachedInputIsPricedSeparately is the whole reason cache rates are in the
// table. OpenAI's cached input is 10% of the input rate on the GPT-5 family;
// billing it as ordinary input would overstate a cache-heavy workload tenfold.
func TestCachedInputIsPricedSeparately(t *testing.T) {
	p := NewPricing()

	full := p.Cost("gpt-5", core.Usage{InputTokens: 1_000_000})
	cached := p.Cost("gpt-5", core.Usage{CacheReadTokens: 1_000_000})

	approx(t, full, 1.25, "1M fresh input")
	approx(t, cached, 0.125, "1M cached input")
	if cached*9 > full {
		t.Errorf("cached input (%.4f) is not meaningfully cheaper than fresh (%.4f)", cached, full)
	}
}

// TestCacheDiscountsDifferPerVendor guards against anyone replacing the
// explicit per-model cache rates with one global multiplier: the discount is
// 10% on GPT-5, 25% on GPT-4.1 and 50% on GPT-4o.
func TestCacheDiscountsDifferPerVendor(t *testing.T) {
	p := NewPricing()
	cases := map[string]float64{
		"gpt-5":   0.10,
		"gpt-4.1": 0.25,
		"gpt-4o":  0.50,
	}
	for model, wantRatio := range cases {
		mp, ok := p.Price(model)
		if !ok {
			t.Fatalf("%s missing from the price table", model)
		}
		got := mp.CacheReadPerMTok / mp.InputPerMTok
		if math.Abs(got-wantRatio) > 0.001 {
			t.Errorf("%s cache ratio = %.3f, want %.3f", model, got, wantRatio)
		}
	}
}

// TestModelPrefixMatching: dated snapshots must resolve, and the longest
// prefix must win so gpt-5-mini is never priced as gpt-5 (a 5x error).
func TestModelPrefixMatching(t *testing.T) {
	p := NewPricing()
	cases := map[string]float64{
		"gpt-5":                   1.25,
		"gpt-5-2025-08-07":        1.25,
		"gpt-5-mini":              0.25,
		"gpt-5-mini-2025-08-07":   0.25,
		"gpt-5-nano":              0.05,
		"gpt-5.1":                 1.25,
		"gpt-5.2":                 1.75,
		"gpt-4o-2024-08-06":       2.50,
		"gpt-4.1-mini":            0.40,
		"o4-mini":                 1.10,
		"claude-opus-5":           5.00,
		"claude-sonnet-4-6":       3.00,
		"anthropic.claude-opus-5": 5.00, // Bedrock-style prefix
		"claude-opus-5@20260101":  5.00, // Vertex-style version suffix
	}
	for model, wantInput := range cases {
		mp, ok := p.Price(model)
		if !ok {
			t.Errorf("%s did not resolve to a price", model)
			continue
		}
		if mp.InputPerMTok != wantInput {
			t.Errorf("%s input rate = %.3f, want %.3f", model, mp.InputPerMTok, wantInput)
		}
	}
}

// TestUnknownModelIsTrackedNotGuessed: reporting $0.00 for an unpriced model is
// the correct behaviour, but silently is not -- an operator needs to know their
// cost dashboard has a blind spot.
func TestUnknownModelIsTrackedNotGuessed(t *testing.T) {
	p := NewPricing()

	if cost := p.Cost("some-model-nobody-added", core.Usage{InputTokens: 1_000_000}); cost != 0 {
		t.Errorf("an unpriced model should cost 0, got %.4f", cost)
	}
	unknown := p.UnknownModels()
	if len(unknown) == 0 {
		t.Fatal("the unpriced model was not recorded")
	}
	found := false
	for _, u := range unknown {
		if len(u) > 0 && u[:4] == "some" {
			found = true
		}
	}
	if !found {
		t.Errorf("UnknownModels did not name the model: %v", unknown)
	}
}

func TestAnthropicCacheMultiplierFallback(t *testing.T) {
	p := NewPricing()
	// Anthropic entries omit explicit cache rates, so the standard multipliers
	// apply: reads at 0.1x input, writes at 1.25x.
	read := p.Cost("claude-opus-5", core.Usage{CacheReadTokens: 1_000_000})
	write := p.Cost("claude-opus-5", core.Usage{CacheWriteTokens: 1_000_000})
	approx(t, read, 0.5, "claude cache read")
	approx(t, write, 6.25, "claude cache write")
}

func TestInputCostForQuotaEstimate(t *testing.T) {
	p := NewPricing()
	approx(t, p.InputCost("gpt-5", 200_000), 0.25, "gpt-5 200k input estimate")
	if p.InputCost("unpriced-model", 1_000_000) != 0 {
		t.Error("an unpriced model should estimate 0")
	}
}

func TestContextWindows(t *testing.T) {
	p := NewPricing()
	if got := p.ContextWindow("gpt-5"); got != 400_000 {
		t.Errorf("gpt-5 context window = %d", got)
	}
	if got := p.ContextWindow("gpt-4.1"); got != 1_047_576 {
		t.Errorf("gpt-4.1 context window = %d", got)
	}
	if got := p.ContextWindow("nothing-here"); got != 0 {
		t.Errorf("unknown model should report 0, got %d", got)
	}
}

// TestShippedPricingOverrideLoads guards against the documented example
// drifting from the loader. Operators copy this file, so it has to parse.
func TestShippedPricingOverrideLoads(t *testing.T) {
	p, err := LoadPricing("../../config/pricing.yaml")
	if err != nil {
		t.Fatalf("config/pricing.yaml does not load: %v", err)
	}
	// The override must add its own entry without discarding the built-ins.
	if mp, ok := p.Price("llama-3.3-70b"); !ok || mp.InputPerMTok != 0.35 {
		t.Errorf("override entry missing or wrong: %+v ok=%v", mp, ok)
	}
	if mp, ok := p.Price("gpt-5"); !ok || mp.InputPerMTok != 1.25 {
		t.Error("loading an override discarded the built-in table")
	}
}
