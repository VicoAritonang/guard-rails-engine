// Package telemetry turns guard activity into numbers an operator can act on:
// cost, latency, detection rates, and traces.
package telemetry

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// ModelPrice is USD per million tokens.
//
// Cache pricing is modelled separately because it dominates the economics of
// any agent that resends a long system prompt every turn: a cache read is an
// order of magnitude cheaper than a fresh input token, and a cost model that
// ignores the distinction will overstate spend by 5-10x on exactly the
// workloads operators care most about.
type ModelPrice struct {
	InputPerMTok      float64 `yaml:"input"`
	OutputPerMTok     float64 `yaml:"output"`
	CacheReadPerMTok  float64 `yaml:"cache_read"`
	CacheWritePerMTok float64 `yaml:"cache_write"`
	ContextWindow     int     `yaml:"context_window"`
}

// defaultPrices are first-party API rates in USD per million tokens.
//
// PRICES CHANGE. This table is a starting default, not a fact: verify it
// against the provider's pricing page for anything you bill on, and override it
// with GUARDRAILS_PRICING rather than editing this file. Reseller and
// cloud-marketplace routes (Azure OpenAI, Bedrock, Vertex) are separately
// priced and always need an override.
//
// Cache rates are stated explicitly where the provider publishes them, because
// the discount differs sharply between vendors -- OpenAI's cached input is 10%
// of the input rate on the GPT-5 family but 50% on GPT-4.1 and 20% on GPT-4o --
// and a single hard-coded multiplier would be wrong for most of this table.
//
// Last verified: 2026-08-28.
var defaultPrices = map[string]ModelPrice{
	// --- OpenAI: GPT-5 family --------------------------------------------
	"gpt-5":         {InputPerMTok: 1.25, CacheReadPerMTok: 0.125, OutputPerMTok: 10, ContextWindow: 400_000},
	"gpt-5-mini":    {InputPerMTok: 0.25, CacheReadPerMTok: 0.025, OutputPerMTok: 2, ContextWindow: 400_000},
	"gpt-5-nano":    {InputPerMTok: 0.05, CacheReadPerMTok: 0.005, OutputPerMTok: 0.40, ContextWindow: 400_000},
	"gpt-5-pro":     {InputPerMTok: 15, OutputPerMTok: 120, ContextWindow: 400_000},
	"gpt-5.1":       {InputPerMTok: 1.25, CacheReadPerMTok: 0.125, OutputPerMTok: 10, ContextWindow: 400_000},
	"gpt-5.2":       {InputPerMTok: 1.75, CacheReadPerMTok: 0.175, OutputPerMTok: 14, ContextWindow: 400_000},
	"gpt-5.4":       {InputPerMTok: 2.50, CacheReadPerMTok: 0.25, OutputPerMTok: 15, ContextWindow: 400_000},
	"gpt-5.4-mini":  {InputPerMTok: 0.75, CacheReadPerMTok: 0.075, OutputPerMTok: 4.50, ContextWindow: 400_000},
	"gpt-5.4-nano":  {InputPerMTok: 0.20, CacheReadPerMTok: 0.02, OutputPerMTok: 1.25, ContextWindow: 400_000},
	"gpt-5.5":       {InputPerMTok: 5, CacheReadPerMTok: 0.50, OutputPerMTok: 30, ContextWindow: 400_000},
	"gpt-5.6-luna":  {InputPerMTok: 0.20, CacheReadPerMTok: 0.02, OutputPerMTok: 1.20, ContextWindow: 400_000},
	"gpt-5.6-terra": {InputPerMTok: 2, CacheReadPerMTok: 0.20, OutputPerMTok: 12, ContextWindow: 400_000},
	"gpt-5.6-sol":   {InputPerMTok: 4, CacheReadPerMTok: 0.40, OutputPerMTok: 20, ContextWindow: 400_000},

	// --- OpenAI: GPT-4.1 and GPT-4o --------------------------------------
	"gpt-4.1":      {InputPerMTok: 2, CacheReadPerMTok: 0.50, OutputPerMTok: 8, ContextWindow: 1_047_576},
	"gpt-4.1-mini": {InputPerMTok: 0.40, CacheReadPerMTok: 0.10, OutputPerMTok: 1.60, ContextWindow: 1_047_576},
	"gpt-4.1-nano": {InputPerMTok: 0.10, CacheReadPerMTok: 0.025, OutputPerMTok: 0.40, ContextWindow: 1_047_576},
	"gpt-4o":       {InputPerMTok: 2.50, CacheReadPerMTok: 1.25, OutputPerMTok: 10, ContextWindow: 128_000},
	"gpt-4o-mini":  {InputPerMTok: 0.15, CacheReadPerMTok: 0.075, OutputPerMTok: 0.60, ContextWindow: 128_000},

	// --- OpenAI: o-series reasoning --------------------------------------
	"o1":      {InputPerMTok: 15, CacheReadPerMTok: 7.50, OutputPerMTok: 60, ContextWindow: 200_000},
	"o1-pro":  {InputPerMTok: 150, OutputPerMTok: 600, ContextWindow: 200_000},
	"o3":      {InputPerMTok: 2, CacheReadPerMTok: 0.50, OutputPerMTok: 8, ContextWindow: 200_000},
	"o3-mini": {InputPerMTok: 1.10, CacheReadPerMTok: 0.55, OutputPerMTok: 4.40, ContextWindow: 200_000},
	"o3-pro":  {InputPerMTok: 20, OutputPerMTok: 80, ContextWindow: 200_000},
	"o4-mini": {InputPerMTok: 1.10, CacheReadPerMTok: 0.275, OutputPerMTok: 4.40, ContextWindow: 200_000},

	// --- Anthropic --------------------------------------------------------
	"claude-fable-5":    {InputPerMTok: 10, OutputPerMTok: 50, ContextWindow: 1_000_000},
	"claude-mythos-5":   {InputPerMTok: 10, OutputPerMTok: 50, ContextWindow: 1_000_000},
	"claude-opus-5":     {InputPerMTok: 5, OutputPerMTok: 25, ContextWindow: 1_000_000},
	"claude-opus-4-8":   {InputPerMTok: 5, OutputPerMTok: 25, ContextWindow: 1_000_000},
	"claude-opus-4-7":   {InputPerMTok: 5, OutputPerMTok: 25, ContextWindow: 1_000_000},
	"claude-opus-4-6":   {InputPerMTok: 5, OutputPerMTok: 25, ContextWindow: 1_000_000},
	"claude-sonnet-5":   {InputPerMTok: 2, OutputPerMTok: 10, ContextWindow: 1_000_000},
	"claude-sonnet-4-6": {InputPerMTok: 3, OutputPerMTok: 15, ContextWindow: 1_000_000},
	"claude-haiku-4-5":  {InputPerMTok: 1, OutputPerMTok: 5, ContextWindow: 200_000},

	// --- Groq (keyed by Groq's own model ids, which contain a slash) --------
	// Groq lists no cached-input discount for these, so cache reads are priced
	// at the input rate rather than at the Anthropic-style 0.1x default.
	// qwen/qwen3.8-27b had no published rate when this table was written; the
	// figure is an estimate carried over from the Qwen3-32B listing. Override
	// it with GUARDRAILS_PRICING before quoting a cost from it.
	"openai/gpt-oss-20b":                  {InputPerMTok: 0.075, CacheReadPerMTok: 0.075, OutputPerMTok: 0.30, ContextWindow: 131_072},
	"openai/gpt-oss-120b":                 {InputPerMTok: 0.15, CacheReadPerMTok: 0.15, OutputPerMTok: 0.60, ContextWindow: 131_072},
	"openai/gpt-oss-safeguard-20b":        {InputPerMTok: 0.075, CacheReadPerMTok: 0.075, OutputPerMTok: 0.30, ContextWindow: 131_072},
	"qwen/qwen3.8-27b":                    {InputPerMTok: 0.29, CacheReadPerMTok: 0.29, OutputPerMTok: 0.59, ContextWindow: 131_072},
	"meta-llama/llama-prompt-guard-2-86m": {InputPerMTok: 0.04, CacheReadPerMTok: 0.04, OutputPerMTok: 0.04, ContextWindow: 512},
	"meta-llama/llama-prompt-guard-2-22m": {InputPerMTok: 0.03, CacheReadPerMTok: 0.03, OutputPerMTok: 0.03, ContextWindow: 512},

	// --- OpenAI auxiliary ----------------------------------------------------
	"text-embedding-3-small": {InputPerMTok: 0.02, ContextWindow: 8_191},
	"text-embedding-3-large": {InputPerMTok: 0.13, ContextWindow: 8_191},
	// omni-moderation is free of charge.
	"omni-moderation-latest": {ContextWindow: 32_768},
}

// Standard Anthropic cache multipliers: a write costs 1.25x a fresh input
// token, a read costs 0.1x. Applied when a price entry omits explicit cache
// rates so the common case needs only two numbers.
const (
	cacheWriteMultiplier = 1.25
	cacheReadMultiplier  = 0.10
)

// Pricing resolves a model name to a price and computes request cost.
type Pricing struct {
	mu     sync.RWMutex
	prices map[string]ModelPrice
	// unknown accumulates model names with no price entry, so an operator can
	// see that their cost dashboard has a blind spot instead of silently
	// reading $0.00 for a model nobody added.
	unknown map[string]int
}

// NewPricing returns the built-in table.
func NewPricing() *Pricing {
	p := &Pricing{
		prices:  make(map[string]ModelPrice, len(defaultPrices)),
		unknown: map[string]int{},
	}
	for k, v := range defaultPrices {
		p.prices[k] = v
	}
	return p
}

// LoadPricing overlays a YAML price file on the defaults.
func LoadPricing(path string) (*Pricing, error) {
	p := NewPricing()
	if path == "" {
		return p, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pricing: %w", err)
	}
	var file struct {
		Models map[string]ModelPrice `yaml:"models"`
	}
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse pricing %s: %w", path, err)
	}
	for name, price := range file.Models {
		if price.InputPerMTok < 0 || price.OutputPerMTok < 0 {
			return nil, fmt.Errorf("pricing %s: negative rate", name)
		}
		p.prices[name] = price
	}
	return p, nil
}

// Price looks up a model, tolerating the suffixes providers append.
//
// Callers pass whatever the client sent: "claude-opus-5", a dated snapshot, or
// a Bedrock-prefixed id like "anthropic.claude-opus-5". Normalising here means
// no other package has to know the shape of a model id.
func (p *Pricing) Price(model string) (ModelPrice, bool) {
	if model == "" {
		return ModelPrice{}, false
	}
	p.mu.RLock()
	if mp, ok := p.prices[model]; ok {
		p.mu.RUnlock()
		return mp, true
	}
	p.mu.RUnlock()

	norm := normalizeModel(model)
	p.mu.RLock()
	mp, ok := p.prices[norm]
	if !ok {
		// Longest-prefix match handles dated snapshots such as
		// "claude-sonnet-4-6-20251114" without enumerating every date.
		best := ""
		for name := range p.prices {
			if strings.HasPrefix(norm, name) && len(name) > len(best) {
				best, mp, ok = name, p.prices[name], true
			}
		}
	}
	p.mu.RUnlock()

	if !ok {
		p.mu.Lock()
		p.unknown[model]++
		p.mu.Unlock()
	}
	return mp, ok
}

func normalizeModel(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	for _, prefix := range []string{"anthropic.", "us.anthropic.", "eu.anthropic.", "apac.anthropic."} {
		m = strings.TrimPrefix(m, prefix)
	}
	// Vertex uses "model@version"; strip the version.
	if i := strings.Index(m, "@"); i > 0 {
		m = m[:i]
	}
	return m
}

// Cost computes the USD cost of a completed request.
func (p *Pricing) Cost(model string, u core.Usage) float64 {
	mp, ok := p.Price(model)
	if !ok {
		return 0
	}
	const perToken = 1_000_000.0

	cacheWrite := mp.CacheWritePerMTok
	if cacheWrite == 0 {
		cacheWrite = mp.InputPerMTok * cacheWriteMultiplier
	}
	cacheRead := mp.CacheReadPerMTok
	if cacheRead == 0 {
		cacheRead = mp.InputPerMTok * cacheReadMultiplier
	}

	return float64(u.InputTokens)/perToken*mp.InputPerMTok +
		float64(u.OutputTokens)/perToken*mp.OutputPerMTok +
		float64(u.CacheWriteTokens)/perToken*cacheWrite +
		float64(u.CacheReadTokens)/perToken*cacheRead
}

// InputCost prices an input-token estimate, used by the quota guard before the
// request is sent and no usage figures exist yet.
func (p *Pricing) InputCost(model string, tokens int) float64 {
	mp, ok := p.Price(model)
	if !ok {
		return 0
	}
	return float64(tokens) / 1_000_000.0 * mp.InputPerMTok
}

// ContextWindow reports the model's input limit, or 0 if unknown.
func (p *Pricing) ContextWindow(model string) int {
	mp, _ := p.Price(model)
	return mp.ContextWindow
}

// UnknownModels lists models seen with no price entry, most frequent first.
func (p *Pricing) UnknownModels() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	type kv struct {
		name string
		n    int
	}
	list := make([]kv, 0, len(p.unknown))
	for k, v := range p.unknown {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, fmt.Sprintf("%s (%d requests)", e.name, e.n))
	}
	return out
}

// Models lists priced model names.
func (p *Pricing) Models() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.prices))
	for k := range p.prices {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
