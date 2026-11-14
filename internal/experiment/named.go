package experiment

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/providers"
	"go.vicoworks.com/guard-rails-engine/internal/telemetry"
)

// Spec describes one experiment for people choosing which to run: what it
// asks, what it costs, and how long it takes. The question is written first
// and the experiment designed to answer it, which is what keeps an evidence
// suite from becoming a collection of flattering numbers.
type Spec struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Question string `json:"question"`
	// Calls says what a full run sends upstream; Quick what a quick run does.
	Calls    string `json:"calls"`
	Quick    string `json:"quick"`
	Duration string `json:"duration"`
	// NeedsModels is false for experiments that run entirely offline.
	NeedsModels bool `json:"needs_models"`
	// NeedsFetch is true when public data must be downloaded first.
	NeedsFetch bool `json:"needs_fetch,omitempty"`
}

// Catalog lists every experiment in display order.
var Catalog = []Spec{
	{Name: "resilience", Title: "Resilience under provider failure: fallback chains and circuit breaking",
		Question: "How much availability does a fallback chain buy during a provider outage, and what does the circuit breaker add on top?",
		Calls:    "none: seeded fault injection against the production router", Quick: "identical (it is already instant)",
		Duration: "~1 s"},
	{Name: "benchmarks", Title: "Public guardrail benchmarks: rules vs model classifiers vs layered defence",
		Question: "On eight public benchmarks the field uses (prompt injection, in-the-wild jailbreaks, harmful behaviours, exaggerated safety, over-defence, real user traffic, and indirect injection in tool results), how does each detection layer score, and what does layering them buy?",
		Calls:    "160 cases x 8 benchmarks x 4 classifiers (~4,000 calls, <$0.30, Groq rate limits apply)",
		Quick:    "24 cases per benchmark, no Safeguard (~600 calls, <$0.05)",
		Duration: "quick ~4 min · full ~45 min", NeedsModels: true, NeedsFetch: true},
	{Name: "asr", Title: "Attack success rate across models, with and without the gateway",
		Question: "How often does each model leak a secret from its system prompt under extraction attacks, and how much of that does each gateway layer prevent without blocking ordinary customers?",
		Calls:    "34 cases x 6 models", Quick: "34 cases x 2 models (gpt-4.1-nano, gpt-oss-20b)",
		Duration: "quick ~1 min · full ~6 min", NeedsModels: true},
	{Name: "detectors", Title: "Held-out detector benchmark: rules vs model classifiers",
		Question: "How well does each detection layer generalise to attacks it was not built from (paraphrases, eight languages, indirect injection), and what does each cost in latency and money?",
		Calls:    "134 cases x 5 classifiers", Quick: "40 cases x Prompt Guard + Moderation",
		Duration: "quick ~1 min · full ~20 min", NeedsModels: true},
	{Name: "pii", Title: "PII redaction round-trip across models",
		Question: "Does redact-and-restore keep personal data away from model providers, and what does it cost in task success on each model?",
		Calls:    "12 tasks x 6 models x 2 (raw and redacted)", Quick: "12 tasks x 2 models",
		Duration: "quick ~40 s · full ~3 min", NeedsModels: true},
	{Name: "efficiency", Title: "Response caching: savings and the semantic-cache correctness trade",
		Question: "How much spend and latency do exact and semantic caching save on a realistic support workload, and at what similarity threshold does the semantic cache start serving wrong answers?",
		Calls:    "~50 completions + 60 embeddings", Quick: "100-request workload",
		Duration: "~30 s", NeedsModels: true},
}

// SpecFor finds a catalog entry.
func SpecFor(name string) (Spec, bool) {
	for _, s := range Catalog {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// RunConfig holds every knob of a named run.
type RunConfig struct {
	Root             string
	Corpus           string
	Models           []string
	Classifiers      []string
	BenchClassifiers []string
	Semantic         string
	CacheModel       string
	PerBench         int
	SlowSample       int
	Workers          int
	Limit            int
	Requests         int
	Fresh            bool
	Quick            bool
	Version          string
}

// DefaultRunConfig is a full run.
func DefaultRunConfig(root string) RunConfig {
	return RunConfig{
		Root: root, Corpus: "testdata/eval",
		Models:           []string{"gpt-5-nano", "gpt-5-mini", "gpt-4.1-nano", "gpt-oss-20b", "gpt-oss-120b", "qwen3-27b"},
		Classifiers:      []string{"prompt-guard-22m", "prompt-guard-86m", "safeguard-20b", "gpt-5-nano", "moderation"},
		BenchClassifiers: []string{"prompt-guard-86m", "gpt-5-nano", "openai-moderation", "safeguard-20b"},
		Semantic:         "prompt-guard-86m", CacheModel: "gpt-4.1-nano",
		PerBench: 160, SlowSample: 24, Workers: 6, Requests: 200, Version: "dev",
	}
}

// Quickened shrinks a run to minutes and cents. Quick runs answer the same
// question on a smaller sample; their reports say so in the configuration.
func (rc RunConfig) Quickened() RunConfig {
	rc.Quick = true
	rc.Models = []string{"gpt-4.1-nano", "gpt-oss-20b"}
	rc.Classifiers = []string{"prompt-guard-86m", "moderation"}
	rc.BenchClassifiers = []string{"prompt-guard-86m", "gpt-5-nano", "openai-moderation"}
	rc.PerBench, rc.SlowSample, rc.Limit, rc.Requests = 24, 0, 40, 100
	return rc
}

// RunNamed runs one experiment and writes it to the ledger.
func RunNamed(ctx context.Context, cfg *config.Config, router *providers.Router, pricing *telemetry.Pricing,
	rc RunConfig, name string, log io.Writer) (*Result, string, error) {
	spec, ok := SpecFor(name)
	if !ok {
		return nil, "", fmt.Errorf("unknown experiment %q", name)
	}
	env, err := NewEnv(cfg, router, pricing, filepath.Join(rc.Root, ".callcache"), rc.Fresh, log)
	if err != nil {
		return nil, "", err
	}
	ds := filepath.Join(rc.Root, "datasets")
	started := time.Now().UTC()
	conf := map[string]any{"policy": env.Policy.Name, "policy_version": env.Policy.Version, "workers": rc.Workers, "quick": rc.Quick}
	var res *Result
	switch name {
	case "detectors":
		o := DetectorsOptions{HeldOutPath: filepath.Join(ds, "heldout_detection.jsonl"), CorpusPath: rc.Corpus,
			Classifiers: rc.Classifiers, Workers: rc.Workers}
		if rc.Quick {
			o.Limit = rc.Limit
		}
		conf["classifiers"], conf["escalate_above"], conf["limit"] = o.Classifiers, 0.25, o.Limit
		res, err = RunDetectors(ctx, env, o)
	case "asr":
		o := ASROptions{Dataset: filepath.Join(ds, "asr.jsonl"), Models: rc.Models, Classifier: rc.Semantic, Workers: rc.Workers}
		conf["models"], conf["semantic_classifier"], conf["canary"] = rc.Models, rc.Semantic, Canary
		res, err = RunASR(ctx, env, o)
	case "pii":
		o := PIIOptions{Dataset: filepath.Join(ds, "pii_tasks.jsonl"), Models: rc.Models, Workers: rc.Workers}
		conf["models"] = rc.Models
		res, err = RunPII(ctx, env, o)
	case "efficiency":
		o := EfficiencyOptions{Dataset: filepath.Join(ds, "cache_workload.jsonl"), Model: rc.CacheModel, Requests: rc.Requests, Seed: 7}
		conf["model"], conf["requests"], conf["seed"] = o.Model, o.Requests, o.Seed
		res, err = RunEfficiency(ctx, env, o)
	case "benchmarks":
		o := BenchmarksOptions{Dir: filepath.Join(rc.Root, "benchmarks"), PerBench: rc.PerBench, SlowSample: max(rc.SlowSample, 1),
			Classifiers: rc.BenchClassifiers, SlowOnes: []string{"safeguard-20b"}, Workers: rc.Workers, Seed: 2026}
		conf["per_bench"], conf["slow_sample"], conf["classifiers"], conf["seed"] = o.PerBench, o.SlowSample, o.Classifiers, o.Seed
		res, err = RunBenchmarks(ctx, env, o)
	case "resilience":
		o := ResilienceOptions{Seed: 42}
		conf["seed"] = o.Seed
		res, err = RunResilience(ctx, env, o)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", name, err)
	}
	res.Experiment, res.Title, res.Question = name, spec.Title, spec.Question
	res.RunID = started.Format("20060102-150405")
	res.Version = rc.Version
	res.StartedAt, res.FinishedAt = started, time.Now().UTC()
	res.Config = conf
	res.Usage = Usage{UpstreamCalls: env.LLM.Calls, CacheReplays: env.LLM.CacheHits, CostUSD: env.LLM.CostUSD}
	dir, err := Write(rc.Root, res)
	return res, dir, err
}
