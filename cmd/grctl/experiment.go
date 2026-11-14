package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/experiment"
	"go.vicoworks.com/guard-rails-engine/internal/gateway"
	"go.vicoworks.com/guard-rails-engine/internal/telemetry"
)

func runExperiment(ctx context.Context, args []string) error {
	def := experiment.DefaultRunConfig("experiments")
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	out := fs.String("out", "experiments", "experiments root (datasets/, runs/, .callcache/)")
	models := fs.String("models", strings.Join(def.Models, ","), "catalog aliases of the target models")
	classifiers := fs.String("classifiers", strings.Join(def.Classifiers, ","), "classifiers for the detectors experiment")
	semantic := fs.String("semantic", def.Semantic, "semantic-tier classifier for the asr experiment (empty disables)")
	cacheModel := fs.String("cache-model", def.CacheModel, "upstream model for the efficiency experiment")
	corpus := fs.String("corpus", def.Corpus, "labelled corpus for the in-distribution set")
	workers := fs.Int("workers", def.Workers, "concurrent upstream calls")
	limit := fs.Int("limit", 0, "cap the number of cases in the detectors experiment")
	fresh := fs.Bool("fresh", false, "ignore the call cache and re-query every model")
	quick := fs.Bool("quick", false, "small samples and two models: minutes and cents instead of the full run")
	catalog := fs.String("catalog", "config/models.yaml", "model catalog")
	perBench := fs.Int("per-bench", def.PerBench, "benchmarks: stratified sample size per benchmark")
	slowSample := fs.Int("slow-sample", def.SlowSample, "benchmarks: cases per benchmark for rate-limited classifiers")
	benchClassifiers := fs.String("bench-classifiers", strings.Join(def.BenchClassifiers, ","), "benchmarks: classifiers to compare")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var names []string
	for _, s := range experiment.Catalog {
		names = append(names, s.Name)
	}
	which := fs.Args()
	if len(which) == 0 {
		return fmt.Errorf("usage: grctl experiment [flags] <%s|all|fetch|index>", strings.Join(names, "|"))
	}
	switch which[0] {
	case "index":
		n, err := experiment.Rerender(*out)
		if err == nil {
			fmt.Printf("re-rendered %d reports and experiments/index.html\n", n)
		}
		return err
	case "fetch":
		fmt.Println("fetching public benchmarks into", filepath.Join(*out, "benchmarks"))
		_, err := experiment.FetchBenchmarks(ctx, filepath.Join(*out, "benchmarks"), os.Stdout)
		return err
	case "all":
		which = names
	}

	// Rate-limit retries happen in the recorder, outside the latency
	// measurement. Left to the SDK, a 429 back-off would be reported as the
	// model's own latency.
	if os.Getenv("GUARDRAILS_UPSTREAM_MAX_RETRIES") == "" {
		_ = os.Setenv("GUARDRAILS_UPSTREAM_MAX_RETRIES", "-1")
	}
	if os.Getenv("GUARDRAILS_MODELS") == "" {
		_ = os.Setenv("GUARDRAILS_MODELS", *catalog)
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	pricing, err := telemetry.LoadPricing(cfg.PricingPath)
	if err != nil {
		return err
	}
	router, err := gateway.BuildRouter(cfg, nil, nil)
	if err != nil {
		return err
	}

	rc := experiment.RunConfig{Root: *out, Corpus: *corpus, Models: splitList(*models), Classifiers: splitList(*classifiers),
		BenchClassifiers: splitList(*benchClassifiers), Semantic: *semantic, CacheModel: *cacheModel,
		PerBench: *perBench, SlowSample: *slowSample, Workers: *workers, Limit: *limit, Requests: def.Requests,
		Fresh: *fresh, Version: version}
	if *quick {
		rc = rc.Quickened()
	}
	for _, name := range which {
		res, dir, err := experiment.RunNamed(ctx, cfg, router, pricing, rc, name, os.Stderr)
		if err != nil {
			return err
		}
		fmt.Printf("\n== %s ==\n", res.Title)
		for _, m := range res.Headline {
			fmt.Printf("  %-44s %s  %s\n", m.Label, m.Value, m.Hint)
		}
		for _, f := range res.Findings {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Printf("  report: %s\n", filepath.Join(dir, "report.html"))
	}
	return nil
}
