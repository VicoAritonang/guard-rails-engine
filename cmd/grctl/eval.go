package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/eval"
)

func runEval(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	dataset := fs.String("dataset", "testdata/eval", "labelled dataset file or directory (.jsonl)")
	policyPath := fs.String("policy", "", "policy YAML (default: built-in balanced policy)")
	strict := fs.Bool("strict", false, "use the built-in strict policy instead of balanced")
	outDir := fs.String("out", "", "directory to write report.json and report.md")
	redteam := fs.Bool("redteam", false, "also generate and score evasion variants")
	sweepSpec := fs.String("sweep", "", "threshold sweep as guard:family, e.g. injection:injection")
	sweepSteps := fs.Int("sweep-steps", 19, "number of threshold points in the sweep")
	quiet := fs.Bool("quiet", false, "suppress the markdown report on stdout")

	minF1 := fs.Float64("min-f1", 0, "gate: fail if macro F1 falls below this")
	minRecall := fs.Float64("min-recall", 0, "gate: fail if any family's recall falls below this")
	minPrecision := fs.Float64("min-precision", 0, "gate: fail if any family's precision falls below this")
	maxFPR := fs.Float64("max-benign-fpr", 0, "gate: fail if the benign false-positive rate exceeds this")
	maxP99 := fs.Duration("max-p99", 0, "gate: fail if any stage p99 exceeds this (e.g. 50ms)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadPolicy(*policyPath, *strict)
	if err != nil {
		return err
	}

	ds, err := eval.LoadDataset(*dataset)
	if err != nil {
		return err
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "loaded %d cases from %s\n", len(ds.Cases), *dataset)
	}

	if *redteam {
		rt := eval.GenerateRedTeam(ds, nil)
		ds.Cases = append(ds.Cases, rt.Cases...)
		if !*quiet {
			fmt.Fprintf(os.Stderr, "generated %d red-team variants\n", len(rt.Cases))
		}
	}

	h, err := eval.NewHarnessFromPolicy(pol, evalSecret())
	if err != nil {
		return err
	}

	start := time.Now()
	rep, err := h.Run(ctx, ds)
	if err != nil {
		return err
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "scored %d cases in %s\n", rep.Cases, time.Since(start).Round(time.Millisecond))
	}

	var evasion *eval.EvasionReport
	if *redteam {
		evasion = eval.ScoreEvasion(rep)
	}

	var sweeps []*eval.Sweep
	if *sweepSpec != "" {
		guard, family, ok := strings.Cut(*sweepSpec, ":")
		if !ok {
			return fmt.Errorf("--sweep expects guard:family, got %q", *sweepSpec)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "sweeping %s over %d thresholds...\n", guard, *sweepSteps)
		}
		sw, err := eval.RunSweep(ctx, pol, ds, guard, family, *sweepSteps, evalSecret())
		if err != nil {
			return err
		}
		sweeps = append(sweeps, sw)
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		jsonPath := filepath.Join(*outDir, "report.json")
		jf, err := os.Create(jsonPath)
		if err != nil {
			return err
		}
		if err := eval.WriteJSON(jf, rep); err != nil {
			jf.Close()
			return err
		}
		jf.Close()

		mdPath := filepath.Join(*outDir, "report.md")
		mf, err := os.Create(mdPath)
		if err != nil {
			return err
		}
		if err := eval.WriteMarkdown(mf, rep, sweeps, evasion); err != nil {
			mf.Close()
			return err
		}
		mf.Close()
		fmt.Fprintf(os.Stderr, "wrote %s and %s\n", jsonPath, mdPath)
	}

	if !*quiet {
		if err := eval.WriteMarkdown(os.Stdout, rep, sweeps, evasion); err != nil {
			return err
		}
	}

	gate := eval.Gate{
		MinMacroF1:   *minF1,
		MinRecall:    *minRecall,
		MinPrecision: *minPrecision,
		MaxBenignFPR: *maxFPR,
		MaxP99:       *maxP99,
		MaxErrors:    0,
	}
	if failures := gate.Check(rep); len(failures) > 0 {
		var b strings.Builder
		b.WriteString("quality gate failed:\n")
		for _, f := range failures {
			fmt.Fprintf(&b, "  - %s\n", f)
		}
		return &gateError{msg: b.String()}
	}
	return nil
}

func runRedteam(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("redteam", flag.ExitOnError)
	dataset := fs.String("dataset", "testdata/eval", "labelled dataset to derive variants from")
	policyPath := fs.String("policy", "", "policy YAML")
	strict := fs.Bool("strict", false, "use the built-in strict policy")
	only := fs.String("only", "", "comma-separated mutator names (default: all)")
	minCatch := fs.Float64("min-catch-rate", 0, "gate: fail if overall catch rate falls below this")
	dump := fs.String("dump", "", "write the generated variants to this .jsonl file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadPolicy(*policyPath, *strict)
	if err != nil {
		return err
	}
	base, err := eval.LoadDataset(*dataset)
	if err != nil {
		return err
	}

	var names []string
	if *only != "" {
		names = strings.Split(*only, ",")
	}
	rt := eval.GenerateRedTeam(base, names)
	if len(rt.Cases) == 0 {
		return fmt.Errorf("redteam: no variants generated (dataset has no labelled inbound attacks?)")
	}
	fmt.Fprintf(os.Stderr, "generated %d variants from %d source cases\n", len(rt.Cases), len(base.Cases))

	if *dump != "" {
		if err := dumpDataset(*dump, rt); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *dump)
	}

	h, err := eval.NewHarnessFromPolicy(pol, evalSecret())
	if err != nil {
		return err
	}
	rep, err := h.Run(ctx, rt)
	if err != nil {
		return err
	}
	er := eval.ScoreEvasion(rep)

	if err := eval.WriteMarkdown(os.Stdout, rep, nil, er); err != nil {
		return err
	}

	if *minCatch > 0 && er.Total > 0 {
		rate := float64(er.Caught) / float64(er.Total)
		if rate < *minCatch {
			return &gateError{msg: fmt.Sprintf(
				"quality gate failed:\n  - evasion catch rate = %.3f, want >= %.3f\n", rate, *minCatch)}
		}
	}
	return nil
}

func loadPolicy(path string, strict bool) (*config.Policy, error) {
	if path != "" {
		return config.LoadPolicy(path)
	}
	pol := config.DefaultPolicy()
	if strict {
		pol = config.StrictPolicy()
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return pol, nil
}

// evalSecret is fixed so that vault placeholders are byte-identical across
// runs. A random secret would make every redaction diff noisy and would break
// golden-file comparison of reports.
func evalSecret() []byte { return []byte("grctl-deterministic-eval-secret") }

func dumpDataset(path string, ds *eval.Dataset) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := jsonEncoder(f)
	for _, c := range ds.Cases {
		if err := enc.Encode(c); err != nil {
			return err
		}
	}
	return nil
}
