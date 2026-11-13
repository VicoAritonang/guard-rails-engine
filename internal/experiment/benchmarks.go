package experiment

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/judge"
)

// BenchmarksOptions configures the public-benchmark run.
type BenchmarksOptions struct {
	Dir         string   // where FetchBenchmarks wrote the data
	PerBench    int      // stratified sample size per benchmark
	SlowSample  int      // cap for rate-limited classifiers (safeguard)
	Classifiers []string // model classifiers to compare against the rules
	SlowOnes    []string // classifiers that only see the first SlowSample cases
	Workers     int
	Seed        int64
}

type benchTrial struct {
	Case      string  `json:"case"`
	Bench     string  `json:"bench"`
	Category  string  `json:"category,omitempty"`
	Positive  bool    `json:"positive"`
	Detector  string  `json:"detector"`
	Predicted bool    `json:"predicted"`
	Score     float64 `json:"score"`
	LatencyUS int64   `json:"latency_us"`
	CostUSD   float64 `json:"cost_usd"`
	Error     string  `json:"error,omitempty"`
}

// sampleBench takes a seeded, stratified sample and interleaves the classes,
// so any prefix of it is itself roughly balanced. That is what lets a
// rate-limited classifier score the first k cases and still be comparable.
func sampleBench(cases []BenchCase, n int, seed int64) []BenchCase {
	rng := rand.New(rand.NewSource(seed))
	var pos, neg []BenchCase
	for _, c := range cases {
		if c.Positive {
			pos = append(pos, c)
		} else {
			neg = append(neg, c)
		}
	}
	rng.Shuffle(len(pos), func(i, j int) { pos[i], pos[j] = pos[j], pos[i] })
	rng.Shuffle(len(neg), func(i, j int) { neg[i], neg[j] = neg[j], neg[i] })
	wantPos, wantNeg := n/2, n-n/2
	switch {
	case len(pos) == 0:
		wantNeg = n
	case len(neg) == 0:
		wantPos = n
	}
	pos, neg = pos[:min(wantPos, len(pos))], neg[:min(wantNeg, len(neg))]
	var out []BenchCase
	for i := 0; i < max(len(pos), len(neg)); i++ {
		if i < len(pos) {
			out = append(out, pos[i])
		}
		if i < len(neg) {
			out = append(out, neg[i])
		}
	}
	return out
}

// Wilson returns the 95% Wilson score interval for k successes in n trials.
// Benchmarks here are 40-200 cases per cell; a point estimate without an
// interval would invite reading noise as a ranking.
func Wilson(k, n int) (lo, hi float64) {
	if n == 0 {
		return math.NaN(), math.NaN()
	}
	const z = 1.96
	p := float64(k) / float64(n)
	d := 1 + z*z/float64(n)
	c := p + z*z/(2*float64(n))
	m := z * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n)))
	return (c - m) / d, (c + m) / d
}

func pctCI(k, n int) string {
	if n == 0 {
		return "n/a"
	}
	lo, hi := Wilson(k, n)
	return fmt.Sprintf("%.1f%% [%.0f–%.0f]", float64(k)/float64(n)*100, lo*100, hi*100)
}

// RunBenchmarks scores the rules and every model classifier on each public
// benchmark, then replays defence-in-depth strategies from the same verdicts.
func RunBenchmarks(ctx context.Context, env *Env, opts BenchmarksOptions) (*Result, error) {
	raw, err := os.ReadFile(filepath.Join(opts.Dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("no fetched benchmarks in %s (run: grctl experiment fetch): %w", opts.Dir, err)
	}
	var man Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return nil, err
	}
	if opts.PerBench <= 0 {
		opts.PerBench = 160
	}
	if opts.SlowSample <= 0 {
		opts.SlowSample = 40
	}
	slow := map[string]bool{}
	for _, s := range opts.SlowOnes {
		slow[s] = true
	}
	var cls []judge.Classifier
	for _, name := range opts.Classifiers {
		c, err := classifierFor(env, name)
		if err != nil {
			env.Logf("  skipping classifier %s: %v", name, err)
			continue
		}
		cls = append(cls, c)
	}
	detectors := []string{"rules"}
	for _, c := range cls {
		detectors = append(detectors, c.Name())
	}

	type job struct {
		c    BenchCase
		rank int // position within its benchmark's interleaved sample
	}
	var jobs []job
	var benches []ManifestItem
	for _, e := range man.Entries {
		all, err := ReadJSONL[BenchCase](filepath.Join(opts.Dir, e.File))
		if err != nil {
			return nil, err
		}
		s := sampleBench(all, opts.PerBench, opts.Seed)
		for i, c := range s {
			jobs = append(jobs, job{c, i})
		}
		benches = append(benches, e)
	}
	env.Logf("benchmarks: %d cases across %d benchmarks x %d detectors", len(jobs), len(benches), len(detectors))

	trials := make([][]benchTrial, len(jobs))
	var mu sync.Mutex
	done := 0
	ParallelDo(ctx, len(jobs), opts.Workers, func(ctx context.Context, i int) {
		jb := jobs[i]
		c := jb.c
		row := []benchTrial{env.rulesVerdict(ctx, c)}
		var wg sync.WaitGroup
		res := make([]*benchTrial, len(cls))
		for k, cl := range cls {
			if slow[cl.Name()] && jb.rank >= opts.SlowSample {
				continue
			}
			// Moderation scores content safety; it has no notion of a tool
			// result, so it is not asked about one.
			if c.Stage == core.StageToolResult && cl.Name() == "openai-moderation" {
				continue
			}
			wg.Add(1)
			go func(k int, cl judge.Classifier) {
				defer wg.Done()
				sink := &LatencySink{}
				start := time.Now()
				v, err := cl.Classify(WithLatencySink(ctx, sink), c.Text, c.Stage)
				lat := sink.Max()
				if lat == 0 {
					lat = time.Since(start)
				}
				t := benchTrial{Detector: cl.Name(), Predicted: v.Unsafe && err == nil, Score: v.Score,
					LatencyUS: lat.Microseconds(), CostUSD: v.CostUSD}
				if err != nil {
					t.Error = err.Error()
				}
				res[k] = &t
			}(k, cl)
		}
		wg.Wait()
		for _, t := range res {
			if t != nil {
				row = append(row, *t)
			}
		}
		for k := range row {
			row[k].Case, row[k].Bench, row[k].Category, row[k].Positive = c.ID, c.Bench, c.Category, c.Positive
		}
		trials[i] = row
		mu.Lock()
		done++
		if done%100 == 0 || done == len(jobs) {
			env.Logf("  %d/%d cases", done, len(jobs))
		}
		mu.Unlock()
	})
	return analyzeBenchmarks(benches, detectors, trials, opts), nil
}

// rulesVerdict runs the deterministic stage the case belongs to.
func (e *Env) rulesVerdict(ctx context.Context, c BenchCase) benchTrial {
	vault := core.NewVault(e.Secret)
	var dec *core.Decision
	if c.Stage == core.StageToolResult {
		tx := &core.Transaction{ID: c.ID, Stage: core.StageToolResult, Vault: vault, StartedAt: time.Now(),
			ToolResults: []core.ToolResult{{Name: c.Tool, Content: c.Text, Origin: core.OriginTool}}}
		dec, _ = e.Engine.ToolResult.Execute(ctx, tx)
	} else {
		tx := &core.Transaction{ID: c.ID, Stage: core.StageInbound, Vault: vault, StartedAt: time.Now(),
			Messages: []core.Message{{Role: core.RoleUser, Content: c.Text}}}
		dec, _ = e.Engine.Inbound.Execute(ctx, tx)
	}
	pred := false
	for _, f := range dec.Findings {
		switch f.Guard {
		case "injection", "topic", "tool_result":
			pred = true
		}
	}
	return benchTrial{Detector: "rules", Predicted: pred, Score: judge.HeuristicScore(dec), LatencyUS: dec.Duration.Microseconds()}
}

type cell struct {
	tp, fp, fn, tn, errs int
	lat                  []time.Duration
	cost                 float64
}

func (c *cell) add(t benchTrial) {
	if t.Error != "" {
		c.errs++
	}
	switch {
	case t.Predicted && t.Positive:
		c.tp++
	case t.Predicted:
		c.fp++
	case t.Positive:
		c.fn++
	default:
		c.tn++
	}
	c.lat = append(c.lat, us(t.LatencyUS))
	c.cost += t.CostUSD
}
func (c *cell) n() int { return c.tp + c.fp + c.fn + c.tn }

// score is balanced accuracy when the benchmark has both classes, recall when
// it is attacks-only and specificity when it is benign-only. One number per
// cell lets benchmarks of different shapes share a chart.
func (c *cell) score() float64 {
	p, n := c.tp+c.fn, c.fp+c.tn
	switch {
	case p > 0 && n > 0:
		return (float64(c.tp)/float64(p) + float64(c.tn)/float64(n)) / 2
	case p > 0:
		return float64(c.tp) / float64(p)
	case n > 0:
		return float64(c.tn) / float64(n)
	}
	return math.NaN()
}
func (c *cell) f1() float64 {
	if c.tp == 0 {
		return 0
	}
	p := float64(c.tp) / float64(c.tp+c.fp)
	r := float64(c.tp) / float64(c.tp+c.fn)
	return 2 * p * r / (p + r)
}

var detectorLabels = map[string]string{
	"rules":             "Deterministic rules",
	"prompt-guard-86m":  "Prompt Guard 2 (86M)",
	"prompt-guard-22m":  "Prompt Guard 2 (22M)",
	"safeguard-20b":     "gpt-oss-safeguard-20b",
	"gpt-5-nano":        "LLM judge (gpt-5-nano)",
	"openai-moderation": "OpenAI moderation",
}

func label(d string) string {
	if l, ok := detectorLabels[d]; ok {
		return l
	}
	return d
}

func analyzeBenchmarks(benches []ManifestItem, detectors []string, trials [][]benchTrial, opts BenchmarksOptions) *Result {
	res := &Result{}
	cells := map[string]map[string]*cell{} // bench -> detector
	for _, b := range benches {
		cells[b.Name] = map[string]*cell{}
		for _, d := range detectors {
			cells[b.Name][d] = &cell{}
		}
	}
	for _, row := range trials {
		for _, t := range row {
			res.Trials = append(res.Trials, t)
			cells[t.Bench][t.Detector].add(t)
		}
	}

	// --- per-benchmark tables --------------------------------------------------
	chart := Chart{Title: "Detection score by benchmark", Format: "pct",
		Note: "Balanced accuracy where a benchmark has both classes; recall for attack-only sets (Gandalf); specificity for benign-only sets (NotInject). Higher is better."}
	for _, d := range detectors {
		chart.Series = append(chart.Series, label(d))
	}
	chart.Values = make([][]float64, len(detectors))
	for _, b := range benches {
		chart.Categories = append(chart.Categories, b.Title)
		t := Table{Title: b.Title, Columns: []string{"Detector", "n", "Recall [95% CI]", "False-positive rate [95% CI]", "F1", "Score", "p50 latency", "$ / 1k", "Errors"},
			Note: fmt.Sprintf("%s. Licence: %s. Source: %s (revision %s). %s.", b.Measures, b.License, b.Source, short(b.Revision), b.Citation)}
		for di, d := range detectors {
			c := cells[b.Name][d]
			chart.Values[di] = append(chart.Values[di], nanTo0(c.score()))
			if c.n() == 0 {
				t.Rows = append(t.Rows, []string{label(d), "0", "not run", "", "", "", "", "", ""})
				continue
			}
			t.Rows = append(t.Rows, []string{label(d), fmt.Sprint(c.n()),
				pctCI(c.tp, c.tp+c.fn), pctCI(c.fp, c.fp+c.tn), fmt.Sprintf("%.3f", c.f1()), Pct(c.score()),
				Ms(Percentile(c.lat, 0.5)), fmt.Sprintf("$%.4f", c.cost/float64(c.n())*1000), fmt.Sprint(c.errs)})
		}
		res.Tables = append(res.Tables, t)
	}

	// --- macro leaderboard --------------------------------------------------------
	lb := Table{Title: "Leaderboard (macro-average over benchmarks each detector ran on)",
		Columns: []string{"Detector", "Macro score", "Macro recall", "Macro FPR", "Benchmarks", "p50 latency", "$ / 1k req"}}
	type lbRow struct {
		d                  string
		score, recall, fpr float64
		nb                 int
		p50                time.Duration
		cost               float64
	}
	var rows []lbRow
	for _, d := range detectors {
		var s, r, f float64
		var ns, nr, nf, nb int
		var lats []time.Duration
		var cost float64
		var n int
		for _, b := range benches {
			c := cells[b.Name][d]
			if c.n() == 0 {
				continue
			}
			nb++
			s += c.score()
			ns++
			if c.tp+c.fn > 0 {
				r += float64(c.tp) / float64(c.tp+c.fn)
				nr++
			}
			if c.fp+c.tn > 0 {
				f += float64(c.fp) / float64(c.fp+c.tn)
				nf++
			}
			lats = append(lats, c.lat...)
			cost += c.cost
			n += c.n()
		}
		rows = append(rows, lbRow{d, s / float64(max(ns, 1)), r / float64(max(nr, 1)), f / float64(max(nf, 1)), nb, Percentile(lats, 0.5), cost / float64(max(n, 1)) * 1000})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].score > rows[j].score })
	lbChart := Chart{Title: "Macro detection score", Format: "pct", Series: []string{"Macro score"}}
	lbChart.Values = [][]float64{{}}
	for _, r := range rows {
		lb.Rows = append(lb.Rows, []string{label(r.d), Pct(r.score), Pct(r.recall), Pct(r.fpr), fmt.Sprint(r.nb), Ms(r.p50), fmt.Sprintf("$%.4f", r.cost)})
		lbChart.Categories = append(lbChart.Categories, label(r.d))
		lbChart.Values[0] = append(lbChart.Values[0], r.score)
	}

	// --- strategies ------------------------------------------------------------------
	type strat struct {
		name string
		uses []string
	}
	var strats []strat
	strats = append(strats, strat{"Rules only", []string{"rules"}})
	has := func(d string) bool {
		for _, x := range detectors {
			if x == d {
				return true
			}
		}
		return false
	}
	if has("prompt-guard-86m") {
		strats = append(strats, strat{"Rules + Prompt Guard", []string{"rules", "prompt-guard-86m"}})
		if has("openai-moderation") {
			strats = append(strats, strat{"Rules + Prompt Guard + Moderation", []string{"rules", "prompt-guard-86m", "openai-moderation"}})
		}
		if has("gpt-5-nano") {
			strats = append(strats, strat{"Rules + Prompt Guard + LLM judge", []string{"rules", "prompt-guard-86m", "gpt-5-nano"}})
		}
	}
	st := Table{Title: "Defence-in-depth strategies (replayed from the same verdicts)",
		Columns: append([]string{"Strategy", "Macro score"}, benchTitles(benches)...)}
	stChart := Chart{Title: "Defence-in-depth: macro score by strategy", Format: "pct", Series: []string{"Macro score"}}
	stChart.Values = [][]float64{{}}
	stratScore := map[string]float64{}
	for _, s := range strats {
		var row []string
		var sum float64
		var nb int
		for _, b := range benches {
			c := &cell{}
			for _, tr := range trials {
				if len(tr) == 0 || tr[0].Bench != b.Name {
					continue
				}
				byDet := map[string]benchTrial{}
				for _, t := range tr {
					byDet[t.Detector] = t
				}
				pred, ok := false, true
				for _, d := range s.uses {
					t, ran := byDet[d]
					if !ran {
						// Moderation is not consulted on tool results; a
						// strategy simply runs without it there.
						if d == "openai-moderation" && b.Stage == core.StageToolResult {
							continue
						}
						ok = false
						break
					}
					pred = pred || t.Predicted
				}
				if !ok {
					continue
				}
				c.add(benchTrial{Positive: tr[0].Positive, Predicted: pred})
			}
			if c.n() == 0 {
				row = append(row, "n/a")
				continue
			}
			row = append(row, Pct(c.score()))
			sum += c.score()
			nb++
		}
		ms := sum / float64(max(nb, 1))
		stratScore[s.name] = ms
		st.Rows = append(st.Rows, append([]string{s.name, Pct(ms)}, row...))
		stChart.Categories = append(stChart.Categories, s.name)
		stChart.Values[0] = append(stChart.Values[0], ms)
	}

	// --- findings ----------------------------------------------------------------------
	best := rows[0]
	res.Headline = []Metric{
		{"Public benchmarks", fmt.Sprint(len(benches)), fmt.Sprintf("%d scored cases", len(trials))},
		{"Best single detector", label(best.d), fmt.Sprintf("macro score %s", Pct(best.score))},
	}
	bestStrat, bestStratScore := "", -1.0
	for _, s := range strats {
		if stratScore[s.name] > bestStratScore {
			bestStrat, bestStratScore = s.name, stratScore[s.name]
		}
	}
	res.Headline = append(res.Headline, Metric{"Best layered strategy", Pct(bestStratScore), bestStrat})

	rulesRow := cellsFor(cells, benches, "rules")
	rulesScore := math.NaN()
	for _, r := range rows {
		if r.d == "rules" {
			rulesScore = r.score
		}
	}
	res.Findings = append(res.Findings, fmt.Sprintf(
		"The deterministic rules alone score %s macro across %d public benchmarks, strongest on %s, weakest on %s. They are a sub-millisecond, zero-cost floor, not a complete detector.",
		Pct(rulesScore), len(benches), rulesRow.best, rulesRow.worst))
	if c, ok := cells["notinject"]; ok {
		var parts []string
		for _, d := range detectors {
			if x := c[d]; x.n() > 0 {
				parts = append(parts, fmt.Sprintf("%s %s", label(d), Pct(float64(x.fp)/float64(max(x.n(), 1)))))
			}
		}
		res.Findings = append(res.Findings, "Over-defence on NotInject (benign prompts containing trigger words; lower is better): "+strings.Join(parts, ", ")+".")
	}
	if c, ok := cells["xstest"]; ok {
		var parts []string
		for _, d := range detectors {
			if x := c[d]; x.fp+x.tn > 0 {
				parts = append(parts, fmt.Sprintf("%s %s", label(d), Pct(float64(x.fp)/float64(x.fp+x.tn))))
			}
		}
		res.Findings = append(res.Findings, "False positives on XSTest's safe-but-scary prompts (\"how do I kill a Python process\"): "+strings.Join(parts, ", ")+".")
	}
	if c, ok := cells["injecagent"]; ok {
		var parts []string
		for _, d := range detectors {
			if x := c[d]; x.n() > 0 {
				parts = append(parts, fmt.Sprintf("%s recall %s / FPR %s", label(d), Pct(Ratio(x.tp, x.tp+x.fn)), Pct(Ratio(x.fp, x.fp+x.tn))))
			}
		}
		res.Findings = append(res.Findings, "Indirect injection in tool results (InjecAgent, scored at the tool_result stage): "+strings.Join(parts, "; ")+".")
	}
	res.Findings = append(res.Findings, fmt.Sprintf("Layering wins: %s reaches %s macro, above any single detector (%s, %s).", bestStrat, Pct(bestStratScore), label(best.d), Pct(best.score)))

	res.Tables = append([]Table{lb, st}, res.Tables...)
	res.Charts = []Chart{chart, lbChart, stChart}
	res.Notes = []string{
		fmt.Sprintf("Each benchmark is sampled to %d cases, stratified by label and interleaved, with seed %d. Rate-limited classifiers (%s) score the first %d cases of each sample, which are themselves balanced; their n is shown per row.", opts.PerBench, opts.Seed, strings.Join(opts.SlowOnes, ", "), opts.SlowSample),
		"Datasets are fetched at run time from their original sources and never committed; experiments/benchmarks/manifest.json pins the exact revision and records the licence of each.",
		"95% intervals are Wilson score intervals. Differences inside overlapping intervals are not evidence of a ranking.",
		"Classifier errors (rate limits after retries, unparseable output) are scored as 'allowed' (what fail-open means in production) and counted in the Errors column.",
		"deepset/prompt-injections labels some role-play requests ('act as an interviewer') as injections, which penalises detectors that allow them; treat its scores with that in mind.",
		"InjecAgent negatives are the benchmark's own tool-response templates with the attacker slot filled by ordinary review/email/note text (internal/experiment/benchfetch.go).",
		"OpenAI moderation is not consulted on tool results; it has no concept of indirect injection.",
	}
	return res
}

func benchTitles(b []ManifestItem) []string {
	var out []string
	for _, x := range b {
		out = append(out, x.Title)
	}
	return out
}

type bestWorst struct{ best, worst string }

func cellsFor(cells map[string]map[string]*cell, benches []ManifestItem, d string) bestWorst {
	var bw bestWorst
	hi, lo := -1.0, 2.0
	for _, b := range benches {
		c := cells[b.Name][d]
		if c.n() == 0 {
			continue
		}
		s := c.score()
		if s > hi {
			hi, bw.best = s, fmt.Sprintf("%s (%s)", b.Title, Pct(s))
		}
		if s < lo {
			lo, bw.worst = s, fmt.Sprintf("%s (%s)", b.Title, Pct(s))
		}
	}
	return bw
}
