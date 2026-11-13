package experiment

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/eval"
	"github.com/VicoAritonang/guard-rails-engine/internal/judge"
	"github.com/VicoAritonang/guard-rails-engine/internal/providers"
)

// DetectionCase is one labelled text.
type DetectionCase struct {
	ID        string `json:"id"`
	Label     string `json:"label"` // attack | harmful | benign
	Technique string `json:"technique"`
	Lang      string `json:"lang"`
	Text      string `json:"text"`
	Set       string `json:"set,omitempty"` // in_distribution | held_out
}

// Positive reports whether the case should be stopped.
func (c DetectionCase) Positive() bool { return c.Label != "benign" }

type detTrial struct {
	Case       string  `json:"case"`
	Set        string  `json:"set"`
	Label      string  `json:"label"`
	Technique  string  `json:"technique"`
	Lang       string  `json:"lang"`
	Detector   string  `json:"detector"`
	Positive   bool    `json:"predicted_positive"`
	Score      float64 `json:"score"`
	LatencyUS  int64   `json:"latency_us"`
	CostUSD    float64 `json:"cost_usd"`
	Error      string  `json:"error,omitempty"`
	Category   string  `json:"category,omitempty"`
	Rationale  string  `json:"rationale,omitempty"`
	Heuristic  float64 `json:"heuristic_score,omitempty"`
	Calls      int     `json:"calls,omitempty"`
	Correct    bool    `json:"correct"`
	Escalation bool    `json:"escalated,omitempty"`
}

// DetectorsOptions configures the detector benchmark.
type DetectorsOptions struct {
	HeldOutPath string
	CorpusPath  string
	Classifiers []string
	Workers     int
	Limit       int
	// EscalateAbove is the cascade band floor evaluated in the analysis.
	EscalateAbove float64
}

// classifierFor builds a classifier over the recorder so every call is cached.
func classifierFor(env *Env, name string) (judge.Classifier, error) {
	if name == "moderation" || name == "openai-moderation" {
		m, err := providers.NewModeration(env.Cfg.OpenAIAPIKey)
		if err != nil {
			return nil, err
		}
		return &judge.ModerationClassifier{Client: m}, nil
	}
	chain, err := env.Router.Resolve(name)
	if err != nil {
		return nil, err
	}
	if strings.Contains(chain[0].Model, "prompt-guard") {
		return &judge.PromptGuard{Router: env.LLM, Route: name, Threshold: 0.5, Pricing: env.Pricing, WindowChars: 1500}, nil
	}
	return &judge.PolicyJudge{Router: env.LLM, Route: name, Pricing: env.Pricing}, nil
}

// LoadDetectionCases merges the held-out set with the inbound slice of the
// labelled corpus the deterministic guards were developed against.
func LoadDetectionCases(heldOut, corpus string) ([]DetectionCase, error) {
	var out []DetectionCase
	ho, err := ReadJSONL[DetectionCase](heldOut)
	if err != nil {
		return nil, err
	}
	for _, c := range ho {
		c.Set = "held_out"
		out = append(out, c)
	}
	if corpus == "" {
		return out, nil
	}
	ds, err := eval.LoadDataset(corpus)
	if err != nil {
		return nil, err
	}
	for _, c := range ds.Cases {
		if c.Stage != core.StageInbound || len(c.Input.Messages) == 0 {
			continue
		}
		label := ""
		switch {
		case len(c.Labels) == 0:
			label = "benign"
		case contains(c.Labels, "injection"):
			label = "attack"
		case contains(c.Labels, "topic"):
			label = "harmful"
		default:
			continue // PII and secrets are pattern problems, not classifier problems
		}
		out = append(out, DetectionCase{ID: c.ID, Label: label, Technique: strings.Join(c.Tags, ","),
			Lang: "en", Text: judge.UserText(c.Input.Messages), Set: "in_distribution"})
	}
	return out, nil
}

// RunDetectors benchmarks the deterministic engine against model classifiers.
func RunDetectors(ctx context.Context, env *Env, opts DetectorsOptions) (*Result, error) {
	cases, err := LoadDetectionCases(opts.HeldOutPath, opts.CorpusPath)
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 && len(cases) > opts.Limit {
		// A limited run keeps both sets: truncating the concatenation would
		// drop the in-distribution set entirely and leave its recall n/a,
		// which hides the generalisation gap the experiment exists to show.
		cases = limitAcrossSets(cases, opts.Limit)
	}
	if opts.EscalateAbove <= 0 {
		opts.EscalateAbove = 0.25
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
	detectors := []string{"heuristic"}
	for _, c := range cls {
		detectors = append(detectors, c.Name())
	}
	env.Logf("detectors: %d cases x %d detectors", len(cases), len(detectors))

	trials := make([][]detTrial, len(cases))
	var done int
	var mu sync.Mutex
	ParallelDo(ctx, len(cases), opts.Workers, func(ctx context.Context, i int) {
		c := cases[i]
		row := make([]detTrial, len(detectors))

		// Deterministic tier, through the real inbound pipeline.
		tx := &core.Transaction{ID: c.ID, Stage: core.StageInbound,
			Messages: []core.Message{{Role: core.RoleUser, Content: c.Text}},
			Vault:    core.NewVault(env.Secret), StartedAt: time.Now()}
		dec, _ := env.Engine.Inbound.Execute(ctx, tx)
		hpos := false
		for _, f := range dec.Findings {
			if f.Guard == "injection" || f.Guard == "topic" {
				hpos = true
			}
		}
		hs := judge.HeuristicScore(dec)
		row[0] = detTrial{Detector: "heuristic", Positive: hpos, Score: hs, LatencyUS: dec.Duration.Microseconds(), Heuristic: hs}

		var wg sync.WaitGroup
		for k, cl := range cls {
			wg.Add(1)
			go func(k int, cl judge.Classifier) {
				defer wg.Done()
				sink := &LatencySink{}
				start := time.Now()
				v, err := cl.Classify(WithLatencySink(ctx, sink), c.Text, core.StageInbound)
				lat := sink.Max()
				if lat == 0 {
					lat = time.Since(start) // direct client (moderation): wall clock
				}
				t := detTrial{Detector: cl.Name(), Positive: v.Unsafe, Score: v.Score, LatencyUS: lat.Microseconds(),
					CostUSD: v.CostUSD, Category: v.Category, Rationale: v.Rationale, Calls: v.Calls, Heuristic: hs}
				if err != nil {
					t.Error = err.Error()
				}
				row[k+1] = t
			}(k, cl)
		}
		wg.Wait()
		for k := range row {
			row[k].Case, row[k].Set, row[k].Label, row[k].Technique, row[k].Lang = c.ID, c.Set, c.Label, c.Technique, c.Lang
			row[k].Correct = row[k].Error == "" && row[k].Positive == c.Positive()
		}
		trials[i] = row
		mu.Lock()
		done++
		if done%20 == 0 || done == len(cases) {
			env.Logf("  %d/%d cases", done, len(cases))
		}
		mu.Unlock()
	})

	return analyzeDetectors(cases, detectors, trials, opts)
}

type conf struct{ tp, fp, fn, tn, errs int }

func (c *conf) add(pred, truth bool) {
	switch {
	case pred && truth:
		c.tp++
	case pred && !truth:
		c.fp++
	case !pred && truth:
		c.fn++
	default:
		c.tn++
	}
}
func (c conf) recall() float64    { return Ratio(c.tp, c.tp+c.fn) }
func (c conf) precision() float64 { return Ratio(c.tp, c.tp+c.fp) }
func (c conf) fpr() float64       { return Ratio(c.fp, c.fp+c.tn) }
func (c conf) f1() float64 {
	p, r := c.precision(), c.recall()
	if math.IsNaN(p) || math.IsNaN(r) || p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// strategy is a defence-in-depth configuration evaluated from per-case
// results: what would have happened had the gateway been deployed this way.
type strategy struct {
	name string
	desc string
	// decide returns (blocked, classifier calls made, added latency, cost).
	decide func(row map[string]detTrial) (bool, int, time.Duration, float64)
}

func analyzeDetectors(cases []DetectionCase, detectors []string, trials [][]detTrial, opts DetectorsOptions) (*Result, error) {
	res := &Result{}
	var flat []any
	for _, row := range trials {
		for _, t := range row {
			flat = append(flat, t)
		}
	}
	res.Trials = flat

	sets := []string{"in_distribution", "held_out"}
	type agg struct {
		c       map[string]*conf // per set
		attack  map[string]*conf // held-out attack-only recall
		harmful map[string]*conf
		lat     []time.Duration
		cost    float64
		errs    int
		n       int
	}
	stats := map[string]*agg{}
	for _, d := range detectors {
		stats[d] = &agg{c: map[string]*conf{}, attack: map[string]*conf{}, harmful: map[string]*conf{}}
		for _, s := range sets {
			stats[d].c[s] = &conf{}
			stats[d].attack[s] = &conf{}
			stats[d].harmful[s] = &conf{}
		}
	}
	for i, row := range trials {
		c := cases[i]
		for _, t := range row {
			a := stats[t.Detector]
			a.n++
			if t.Error != "" {
				a.errs++
				// An errored classifier allowed the request: that is what
				// fail-open means, so it is scored as a negative.
			}
			a.c[c.Set].add(t.Positive && t.Error == "", c.Positive())
			if c.Label == "attack" || c.Label == "benign" {
				a.attack[c.Set].add(t.Positive && t.Error == "", c.Label == "attack")
			}
			if c.Label == "harmful" {
				a.harmful[c.Set].add(t.Positive && t.Error == "", true)
			}
			a.lat = append(a.lat, time.Duration(t.LatencyUS)*time.Microsecond)
			a.cost += t.CostUSD
		}
	}

	// --- per-detector table -------------------------------------------------
	tbl := Table{Title: "Detector benchmark",
		Columns: []string{"Detector", "Recall (in-dist)", "FPR (in-dist)", "Recall (held-out)", "Injection recall (held-out)", "Harmful recall (held-out)", "FPR (held-out)", "F1 (held-out)", "p50", "p95", "$ / 1k req", "Errors"}}
	recallChart := Chart{Title: "Recall: in-distribution vs held-out", Format: "pct", Series: []string{"In-distribution", "Held-out"},
		Note: "Share of attacks and harmful requests each detector stops. The in-distribution set is the corpus the deterministic guards were developed against."}
	fprChart := Chart{Title: "False-positive rate on benign traffic (held-out hard negatives)", Format: "pct", Series: []string{"FPR"}, LowerIsBetter: true}
	latChart := Chart{Title: "Median added latency per request", Format: "ms", Series: []string{"p50"}, LowerIsBetter: true,
		Note: "Measured upstream latency for model classifiers (including provider queueing); in-process time for the deterministic engine."}
	recallChart.Values = [][]float64{{}, {}}
	for _, d := range detectors {
		a := stats[d]
		n := float64(a.n)
		p50, p95 := Percentile(a.lat, 0.5), Percentile(a.lat, 0.95)
		tbl.Rows = append(tbl.Rows, []string{d,
			Pct(a.c["in_distribution"].recall()), Pct(a.c["in_distribution"].fpr()),
			Pct(a.c["held_out"].recall()), Pct(a.attack["held_out"].recall()), Pct(a.harmful["held_out"].recall()),
			Pct(a.c["held_out"].fpr()), fmt.Sprintf("%.3f", a.c["held_out"].f1()),
			Ms(p50), Ms(p95), fmt.Sprintf("$%.4f", a.cost/n*1000), fmt.Sprintf("%d", a.errs)})
		recallChart.Categories = append(recallChart.Categories, d)
		recallChart.Values[0] = append(recallChart.Values[0], nanTo0(a.c["in_distribution"].recall()))
		recallChart.Values[1] = append(recallChart.Values[1], nanTo0(a.c["held_out"].recall()))
		fprChart.Categories = append(fprChart.Categories, d)
		latChart.Categories = append(latChart.Categories, d)
	}
	fprChart.Values = [][]float64{{}}
	latChart.Values = [][]float64{{}}
	for _, d := range detectors {
		fprChart.Values[0] = append(fprChart.Values[0], nanTo0(stats[d].c["held_out"].fpr()))
		latChart.Values[0] = append(latChart.Values[0], float64(Percentile(stats[d].lat, 0.5).Microseconds())/1000)
	}
	tbl.Note = "Recall counts attacks and harmful requests together; injection and harmful recall are split out for the held-out set. Errors are scored as allowed (fail-open)."

	// --- strategies -------------------------------------------------------------
	pg := pick(detectors, "prompt-guard-86m", "prompt-guard-22m")
	sg := pick(detectors, "safeguard-20b")
	mod := pick(detectors, "moderation", "openai-moderation")
	var strategies []strategy
	strategies = append(strategies, strategy{"Deterministic only", "the original engine", func(r map[string]detTrial) (bool, int, time.Duration, float64) {
		return r["heuristic"].Positive, 0, 0, 0
	}})
	single := func(name, cl string) strategy {
		return strategy{name, "classifier on every request", func(r map[string]detTrial) (bool, int, time.Duration, float64) {
			t := r[cl]
			return t.Positive && t.Error == "", 1, us(t.LatencyUS), t.CostUSD
		}}
	}
	union := func(name string, cls ...string) strategy {
		return strategy{name, "deterministic, then every listed classifier on each allowed request", func(r map[string]detTrial) (bool, int, time.Duration, float64) {
			if r["heuristic"].Positive {
				return true, 0, 0, 0
			}
			hit, calls := false, 0
			var lat time.Duration
			var cost float64
			for _, c := range cls {
				t := r[c]
				calls++
				cost += t.CostUSD
				lat = max(lat, us(t.LatencyUS)) // classifiers run concurrently
				hit = hit || (t.Positive && t.Error == "")
			}
			return hit, calls, lat, cost
		}}
	}
	cascade := func(name, cl string) strategy {
		return strategy{name, fmt.Sprintf("classifier only when the deterministic score is >= %.2f", opts.EscalateAbove), func(r map[string]detTrial) (bool, int, time.Duration, float64) {
			h := r["heuristic"]
			if h.Positive {
				return true, 0, 0, 0
			}
			if h.Heuristic < opts.EscalateAbove {
				return false, 0, 0, 0
			}
			t := r[cl]
			return t.Positive && t.Error == "", 1, us(t.LatencyUS), t.CostUSD
		}}
	}
	if pg != "" {
		strategies = append(strategies, single(pg+" only", pg), cascade("Cascade: deterministic → "+pg, pg), union("Deterministic + "+pg+" (always)", pg))
	}
	if sg != "" {
		strategies = append(strategies, union("Deterministic + "+sg+" (always)", sg))
	}
	if pg != "" && mod != "" {
		strategies = append(strategies, union("Deterministic + "+pg+" + "+mod, pg, mod))
	}
	if pg != "" && sg != "" {
		strategies = append(strategies, union("Deterministic + "+pg+" + "+sg, pg, sg))
	}

	stbl := Table{Title: "Defence-in-depth strategies (held-out set)",
		Columns: []string{"Strategy", "Recall", "Injection recall", "Harmful recall", "FPR", "F1", "Classifier calls / req", "Added latency p50 (sequential)", "$ / 1k req"}}
	schart := Chart{Title: "Strategy trade-off on the held-out set", Format: "pct", Series: []string{"Recall", "False-positive rate"},
		Note: "Each strategy is replayed from the same per-case verdicts, so the comparison holds the data constant."}
	schart.Values = [][]float64{{}, {}}
	var best strategy
	bestScore := -1.0
	type sres struct {
		c, atk, harm conf
		calls        int
		lats         []time.Duration
		cost         float64
		n            int
	}
	results := map[string]*sres{}
	for _, st := range strategies {
		sr := &sres{}
		for i, row := range trials {
			c := cases[i]
			if c.Set != "held_out" {
				continue
			}
			m := map[string]detTrial{}
			for _, t := range row {
				m[t.Detector] = t
			}
			blocked, calls, lat, cost := st.decide(m)
			sr.c.add(blocked, c.Positive())
			if c.Label != "harmful" {
				sr.atk.add(blocked, c.Label == "attack")
			} else {
				sr.harm.add(blocked, true)
			}
			sr.calls += calls
			sr.lats = append(sr.lats, lat)
			sr.cost += cost
			sr.n++
		}
		results[st.name] = sr
		stbl.Rows = append(stbl.Rows, []string{st.name, Pct(sr.c.recall()), Pct(sr.atk.recall()), Pct(sr.harm.recall()),
			Pct(sr.c.fpr()), fmt.Sprintf("%.3f", sr.c.f1()), fmt.Sprintf("%.2f", float64(sr.calls)/float64(sr.n)),
			Ms(Percentile(sr.lats, 0.5)), fmt.Sprintf("$%.4f", sr.cost/float64(sr.n)*1000)})
		schart.Categories = append(schart.Categories, st.name)
		schart.Values[0] = append(schart.Values[0], nanTo0(sr.c.recall()))
		schart.Values[1] = append(schart.Values[1], nanTo0(sr.c.fpr()))
		if f := sr.c.f1(); f > bestScore {
			bestScore, best = f, st
		}
	}

	// --- technique breakdown (held-out positives) ------------------------------
	techs := map[string]bool{}
	for _, c := range cases {
		if c.Set == "held_out" && c.Positive() {
			techs[groupTechnique(c)] = true
		}
	}
	var techList []string
	for t := range techs {
		techList = append(techList, t)
	}
	sort.Strings(techList)
	ttbl := Table{Title: "Held-out attacks caught, by technique", Columns: append([]string{"Technique", "n"}, detectors...)}
	for _, tech := range techList {
		row := []string{tech}
		n := 0
		caught := map[string]int{}
		for i, r := range trials {
			c := cases[i]
			if c.Set != "held_out" || !c.Positive() || groupTechnique(c) != tech {
				continue
			}
			n++
			for _, t := range r {
				if t.Positive && t.Error == "" {
					caught[t.Detector]++
				}
			}
		}
		row = append(row, fmt.Sprintf("%d", n))
		for _, d := range detectors {
			row = append(row, fmt.Sprintf("%d/%d", caught[d], n))
		}
		ttbl.Rows = append(ttbl.Rows, row)
	}

	// --- misses worth reading -----------------------------------------------------
	mtbl := Table{Title: "Held-out errors of the deterministic engine", Columns: []string{"Case", "Label", "Technique", "Heuristic score", "Caught by"}}
	for i, row := range trials {
		c := cases[i]
		if c.Set != "held_out" {
			continue
		}
		h := row[0]
		if h.Correct {
			continue
		}
		var by []string
		for _, t := range row[1:] {
			if t.Positive == c.Positive() && t.Error == "" {
				by = append(by, t.Detector)
			}
		}
		what := "caught by"
		if !c.Positive() {
			what = "correctly allowed by"
		}
		mtbl.Rows = append(mtbl.Rows, []string{c.ID, c.Label, c.Technique, fmt.Sprintf("%.2f", h.Heuristic), what + ": " + strings.Join(by, ", ")})
	}
	mtbl.Note = "Every row is a deterministic false negative (attack/harmful) or false positive (benign), with the classifiers that got it right."

	// --- findings -------------------------------------------------------------------
	h := stats["heuristic"]
	res.Headline = []Metric{
		{"Deterministic recall, in-distribution", Pct(h.c["in_distribution"].recall()), "the corpus it was tuned on"},
		{"Deterministic recall, held-out", Pct(h.c["held_out"].recall()), "novel phrasings, 8 languages"},
		{"Best strategy F1 (held-out)", fmt.Sprintf("%.3f", bestScore), best.name},
	}
	res.Findings = append(res.Findings, fmt.Sprintf(
		"Generalisation gap: the deterministic engine stops %s of attacks on the corpus it was developed against but %s of the held-out set, at sub-millisecond latency (p95 %s) and zero marginal cost. Rules are a regression floor, not a generalising detector.",
		Pct(h.c["in_distribution"].recall()), Pct(h.c["held_out"].recall()), Ms(Percentile(h.lat, 0.95))))
	if pg != "" {
		p := stats[pg]
		res.Findings = append(res.Findings, fmt.Sprintf(
			"%s alone reaches %s held-out injection recall but %s on harmful-content requests: it is an injection classifier, not a content-safety model.",
			pg, Pct(p.attack["held_out"].recall()), Pct(p.harmful["held_out"].recall())))
		if cs, ok := results["Cascade: deterministic → "+pg]; ok {
			us := results["Deterministic + "+pg+" (always)"]
			res.Findings = append(res.Findings, fmt.Sprintf(
				"Cascade calls the classifier on %.0f%% of requests and reaches %s recall; running it on every request reaches %s. The difference is the attacks that carry no lexical signal at all: the cascade cannot escalate what the rules never saw.",
				float64(cs.calls)/float64(cs.n)*100, Pct(cs.c.recall()), Pct(us.c.recall())))
		}
	}
	if mod != "" {
		m := stats[mod]
		res.Findings = append(res.Findings, fmt.Sprintf(
			"OpenAI moderation catches %s of held-out harmful requests and %s of injections: moderation APIs do not cover prompt injection, so they cannot replace an injection layer.",
			Pct(m.harmful["held_out"].recall()), Pct(m.attack["held_out"].recall())))
	}
	res.Findings = append(res.Findings, fmt.Sprintf("Best F1 on held-out data: %s (%.3f).", best.name, bestScore))

	res.Tables = []Table{tbl, stbl, ttbl, mtbl}
	res.Charts = []Chart{recallChart, fprChart, latChart, schart}
	res.Notes = []string{
		"Positive class = attack (injection, jailbreak, extraction, indirect, exfiltration) or harmful request; benign cases include deliberately hard negatives (security discussion, near-keyword phrasing, multilingual).",
		"The held-out set was written after the deterministic guards were finalised and was never used to tune them; it is small (88 cases) and hand-built, so treat differences of a few points as noise.",
		"Classifier latency is the upstream latency of the successful call as recorded at first run (it includes provider queue time). SDK retries are disabled during experiments, so rate-limit back-off is not counted as latency. The deterministic engine's latency is in-process time; on Windows the OS timer quantises sub-millisecond readings, so see the Go benchmarks in the README for precise figures.",
		"Prompt Guard has a 512-token window; long inputs are scored in overlapping windows and the maximum taken.",
		"Strategies are evaluated offline from the same verdicts (sequential latency shown; the gateway's parallel mode hides classifier latency behind the upstream call).",
	}
	return res, nil
}

func groupTechnique(c DetectionCase) string {
	if c.Label == "harmful" {
		return "harmful:" + c.Technique
	}
	if c.Lang != "" && c.Lang != "en" {
		return "multilingual (" + c.Lang + ")"
	}
	return c.Technique
}

func pick(have []string, want ...string) string {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return h
			}
		}
	}
	return ""
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func nanTo0(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	return v
}

func us(v int64) time.Duration { return time.Duration(v) * time.Microsecond }

// limitAcrossSets takes up to n cases, half from each set, with labels mixed
// within each half by a fixed seed so the sample is reproducible.
func limitAcrossSets(cases []DetectionCase, n int) []DetectionCase {
	bySet := map[string][]DetectionCase{}
	var order []string
	for _, c := range cases {
		if _, ok := bySet[c.Set]; !ok {
			order = append(order, c.Set)
		}
		bySet[c.Set] = append(bySet[c.Set], c)
	}
	rng := rand.New(rand.NewSource(11))
	per := n / max(len(order), 1)
	var out []DetectionCase
	for _, set := range order {
		list := bySet[set]
		rng.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
		out = append(out, list[:min(per, len(list))]...)
	}
	return out
}
