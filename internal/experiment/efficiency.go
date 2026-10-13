package experiment

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/cache"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/providers"
)

// FAQGroup is one question with paraphrases (same answer) and near-misses
// (similar wording, different answer).
type FAQGroup struct {
	ID          string   `json:"id"`
	Canonical   string   `json:"canonical"`
	Paraphrases []string `json:"paraphrases"`
	NearMiss    []string `json:"near_miss"`
}

// EfficiencyOptions configures the cache experiment.
type EfficiencyOptions struct {
	Dataset    string
	Model      string
	Requests   int
	Seed       int64
	Thresholds []float64
}

// memoEmbedder embeds each distinct text once and replays the vector and the
// latency measured the first time, so every cache configuration in the replay
// sees identical embeddings.
type memoEmbedder struct {
	inner cache.Embedder
	mu    sync.Mutex
	vecs  map[string][]float32
	lat   map[string]time.Duration
	toks  map[string]int
}

func (m *memoEmbedder) Model() string { return m.inner.Model() }
func (m *memoEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, int, error) {
	out := make([][]float32, len(texts))
	tok := 0
	var missing []string
	m.mu.Lock()
	for _, t := range texts {
		if _, ok := m.vecs[t]; !ok {
			missing = append(missing, t)
		}
	}
	m.mu.Unlock()
	if len(missing) > 0 {
		start := time.Now()
		vecs, n, err := m.inner.Embed(ctx, missing)
		if err != nil {
			return nil, 0, err
		}
		per := time.Since(start)
		m.mu.Lock()
		for i, t := range missing {
			m.vecs[t] = vecs[i]
			m.lat[t] = per
			m.toks[t] = max(n/len(missing), 1)
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range texts {
		out[i] = m.vecs[t]
		tok += m.toks[t]
	}
	return out, tok, nil
}

type effTrial struct {
	Config     string  `json:"config"`
	Seq        int     `json:"seq"`
	Query      string  `json:"query"`
	Identity   string  `json:"identity"`
	Kind       string  `json:"kind"`
	Result     string  `json:"result"` // miss | hit_exact | hit_semantic
	Similarity float64 `json:"similarity,omitempty"`
	Wrong      bool    `json:"wrong_answer"`
	LatencyMS  float64 `json:"latency_ms"`
	CostUSD    float64 `json:"cost_usd"`
}

// RunEfficiency measures exact and semantic caching: what each saves, and
// what the semantic cache costs in wrong answers.
func RunEfficiency(ctx context.Context, env *Env, opts EfficiencyOptions) (*Result, error) {
	groups, err := ReadJSONL[FAQGroup](opts.Dataset)
	if err != nil {
		return nil, err
	}
	if opts.Model == "" {
		opts.Model = "gpt-4.1-nano"
	}
	if opts.Requests <= 0 {
		opts.Requests = 200
	}
	if len(opts.Thresholds) == 0 {
		opts.Thresholds = []float64{0.80, 0.85, 0.88, 0.90, 0.92, 0.94, 0.96, 0.98}
	}
	inner, err := providers.NewOpenAIEmbedder(env.Cfg.OpenAIAPIKey, "")
	if err != nil {
		return nil, err
	}
	emb := &memoEmbedder{inner: inner, vecs: map[string][]float32{}, lat: map[string]time.Duration{}, toks: map[string]int{}}

	// Identity: paraphrases share their canonical's answer; each near-miss is
	// a different question with its own answer.
	identity := map[string]string{}
	var all []string
	for _, g := range groups {
		identity[g.Canonical] = g.ID
		all = append(all, g.Canonical)
		for _, p := range g.Paraphrases {
			identity[p] = g.ID
			all = append(all, p)
		}
		for i, n := range g.NearMiss {
			identity[n] = fmt.Sprintf("%s/near-%d", g.ID, i)
			all = append(all, n)
		}
	}
	env.Logf("efficiency: embedding %d texts", len(all))
	if _, _, err := emb.Embed(ctx, all); err != nil {
		return nil, err
	}

	// A semantic lookup embeds ONE query. The batch above amortises one round
	// trip over every text, so its timing says nothing about lookup latency;
	// measure single-text calls and charge their median to every lookup.
	var singles []time.Duration
	for i := 0; i < 7 && i < len(all); i++ {
		start := time.Now()
		if _, _, err := inner.Embed(ctx, []string{all[i] + " "}); err != nil {
			return nil, err
		}
		singles = append(singles, time.Since(start))
	}
	lookupLatency := Percentile(singles, 0.5)
	for t := range emb.lat {
		emb.lat[t] = lookupLatency
	}

	// --- Part A: threshold sweep -------------------------------------------------
	// Leave-one-out over every question the cache could hold: canonicals,
	// paraphrases AND near-misses, because in production the cache stores
	// whatever was asked first. A paraphrase whose nearest stored neighbour is
	// above threshold and shares its identity is a useful hit; any query whose
	// nearest neighbour above threshold has a different identity would be
	// served another question's answer.
	type cand struct {
		text, id string
		vec      []float32
		norm     float64
	}
	var stored []cand
	for _, t := range all {
		v := emb.vecs[t]
		stored = append(stored, cand{t, identity[t], v, cache.Norm(v)})
	}
	nearest := func(t string) (string, float64) {
		v := emb.vecs[t]
		n := cache.Norm(v)
		best, bestSim := "", -1.0
		for _, c := range stored {
			if c.text == t {
				continue
			}
			if s := cache.Cosine(v, n, c.vec, c.norm); s > bestSim {
				best, bestSim = c.id, s
			}
		}
		return best, bestSim
	}
	sweep := Table{Title: "Semantic cache threshold sweep (leave-one-out)", Columns: []string{"Threshold", "Paraphrases answered correctly from cache", "Any query served a different question's answer"}}
	sweepChart := Chart{Title: "Semantic cache: useful hits vs wrong answers by threshold", Format: "pct",
		Series: []string{"Paraphrases answered from cache (useful)", "Queries given another question's answer (harmful)"},
		Note:   "Each question is matched against every other stored question. Near-miss questions (similar wording, different answer) are what make low thresholds dangerous."}
	sweepChart.Values = [][]float64{{}, {}}
	type pt struct{ t, useful, harm float64 }
	var pts []pt
	for _, th := range opts.Thresholds {
		var pn, phit, qn, qwrong int
		for _, t := range all {
			id, sim := nearest(t)
			qn++
			if sim >= th && id != identity[t] {
				qwrong++
			}
		}
		for _, g := range groups {
			for _, p := range g.Paraphrases {
				pn++
				if id, sim := nearest(p); sim >= th && id == g.ID {
					phit++
				}
			}
		}
		u, h := Ratio(phit, pn), Ratio(qwrong, qn)
		pts = append(pts, pt{th, u, h})
		sweep.Rows = append(sweep.Rows, []string{fmt.Sprintf("%.2f", th), Pct(u), Pct(h)})
		sweepChart.Categories = append(sweepChart.Categories, fmt.Sprintf("threshold %.2f", th))
		sweepChart.Values[0] = append(sweepChart.Values[0], u)
		sweepChart.Values[1] = append(sweepChart.Values[1], h)
	}
	// The safe operating point: the lowest threshold at and above which no
	// query is served another question's answer.
	safe := opts.Thresholds[len(opts.Thresholds)-1]
	safeUseful := 0.0
	for i := len(pts) - 1; i >= 0; i-- {
		if pts[i].harm > 0 {
			break
		}
		safe, safeUseful = pts[i].t, pts[i].useful
	}

	// --- Part B: workload replay ---------------------------------------------------
	rng := rand.New(rand.NewSource(opts.Seed))
	weights := make([]float64, len(groups))
	var wsum float64
	for i := range groups {
		weights[i] = 1 / float64(i+1) // Zipf: a few questions dominate support traffic
		wsum += weights[i]
	}
	type req struct{ text, kind string }
	var workload []req
	for range opts.Requests {
		x := rng.Float64() * wsum
		gi := 0
		for gi < len(groups)-1 && x > weights[gi] {
			x -= weights[gi]
			gi++
		}
		g := groups[gi]
		switch k := rng.Float64(); {
		case k < 0.5:
			workload = append(workload, req{g.Canonical, "repeat"})
		case k < 0.85:
			workload = append(workload, req{g.Paraphrases[rng.Intn(len(g.Paraphrases))], "paraphrase"})
		default:
			workload = append(workload, req{g.NearMiss[rng.Intn(len(g.NearMiss))], "near_miss"})
		}
	}

	// Upstream answers for every distinct question, recorded once.
	answers := map[string]*providers.Response{}
	var amu sync.Mutex
	distinct := map[string]bool{}
	for _, w := range workload {
		distinct[w.text] = true
	}
	var list []string
	for t := range distinct {
		list = append(list, t)
	}
	env.Logf("efficiency: %d requests, %d distinct questions upstream on %s", len(workload), len(list), opts.Model)
	var firstErr error
	ParallelDo(ctx, len(list), 6, func(ctx context.Context, i int) {
		r, err := env.LLM.Complete(ctx, providers.Request{Model: opts.Model,
			System:   "You are Nusantara Shop's support assistant. Answer in under 60 words.",
			Messages: []core.Message{{Role: core.RoleUser, Content: list[i]}}, MaxTokens: 200})
		amu.Lock()
		defer amu.Unlock()
		if err != nil {
			firstErr = err
			return
		}
		answers[list[i]] = r
	})
	if firstErr != nil {
		return nil, firstErr
	}

	embedCost := func(t string) float64 { return env.Pricing.InputCost("text-embedding-3-small", emb.toks[t]) }
	type cfg struct {
		name     string
		exact    bool
		semantic float64
	}
	configs := []cfg{{"No cache", false, 0}, {"Exact cache", true, 0}}
	for _, t := range []float64{safe, 0.85} {
		dup := false
		for _, c := range configs {
			if c.semantic == t {
				dup = true
			}
		}
		if !dup {
			configs = append(configs, cfg{fmt.Sprintf("Exact + semantic @ %.2f", t), true, t})
		}
	}
	res := &Result{}
	tbl := Table{Title: "Workload replay", Columns: []string{"Configuration", "Requests", "Upstream calls", "Hit rate", "Wrong answers", "Total cost", "Cost vs no cache", "Mean latency", "p95 latency"}}
	costChart := Chart{Title: "Cost of the workload by cache configuration", Format: "usd", Series: []string{"Total spend"}, LowerIsBetter: true}
	latChart := Chart{Title: "Mean response latency by cache configuration", Format: "ms", Series: []string{"Mean latency"}, LowerIsBetter: true}
	costChart.Values, latChart.Values = [][]float64{{}}, [][]float64{{}}
	var baseCost float64
	type summary struct {
		hit, wrong float64
		cost       float64
		mean       time.Duration
	}
	sums := map[string]summary{}
	for _, c := range configs {
		ex := cache.NewExact(10_000, 24*time.Hour)
		var sem *cache.Semantic
		if c.semantic > 0 {
			sem = cache.NewSemantic(emb, cache.SemanticOptions{Threshold: c.semantic, TTL: 24 * time.Hour})
		}
		var calls, hits, wrong int
		var cost float64
		var lats []time.Duration
		var sumLat time.Duration
		for i, w := range workload {
			t := effTrial{Config: c.name, Seq: i, Query: w.text, Identity: identity[w.text], Kind: w.kind, Result: "miss"}
			lat := time.Duration(0)
			key := cache.Key(cache.KeyInput{Model: opts.Model, Messages: []core.Message{{Role: core.RoleUser, Content: w.text}}})
			served := false
			if c.exact {
				if _, ok := ex.Get(key); ok {
					t.Result, served = "hit_exact", true
				}
			}
			var vec []float32
			if !served && sem != nil {
				m, v, _, _ := sem.Lookup(ctx, "b", w.text)
				vec = v
				lat += emb.lat[w.text]
				cost += embedCost(w.text)
				t.CostUSD += embedCost(w.text)
				if m != nil {
					t.Result, t.Similarity, served = "hit_semantic", m.Similarity, true
					t.Wrong = identity[m.Query] != identity[w.text]
				}
			}
			if served {
				hits++
				if t.Wrong {
					wrong++
				}
			} else {
				a := answers[w.text]
				calls++
				lat += a.Latency
				cc := env.Pricing.Cost(a.Model, a.Usage)
				cost += cc
				t.CostUSD += cc
				e := cache.Entry{Text: a.Text, Model: a.Model}
				if c.exact {
					ex.Put(key, e)
				}
				if sem != nil {
					sem.Store("b", w.text, vec, e)
				}
			}
			t.LatencyMS = float64(lat.Microseconds()) / 1000
			lats = append(lats, lat)
			sumLat += lat
			res.Trials = append(res.Trials, t)
		}
		if c.name == "No cache" {
			baseCost = cost
		}
		mean := sumLat / time.Duration(len(workload))
		sums[c.name] = summary{Ratio(hits, len(workload)), Ratio(wrong, len(workload)), cost, mean}
		tbl.Rows = append(tbl.Rows, []string{c.name, fmt.Sprintf("%d", len(workload)), fmt.Sprintf("%d", calls),
			Pct(Ratio(hits, len(workload))), fmt.Sprintf("%d (%s)", wrong, Pct(Ratio(wrong, len(workload)))),
			fmt.Sprintf("$%.5f", cost), fmt.Sprintf("%+.1f%%", (cost/baseCost-1)*100), Ms(mean), Ms(Percentile(lats, 0.95))})
		costChart.Categories = append(costChart.Categories, c.name)
		costChart.Values[0] = append(costChart.Values[0], cost)
		latChart.Categories = append(latChart.Categories, c.name)
		latChart.Values[0] = append(latChart.Values[0], float64(mean.Microseconds())/1000)
	}

	ex := sums["Exact cache"]
	semName := fmt.Sprintf("Exact + semantic @ %.2f", safe)
	sm := sums[semName]
	res.Headline = []Metric{
		{"Exact cache hit rate", Pct(ex.hit), fmt.Sprintf("spend %.0f%% lower, mean latency %s", (1-ex.cost/baseCost)*100, Ms(ex.mean))},
		{"Semantic cache hit rate", Pct(sm.hit), fmt.Sprintf("at threshold %.2f, %s wrong answers", safe, Pct(sm.wrong))},
		{"Semantic lookup latency", Ms(lookupLatency), "one embedding round-trip per exact miss"},
	}
	res.Findings = []string{
		fmt.Sprintf("On a Zipf-distributed support workload the exact cache serves %s of requests, cutting spend %.0f%% and mean latency from %s to %s.",
			Pct(ex.hit), (1-ex.cost/baseCost)*100, Ms(sums["No cache"].mean), Ms(ex.mean)),
		fmt.Sprintf("The lowest threshold at which no stored question is served another's answer is %.2f; at that point only %s of paraphrases hit. With text-embedding-3-small, paraphrases and near-miss questions overlap in similarity, so the semantic cache buys few extra hits before it starts answering the wrong question.", safe, Pct(safeUseful)),
	}
	for _, c := range configs {
		if s, ok := sums[c.name]; ok && c.semantic > 0 && s.wrong > 0 {
			res.Findings = append(res.Findings, fmt.Sprintf(
				"%s serves %s of requests, and %s of all responses are another question's answer: a correctness failure that no latency or cost dashboard would show.",
				c.name, Pct(s.hit), Pct(s.wrong)))
		}
	}
	if sm.mean > ex.mean {
		res.Findings = append(res.Findings, fmt.Sprintf(
			"The semantic layer raises mean latency (%s vs %s with the exact cache alone): every exact miss now pays a %s embedding round-trip, and on this workload too few of those misses become hits to pay it back.",
			Ms(sm.mean), Ms(ex.mean), Ms(lookupLatency)))
	}
	res.Findings = append(res.Findings, "Recommendation: ship the exact cache on by default and the semantic cache off, enabling it per route only after a sweep like this one on that route's own traffic.")
	res.Tables = []Table{sweep, tbl}
	res.Charts = []Chart{sweepChart, costChart, latChart}
	res.Notes = []string{
		fmt.Sprintf("Workload: %d requests drawn Zipf(1) over %d FAQ groups; 50%% exact repeats, 35%% paraphrases, 15%% near-miss questions with different answers. Seed %d.", opts.Requests, len(groups), opts.Seed),
		"Upstream answers and latencies were recorded once per distinct question and replayed into every configuration, so configurations differ only in caching.",
		"Semantic lookup latency is the median of single-query embedding calls measured in this run; embedding cost is priced at text-embedding-3-small rates.",
		"A wrong answer is a semantic hit whose stored question has a different identity (a near-miss, or another group).",
	}
	return res, nil
}
