package eval

import (
	"context"
	"fmt"
	"sort"
	"time"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards"
)

// Harness runs a dataset through an engine and scores the result.
type Harness struct {
	engine *guards.Engine
	policy *config.Policy
	secret []byte
}

// NewHarness builds a harness over an already-constructed engine.
func NewHarness(engine *guards.Engine, pol *config.Policy, secret []byte) *Harness {
	if len(secret) == 0 {
		secret = []byte("eval-fixed-secret")
	}
	return &Harness{engine: engine, policy: pol, secret: secret}
}

// NewHarnessFromPolicy builds engine and harness together, which is what the
// threshold sweep needs since each threshold requires its own engine.
func NewHarnessFromPolicy(pol *config.Policy, secret []byte) (*Harness, error) {
	if len(secret) == 0 {
		secret = []byte("eval-fixed-secret")
	}
	e, err := guards.Build(pol, guards.Deps{Secret: secret})
	if err != nil {
		return nil, err
	}
	return NewHarness(e, pol, secret), nil
}

// CaseResult is the per-case outcome.
type CaseResult struct {
	ID       string        `json:"id"`
	Stage    core.Stage    `json:"stage"`
	Tags     []string      `json:"tags,omitempty"`
	Variant  string        `json:"variant,omitempty"`
	Source   string        `json:"source,omitempty"`
	Expected []string      `json:"expected_labels"`
	Detected []string      `json:"detected_families"`
	Action   core.Action   `json:"action"`
	Expect   core.Action   `json:"expected_action,omitempty"`
	Duration time.Duration `json:"duration_ns"`
	Degraded bool          `json:"degraded,omitempty"`

	// Missed and Spurious make a failing run actionable without re-deriving
	// them from the two label lists.
	Missed   []string `json:"missed,omitempty"`
	Spurious []string `json:"spurious,omitempty"`

	TopScore float64 `json:"top_score,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// Correct reports whether detection matched the labels exactly.
func (r *CaseResult) Correct() bool { return len(r.Missed) == 0 && len(r.Spurious) == 0 }

// Report is the full evaluation result.
type Report struct {
	Dataset     string    `json:"dataset"`
	Policy      string    `json:"policy"`
	PolicyName  string    `json:"policy_name"`
	GeneratedAt time.Time `json:"generated_at"`
	Cases       int       `json:"cases"`

	ByFamily map[string]Confusion `json:"by_family"`
	Overall  Confusion            `json:"overall"`
	MacroF1  float64              `json:"macro_f1"`

	// ActionAccuracy scores enforcement rather than detection: how often the
	// final action equalled the expected one, over cases that declared one.
	ActionAccuracy float64 `json:"action_accuracy"`
	ActionScored   int     `json:"action_scored"`

	// BenignFPR is the headline safety-of-use number: the fraction of benign
	// cases that were flagged or blocked at all.
	BenignFPR   float64 `json:"benign_fpr"`
	BenignCases int     `json:"benign_cases"`

	LatencyByStage map[string]LatencySummary `json:"latency_by_stage"`
	Results        []CaseResult              `json:"results"`

	Degraded int `json:"degraded_decisions"`
	Errors   int `json:"errors"`
}

// Run executes every case.
//
// Cases run sequentially. Parallelism would make the whole thing finish faster
// and make the latency numbers meaningless, and latency against a stated budget
// is one of the things this report exists to establish.
func (h *Harness) Run(ctx context.Context, ds *Dataset) (*Report, error) {
	rep := &Report{
		Dataset:        ds.Name,
		Policy:         h.policy.Path(),
		PolicyName:     h.policy.Name,
		GeneratedAt:    time.Now().UTC(),
		Cases:          len(ds.Cases),
		ByFamily:       map[string]Confusion{},
		LatencyByStage: map[string]LatencySummary{},
	}

	families := ds.Families()
	latency := map[core.Stage]*Latency{}
	for _, st := range core.Stages() {
		latency[st] = &Latency{}
	}
	conf := map[string]*Confusion{}
	for _, f := range families {
		conf[f] = &Confusion{}
	}

	var actionHits, actionScored, benignFlagged int

	for _, c := range ds.Cases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res := h.runCase(ctx, c, families, conf)
		rep.Results = append(rep.Results, res)

		if res.Error != "" {
			rep.Errors++
			continue
		}
		if res.Degraded {
			rep.Degraded++
		}
		latency[c.Stage].Add(res.Duration)

		if c.ExpectAction != "" {
			actionScored++
			if res.Action == c.ExpectAction {
				actionHits++
			}
		}
		if c.Benign() {
			rep.BenignCases++
			if res.Action != core.ActionAllow || len(res.Detected) > 0 {
				benignFlagged++
			}
		}
	}

	for f, c := range conf {
		rep.ByFamily[f] = *c
		rep.Overall.Add(*c)
	}
	rep.MacroF1 = MacroF1(rep.ByFamily)

	if actionScored > 0 {
		rep.ActionAccuracy = float64(actionHits) / float64(actionScored)
	}
	rep.ActionScored = actionScored
	if rep.BenignCases > 0 {
		rep.BenignFPR = float64(benignFlagged) / float64(rep.BenignCases)
	}

	for stage, l := range latency {
		if l.Count() == 0 {
			continue
		}
		rep.LatencyByStage[string(stage)] = l.Summary(h.policy.Budget(string(stage)))
	}
	return rep, nil
}

func (h *Harness) runCase(ctx context.Context, c Case, families []string, conf map[string]*Confusion) CaseResult {
	res := CaseResult{
		ID: c.ID, Stage: c.Stage, Tags: c.Tags,
		Variant: c.Variant, Source: c.Source,
		Expected: c.Families(), Expect: c.ExpectAction,
	}

	pipe, err := h.engine.Pipeline(c.Stage)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	tx := c.Transaction(h.secret)
	start := time.Now()
	dec, err := pipe.Execute(ctx, tx)
	res.Duration = time.Since(start)
	if err != nil && dec == nil {
		res.Error = err.Error()
		return res
	}

	res.Action = dec.Action
	res.Degraded = dec.Degraded

	detected := map[string]struct{}{}
	for _, f := range dec.Findings {
		fam := FamilyOf(f.Category)
		// engine.* findings describe the guardrail's own health, not the
		// prompt, and scoring them as detections would reward a broken guard.
		if fam == "engine" {
			continue
		}
		detected[fam] = struct{}{}
		if f.Score > res.TopScore {
			res.TopScore = f.Score
		}
	}
	for f := range detected {
		res.Detected = append(res.Detected, f)
	}
	sort.Strings(res.Detected)

	expected := map[string]struct{}{}
	for _, f := range c.Families() {
		expected[f] = struct{}{}
	}

	// Score every family in the corpus against every case, so that a detector
	// firing on a case labelled for a different family is correctly counted as
	// a false positive rather than quietly ignored.
	for _, fam := range families {
		_, pred := detected[fam]
		_, act := expected[fam]
		conf[fam].Observe(pred, act)
	}
	for fam := range detected {
		if _, ok := expected[fam]; !ok {
			res.Spurious = append(res.Spurious, fam)
		}
	}
	for fam := range expected {
		if _, ok := detected[fam]; !ok {
			res.Missed = append(res.Missed, fam)
		}
	}
	sort.Strings(res.Spurious)
	sort.Strings(res.Missed)
	return res
}

// Gate is a CI pass/fail threshold set.
//
// This is what turns the evaluation from a report into a control. Without a
// gate, a detection regression is a number in a file nobody opens; with one,
// it fails the build.
type Gate struct {
	MinMacroF1        float64
	MinRecall         float64 // applied per family
	MinPrecision      float64 // applied per family
	MaxBenignFPR      float64
	MaxP99            time.Duration
	MaxErrors         int
	RequireNoDegraded bool
}

// GateFailure describes one unmet threshold.
type GateFailure struct {
	Check  string  `json:"check"`
	Family string  `json:"family,omitempty"`
	Got    float64 `json:"got"`
	Want   float64 `json:"want"`
}

func (f GateFailure) String() string {
	if f.Family != "" {
		return fmt.Sprintf("%s[%s] = %.3f, want %s %.3f", f.Check, f.Family, f.Got, cmpWord(f.Check), f.Want)
	}
	return fmt.Sprintf("%s = %.3f, want %s %.3f", f.Check, f.Got, cmpWord(f.Check), f.Want)
}

func cmpWord(check string) string {
	switch check {
	case "benign_fpr", "p99_ms", "errors":
		return "<="
	default:
		return ">="
	}
}

// Check evaluates the report against the gate.
func (g Gate) Check(rep *Report) []GateFailure {
	var out []GateFailure

	if g.MinMacroF1 > 0 && !(rep.MacroF1 >= g.MinMacroF1) {
		out = append(out, GateFailure{Check: "macro_f1", Got: rep.MacroF1, Want: g.MinMacroF1})
	}
	if g.MaxBenignFPR > 0 && rep.BenignFPR > g.MaxBenignFPR {
		out = append(out, GateFailure{Check: "benign_fpr", Got: rep.BenignFPR, Want: g.MaxBenignFPR})
	}
	if g.MaxErrors >= 0 && rep.Errors > g.MaxErrors {
		out = append(out, GateFailure{Check: "errors", Got: float64(rep.Errors), Want: float64(g.MaxErrors)})
	}

	fams := make([]string, 0, len(rep.ByFamily))
	for f := range rep.ByFamily {
		fams = append(fams, f)
	}
	sort.Strings(fams)

	for _, f := range fams {
		c := rep.ByFamily[f]
		if g.MinRecall > 0 {
			if r := c.Recall(); !isNaN(r) && r < g.MinRecall {
				out = append(out, GateFailure{Check: "recall", Family: f, Got: r, Want: g.MinRecall})
			}
		}
		if g.MinPrecision > 0 {
			if p := c.Precision(); !isNaN(p) && p < g.MinPrecision {
				out = append(out, GateFailure{Check: "precision", Family: f, Got: p, Want: g.MinPrecision})
			}
		}
	}

	if g.MaxP99 > 0 {
		for stage, l := range rep.LatencyByStage {
			if l.P99 > g.MaxP99 {
				out = append(out, GateFailure{
					Check:  "p99_ms",
					Family: stage,
					Got:    float64(l.P99.Microseconds()) / 1000,
					Want:   float64(g.MaxP99.Microseconds()) / 1000,
				})
			}
		}
	}
	if g.RequireNoDegraded && rep.Degraded > 0 {
		out = append(out, GateFailure{Check: "degraded", Got: float64(rep.Degraded), Want: 0})
	}
	return out
}

func isNaN(f float64) bool { return f != f }
