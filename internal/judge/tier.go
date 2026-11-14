package judge

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Mode decides when the semantic tier runs.
type Mode string

const (
	// ModeOff never calls a classifier.
	ModeOff Mode = "off"
	// ModeShadow calls the classifiers on every request, asynchronously,
	// and never enforces. It is how a team learns what the tier would block
	// before letting it block anything: disagreements are counted and logged.
	ModeShadow Mode = "shadow"
	// ModeCascade calls the classifiers only when the deterministic tier saw
	// something but did not block -- a signal score above EscalateAbove or a
	// flagged finding. Most traffic carries no signal at all and never pays
	// for a model call.
	ModeCascade Mode = "cascade"
	// ModeAlways calls the classifiers on every request the deterministic
	// tier allowed. Highest recall, highest cost.
	ModeAlways Mode = "always"
)

// ParseMode validates a mode string.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "", ModeOff:
		return ModeOff, nil
	case ModeShadow, ModeCascade, ModeAlways:
		return m, nil
	}
	return "", fmt.Errorf("judge: unknown mode %q (want off|shadow|cascade|always)", s)
}

// Options configures a Tier.
type Options struct {
	Mode        Mode
	Classifiers []Classifier
	// EscalateAbove is the deterministic signal score at or above which
	// cascade mode escalates. The deterministic block threshold is 0.60, so
	// the band [EscalateAbove, 0.60) is "suspicious but not proven".
	EscalateAbove float64
	// Combine is any | all. "any" maximises recall; "all" (every classifier
	// must agree) maximises precision.
	Combine string
	Timeout time.Duration
	// FailClosed blocks when every classifier errored. The default is open:
	// the deterministic tier has already run, so a classifier outage degrades
	// coverage rather than removing it.
	FailClosed bool
	// Parallel lets the server start the upstream call while the classifier
	// runs, and discard the completion if the verdict is unsafe. It hides the
	// classifier's latency at the cost of paying for completions that end up
	// blocked.
	Parallel bool
	// Stages the tier applies to (inbound, outbound).
	Stages   []core.Stage
	Observer Observer
}

// Observer receives tier events for metrics and logs.
type Observer interface {
	JudgeObserved(stage core.Stage, v Verdict)
	TierDecided(stage core.Stage, mode Mode, out *Outcome)
}

// Outcome is the tier's decision for one text.
type Outcome struct {
	Ran       bool          `json:"ran"`
	Reason    string        `json:"reason"` // why it ran or did not
	Unsafe    bool          `json:"unsafe"`
	Enforced  bool          `json:"enforced"`
	Verdicts  []Verdict     `json:"verdicts,omitempty"`
	Duration  time.Duration `json:"duration_ns"`
	CostUSD   float64       `json:"cost_usd"`
	Degraded  bool          `json:"degraded,omitempty"`
	Heuristic float64       `json:"heuristic_score"`
	// Disagreement names which tier saw something the other did not:
	// "judge_only" (the semantic tier caught what the rules missed) or
	// "heuristic_only" (the reverse). It is the number shadow mode exists to
	// produce.
	Disagreement string `json:"disagreement,omitempty"`
}

// Tier runs the classifiers according to Options.
type Tier struct{ opts Options }

func NewTier(opts Options) (*Tier, error) {
	if opts.Mode == "" {
		opts.Mode = ModeOff
	}
	if opts.Mode != ModeOff && len(opts.Classifiers) == 0 {
		return nil, ErrNoClassifiers
	}
	if opts.EscalateAbove <= 0 {
		opts.EscalateAbove = 0.25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	switch opts.Combine {
	case "":
		opts.Combine = "any"
	case "any", "all":
	default:
		return nil, fmt.Errorf("judge: combine %q must be any or all", opts.Combine)
	}
	if len(opts.Stages) == 0 {
		opts.Stages = []core.Stage{core.StageInbound}
	}
	return &Tier{opts: opts}, nil
}

func (t *Tier) Mode() Mode {
	if t == nil {
		return ModeOff
	}
	return t.opts.Mode
}

func (t *Tier) Parallel() bool { return t != nil && t.opts.Parallel && t.opts.Mode != ModeShadow }

// Options exposes the effective configuration for introspection.
func (t *Tier) Options() Options { return t.opts }

// Applies reports whether the tier covers a stage.
func (t *Tier) Applies(stage core.Stage) bool {
	if t == nil || t.opts.Mode == ModeOff {
		return false
	}
	for _, s := range t.opts.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

// HeuristicScore is the strongest deterministic signal in a decision,
// including sub-threshold scores the policy suppressed. Those suppressed
// scores are exactly the "suspicious but not proven" band cascade keys on.
func HeuristicScore(d *core.Decision) float64 {
	if d == nil {
		return 0
	}
	var best float64
	for k, v := range d.Metrics {
		if (strings.HasPrefix(k, "injection.score.") || strings.HasPrefix(k, "tool_result.injection.score.")) && v > best {
			best = v
		}
	}
	for _, f := range d.Findings {
		if f.Score > best {
			best = f.Score
		}
	}
	return best
}

// ShouldRun applies the escalation rule to a deterministic decision.
func (t *Tier) ShouldRun(d *core.Decision) (bool, string) {
	switch t.Mode() {
	case ModeOff:
		return false, "off"
	}
	if d != nil && d.Blocked() {
		return false, "deterministic_block" // already decided; a model call adds cost, not safety
	}
	switch t.opts.Mode {
	case ModeShadow:
		return true, "shadow"
	case ModeAlways:
		return true, "always"
	}
	score := HeuristicScore(d)
	if score >= t.opts.EscalateAbove {
		return true, "signal"
	}
	if d != nil && d.Action == core.ActionFlag {
		return true, "flagged"
	}
	return false, "no_signal"
}

// Evaluate runs every classifier concurrently on text and combines verdicts.
func (t *Tier) Evaluate(ctx context.Context, stage core.Stage, text string, d *core.Decision) *Outcome {
	out := &Outcome{Heuristic: HeuristicScore(d)}
	run, reason := t.ShouldRun(d)
	out.Reason = reason
	if !run || strings.TrimSpace(text) == "" {
		t.decided(stage, out)
		return out
	}
	var active []Classifier
	for _, c := range t.opts.Classifiers {
		if Supports(c, stage) {
			active = append(active, c)
		}
	}
	if len(active) == 0 {
		out.Reason = "no_classifier_for_stage"
		t.decided(stage, out)
		return out
	}
	out.Ran = true
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, t.opts.Timeout)
	defer cancel()

	verdicts := make([]Verdict, len(active))
	var wg sync.WaitGroup
	for i, c := range active {
		wg.Add(1)
		go func(i int, c Classifier) {
			defer wg.Done()
			v, err := c.Classify(ctx, text, stage)
			if err != nil && v.Error == "" {
				v.Error = err.Error()
			}
			if v.Classifier == "" {
				v.Classifier = c.Name()
			}
			verdicts[i] = v
		}(i, c)
	}
	wg.Wait()
	out.Duration = time.Since(start)
	out.Verdicts = verdicts

	ok, unsafe := 0, 0
	for _, v := range verdicts {
		out.CostUSD += v.CostUSD
		if t.opts.Observer != nil {
			t.opts.Observer.JudgeObserved(stage, v)
		}
		if v.Error != "" {
			continue
		}
		ok++
		if v.Unsafe {
			unsafe++
		}
	}
	switch {
	case ok == 0:
		out.Degraded = true
		out.Unsafe = t.opts.FailClosed
	case t.opts.Combine == "all":
		out.Unsafe = unsafe == ok
	default:
		out.Unsafe = unsafe > 0
	}

	flagged := d != nil && (d.Action != core.ActionAllow || len(d.Findings) > 0)
	switch {
	case out.Unsafe && !flagged && ok > 0:
		out.Disagreement = "judge_only"
	case !out.Unsafe && flagged && ok > 0:
		out.Disagreement = "heuristic_only"
	}
	out.Enforced = out.Unsafe && t.opts.Mode != ModeShadow
	t.decided(stage, out)
	return out
}

func (t *Tier) decided(stage core.Stage, out *Outcome) {
	if t.opts.Observer != nil {
		t.opts.Observer.TierDecided(stage, t.opts.Mode, out)
	}
}

// Finding converts an enforced outcome into a pipeline finding, so a semantic
// block is reported, audited and counted exactly like a deterministic one.
func (o *Outcome) Finding() core.Finding {
	best := Verdict{}
	for _, v := range o.Verdicts {
		if v.Unsafe && v.Score >= best.Score {
			best = v
		}
	}
	cat := best.Category
	if cat == "" || cat == "none" {
		cat = "unsafe"
	}
	msg := fmt.Sprintf("semantic classifier %s judged the content unsafe", best.Classifier)
	if best.Rationale != "" {
		msg += ": " + best.Rationale
	}
	f := core.NewFinding("semantic", best.Classifier, "semantic."+cat, core.SeverityHigh, best.Score, msg)
	f.Meta = map[string]string{"classifier": best.Classifier, "model": best.Model}
	return f
}

// UserText joins the attacker-controlled turns of an inbound transaction.
// System prompts are operator-authored and excluded for the same reason the
// injection guard excludes them: classifying them is a guaranteed false
// positive on any prompt that describes its own rules.
func UserText(msgs []core.Message) string {
	var b strings.Builder
	for _, m := range msgs {
		if m.Role == core.RoleSystem || m.Role == core.RoleAssistant {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(m.Content)
		// Attachments are user content too: a jailbreak in a PDF is still
		// a jailbreak, and the classifiers read the text ingest extracted.
		for _, p := range m.Parts {
			if strings.TrimSpace(p.Text) == "" {
				continue
			}
			b.WriteString("\n\n[" + p.Label() + "]\n")
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// ResultText joins tool-result text and attachment text for the tool-result
// stage.
func ResultText(results []core.ToolResult) string {
	var b strings.Builder
	for _, r := range results {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(r.Content)
		for _, p := range r.Parts {
			if strings.TrimSpace(p.Text) != "" {
				b.WriteString("\n\n[" + p.Label() + "]\n" + p.Text)
			}
		}
	}
	return b.String()
}
