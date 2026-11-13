package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/config"
)

// Result is what a guard returns. Guards never mutate the transaction
// directly: they describe the edits they want and the pipeline applies them.
// That separation is what makes it safe to run every detector concurrently.
type Result struct {
	Findings  []Finding
	Mutations []Mutation
	// Metrics carries detector-internal numbers worth exporting, such as the
	// raw injection score before thresholding. Useful for tuning without
	// redeploying with extra logging.
	Metrics map[string]float64
}

// Guard is the contract every rule implements.
//
// Check must be pure with respect to tx: read freely, write nothing. It must
// also respect ctx cancellation, because the pipeline enforces a per-guard
// deadline and a slow guard is the one failure mode that can breach the
// end-to-end latency budget.
type Guard interface {
	Name() string
	Stage() Stage
	Check(ctx context.Context, tx *Transaction) (Result, error)
}

// Observer receives structured events from the pipeline. Implemented by the
// telemetry package; kept as an interface here so core stays dependency-free
// and testable without a metrics registry.
type Observer interface {
	GuardObserved(stage Stage, run GuardRun)
	DecisionObserved(tx *Transaction, d *Decision)
}

type nopObserver struct{}

func (nopObserver) GuardObserved(Stage, GuardRun)            {}
func (nopObserver) DecisionObserved(*Transaction, *Decision) {}

// Tracer starts a span. Satisfied by an OpenTelemetry adapter.
type Tracer interface {
	Start(ctx context.Context, name string, attrs map[string]string) (context.Context, func(err error))
}

type nopTracer struct{}

func (nopTracer) Start(ctx context.Context, _ string, _ map[string]string) (context.Context, func(error)) {
	return ctx, func(error) {}
}

// ErrBlocked is returned by ExecuteAll when a stage blocks the transaction.
var ErrBlocked = errors.New("guardrails: blocked by policy")

// Pipeline executes the guards registered for one stage.
//
// It is stateless: a single Pipeline is shared by every goroutine in the
// process and holds no per-request data, which is what allows the engine to
// scale horizontally without sticky routing.
type Pipeline struct {
	stage    Stage
	guards   []Guard
	policy   *config.Policy
	observer Observer
	tracer   Tracer
}

// PipelineOption configures a Pipeline.
type PipelineOption func(*Pipeline)

func WithObserver(o Observer) PipelineOption {
	return func(p *Pipeline) {
		if o != nil {
			p.observer = o
		}
	}
}

func WithTracer(t Tracer) PipelineOption {
	return func(p *Pipeline) {
		if t != nil {
			p.tracer = t
		}
	}
}

// NewPipeline builds a stage pipeline. Guards registered for another stage are
// rejected at construction rather than skipped at runtime, so a wiring mistake
// fails at startup.
func NewPipeline(stage Stage, guards []Guard, pol *config.Policy, opts ...PipelineOption) (*Pipeline, error) {
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid stage %q", stage)
	}
	if pol == nil {
		return nil, errors.New("nil policy")
	}
	for _, g := range guards {
		if g.Stage() != stage {
			return nil, fmt.Errorf("guard %q declares stage %q but was registered on %q", g.Name(), g.Stage(), stage)
		}
	}
	// Deterministic guard order: mutation precedence depends on it.
	ordered := make([]Guard, len(guards))
	copy(ordered, guards)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name() < ordered[j].Name() })

	p := &Pipeline{
		stage:    stage,
		guards:   ordered,
		policy:   pol,
		observer: nopObserver{},
		tracer:   nopTracer{},
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Stage reports which interception point this pipeline serves.
func (p *Pipeline) Stage() Stage { return p.stage }

// Guards lists the guard names in execution order.
func (p *Pipeline) Guards() []string {
	out := make([]string, len(p.guards))
	for i, g := range p.guards {
		out[i] = g.Name()
	}
	return out
}

// Execute runs every guard for this stage and returns the aggregated decision.
//
// Concurrency model: all detectors fan out in parallel under a shared stage
// deadline, each with its own guard-level timeout. Detection is the expensive
// part and it is embarrassingly parallel; mutation is the ordering-sensitive
// part and it is serial. Splitting them keeps p99 close to the slowest single
// guard rather than the sum of all guards.
func (p *Pipeline) Execute(ctx context.Context, tx *Transaction) (*Decision, error) {
	if tx == nil {
		return nil, errors.New("nil transaction")
	}
	start := time.Now()
	tx.Stage = p.stage

	ctx, endSpan := p.tracer.Start(ctx, "guardrails.pipeline."+string(p.stage), map[string]string{
		"guardrails.stage":  string(p.stage),
		"guardrails.tenant": tx.Tenant,
		"guardrails.model":  tx.Model,
	})

	stageCtx, cancel := context.WithTimeout(ctx, p.policy.Budget(string(p.stage)))
	defer cancel()

	dec := &Decision{
		TransactionID: tx.ID,
		Stage:         p.stage,
		Action:        ActionAllow,
		PolicyVersion: p.policy.Version,
	}

	results := make([]Result, len(p.guards))
	runs := make([]GuardRun, len(p.guards))
	var wg sync.WaitGroup

	for i, g := range p.guards {
		cfg := p.policy.Guard(g.Name())
		if !cfg.Enabled {
			runs[i] = GuardRun{Guard: g.Name(), Skipped: true, Action: ActionAllow}
			continue
		}
		wg.Add(1)
		go func(i int, g Guard) {
			defer wg.Done()
			results[i], runs[i] = p.runGuard(stageCtx, g, tx)
		}(i, g)
	}
	wg.Wait()

	// Aggregate. Everything below is serial and deterministic.
	for i, run := range runs {
		if run.Guard == "" {
			run.Guard = p.guards[i].Name()
			runs[i] = run
		}
		if run.Skipped {
			continue
		}
		if run.Error != "" && p.policy.EffectiveFailMode(run.Guard) == config.FailOpen {
			dec.Degraded = true
		}
		p.observer.GuardObserved(p.stage, run)
		dec.Action = dec.Action.Escalate(run.Action)

		res := results[i]
		dec.Findings = append(dec.Findings, res.Findings...)
		dec.Mutations = append(dec.Mutations, res.Mutations...)
		for k, v := range res.Metrics {
			if dec.Metrics == nil {
				dec.Metrics = make(map[string]float64, len(res.Metrics))
			}
			dec.Metrics[k] = v
		}
	}
	dec.Runs = runs

	// Redaction only happens if the final action is at least redact and the
	// request is not being blocked outright -- there is no point rewriting a
	// payload that will never be sent.
	if dec.Action == ActionRedact && len(dec.Mutations) > 0 {
		applied := ApplyMutations(tx, dec.Mutations)
		dec.Mutations = applied
	}

	sortFindings(dec.Findings)
	dec.Duration = time.Since(start)
	p.observer.DecisionObserved(tx, dec)

	var err error
	if dec.Blocked() {
		err = fmt.Errorf("%w: %s", ErrBlocked, dec.Reason())
	}
	endSpan(err)
	return dec, nil
}

// runGuard executes one guard under its own deadline and converts any failure
// into a policy-directed outcome. A guard never takes the process down and
// never silently disappears: every path here produces a GuardRun.
func (p *Pipeline) runGuard(ctx context.Context, g Guard, tx *Transaction) (Result, GuardRun) {
	name := g.Name()
	timeout := p.policy.EffectiveTimeout(name)
	failMode := p.policy.EffectiveFailMode(name)

	run := GuardRun{Guard: name, FailMode: string(failMode)}
	gctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	gctx, endSpan := p.tracer.Start(gctx, "guardrails.guard."+name, map[string]string{
		"guardrails.guard": name,
		"guardrails.stage": string(p.stage),
	})

	start := time.Now()
	res, err := p.safeCheck(gctx, g, tx)
	run.Duration = time.Since(start)

	if err == nil && gctx.Err() != nil {
		err = gctx.Err()
	}
	if err != nil {
		run.Error = err.Error()
		run.TimedOut = errors.Is(err, context.DeadlineExceeded)
		if failMode == config.FailClosed {
			run.Action = ActionBlock
			res.Findings = append(res.Findings, guardFailureFinding(name, err))
		} else {
			run.Action = ActionAllow
		}
		run.Findings = len(res.Findings)
		endSpan(err)
		return res, run
	}

	res.Findings = p.applyPolicy(name, res.Findings)
	for _, f := range res.Findings {
		act, perr := ParseAction(p.policy.ActionFor(name, f.Category, f.SeverityName))
		if perr != nil {
			act = ActionFlag
		}
		run.Action = run.Action.Escalate(act)
	}
	// A guard that produced mutations but whose findings all resolved to
	// "flag" must not have those mutations applied -- flag means observe.
	if run.Action.rank() < ActionRedact.rank() {
		res.Mutations = nil
	}
	run.Findings = len(res.Findings)
	endSpan(nil)
	return res, run
}

// safeCheck contains a panicking guard. A regex catastrophe or a nil map in
// one detector must not take down the whole gateway.
func (p *Pipeline) safeCheck(ctx context.Context, g Guard, tx *Transaction) (res Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("guard %s panicked: %v", g.Name(), r)
			res = Result{}
		}
	}()
	return g.Check(ctx, tx)
}

// applyPolicy re-grades findings against the policy: disabled categories are
// dropped, severities are remapped, and score-based findings below their
// threshold are suppressed.
//
// Doing this centrally rather than in each guard is what makes threshold
// sweeps in the eval harness meaningful -- one knob, one place.
func (p *Pipeline) applyPolicy(guard string, in []Finding) []Finding {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	for _, f := range in {
		if !p.policy.CategoryEnabled(guard, f.Category) {
			continue
		}
		if th := p.policy.ThresholdFor(guard, f.Category); th > 0 && f.Score > 0 && f.Score < th {
			continue
		}
		if name := p.policy.SeverityFor(guard, f.Category, f.SeverityName); name != f.SeverityName {
			if sev, err := ParseSeverity(name); err == nil {
				f.Severity, f.SeverityName = sev, name
			}
		}
		out = append(out, f)
	}
	return out
}

func guardFailureFinding(guard string, err error) Finding {
	f := NewFinding(guard, "guard_failure", "engine.guard_failure", SeverityHigh, 1.0,
		"guard failed and policy is fail-closed")
	f.Meta = map[string]string{"error": err.Error()}
	return f
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].Score != f[j].Score {
			return f[i].Score > f[j].Score
		}
		return f[i].Category < f[j].Category
	})
}

// ApplyMutations rewrites the transaction in place and returns the mutations
// that were actually applied.
//
// Two properties matter here. Mutations are applied back-to-front so that
// earlier offsets stay valid as the string shrinks or grows, and overlapping
// mutations are resolved by dropping the later one -- two detectors both
// masking the same substring would otherwise corrupt each other's output
// (e.g. masking an email inside an already-masked JSON blob).
func ApplyMutations(tx *Transaction, muts []Mutation) []Mutation {
	if len(muts) == 0 {
		return nil
	}
	byField := map[string][]Mutation{}
	for _, m := range muts {
		if m.End < m.Start || m.Start < 0 {
			continue
		}
		byField[m.Field] = append(byField[m.Field], m)
	}

	fields := make([]string, 0, len(byField))
	for f := range byField {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	var applied []Mutation
	for _, field := range fields {
		list := byField[field]
		// Sort ascending by start, then by longest match, then guard name so
		// the winner of an overlap is deterministic across runs and machines.
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Start != list[j].Start {
				return list[i].Start < list[j].Start
			}
			if list[i].End != list[j].End {
				return list[i].End > list[j].End
			}
			return list[i].Guard < list[j].Guard
		})

		orig, ok := tx.Field(field)
		if !ok {
			continue
		}

		var keep []Mutation
		lastEnd := -1
		for _, m := range list {
			if m.Start < lastEnd { // overlaps a mutation we already accepted
				continue
			}
			if m.End > len(orig) {
				continue
			}
			keep = append(keep, m)
			lastEnd = m.End
		}
		if len(keep) == 0 {
			continue
		}

		// Rewrite back-to-front.
		buf := orig
		for i := len(keep) - 1; i >= 0; i-- {
			m := keep[i]
			buf = buf[:m.Start] + m.Replacement + buf[m.End:]
		}
		tx.SetField(field, buf)
		applied = append(applied, keep...)
	}
	return applied
}
