// Package runtime implements the interception layer that sits inside an agent
// loop, between the model deciding to act and the action actually happening.
//
// Inbound and outbound guards see one request. These see a trajectory, which is
// where a different class of failure lives: the agent that never terminates,
// the agent that retries the same failing call four hundred times, the agent
// that talks itself into calling a tool it should not have.
package runtime

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// LoopBreaker terminates agent trajectories that stop making progress.
//
// It fails closed. A broken circuit breaker that fails open is worse than no
// breaker at all, because the operator believes they have a bound on spend and
// does not.
type LoopBreaker struct {
	cfg *config.GuardConfig

	maxSteps     int
	maxRepeats   int
	repeatWindow int
	oscillation  bool
	maxWallclock time.Duration
}

func NewLoopBreaker(cfg *config.GuardConfig) (*LoopBreaker, error) {
	g := &LoopBreaker{
		cfg:          cfg,
		maxSteps:     cfg.Int("max_steps", 25),
		maxRepeats:   cfg.Int("max_repeats", 3),
		repeatWindow: cfg.Int("repeat_window", 6),
		oscillation:  cfg.Bool("detect_oscillation", true),
		maxWallclock: time.Duration(cfg.Int("max_wallclock_seconds", 300)) * time.Second,
	}
	if g.maxSteps <= 0 {
		return nil, fmt.Errorf("loop_breaker: max_steps must be positive")
	}
	if g.maxRepeats <= 0 {
		return nil, fmt.Errorf("loop_breaker: max_repeats must be positive")
	}
	return g, nil
}

func (g *LoopBreaker) Name() string      { return config.GuardLoop }
func (g *LoopBreaker) Stage() core.Stage { return core.StageRuntime }

func (g *LoopBreaker) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	res.Metrics = map[string]float64{"loop.step": float64(tx.Step)}

	if tx.Step >= g.maxSteps {
		f := core.NewFinding(g.Name(), "max_steps", "runtime.step_limit", core.SeverityHigh, 1.0,
			fmt.Sprintf("agent reached step %d of %d", tx.Step, g.maxSteps))
		f.Meta = map[string]string{"step": fmt.Sprint(tx.Step), "limit": fmt.Sprint(g.maxSteps)}
		res.Findings = append(res.Findings, f)
	}

	if g.maxWallclock > 0 && !tx.StartedAt.IsZero() {
		if elapsed := time.Since(tx.StartedAt); elapsed > g.maxWallclock {
			f := core.NewFinding(g.Name(), "max_wallclock", "runtime.deadline", core.SeverityHigh, 1.0,
				fmt.Sprintf("trace ran for %s, limit is %s", elapsed.Truncate(time.Second), g.maxWallclock))
			res.Findings = append(res.Findings, f)
		}
		res.Metrics["loop.elapsed_seconds"] = time.Since(tx.StartedAt).Seconds()
	}

	// Build the recent call signature sequence: history followed by the calls
	// about to execute.
	seq := make([]string, 0, len(tx.History)+len(tx.ToolCalls))
	for _, c := range tx.History {
		seq = append(seq, CallSignature(c))
	}
	for _, c := range tx.ToolCalls {
		seq = append(seq, CallSignature(c))
	}
	if len(seq) == 0 {
		return res, nil
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	// Repetition: the same call with the same arguments, more than maxRepeats
	// times inside the recent window. Arguments are part of the signature on
	// purpose -- calling "search" ten times with ten different queries is an
	// agent working; calling it ten times with the same query is an agent
	// stuck.
	window := seq
	if g.repeatWindow > 0 && len(seq) > g.repeatWindow {
		window = seq[len(seq)-g.repeatWindow:]
	}
	counts := map[string]int{}
	for _, s := range window {
		counts[s]++
	}
	for _, sig := range sortedKeys(counts) {
		n := counts[sig]
		if n < g.maxRepeats {
			continue
		}
		f := core.NewFinding(g.Name(), "repeated_call", "runtime.repetition", core.SeverityHigh, 1.0,
			fmt.Sprintf("identical tool call repeated %d times in the last %d steps", n, len(window)))
		f.Meta = map[string]string{"signature": sig, "count": fmt.Sprint(n)}
		res.Findings = append(res.Findings, f)
	}

	// Oscillation: an A,B,A,B cycle, which repetition counting misses because
	// no single signature crosses the threshold. This is the classic shape of
	// an agent toggling between two tools that undo each other's work.
	if g.oscillation && len(seq) >= 4 {
		tail := seq[len(seq)-4:]
		if tail[0] == tail[2] && tail[1] == tail[3] && tail[0] != tail[1] {
			f := core.NewFinding(g.Name(), "oscillation", "runtime.oscillation", core.SeverityHigh, 0.95,
				"agent is alternating between two tool calls without progressing")
			f.Meta = map[string]string{"cycle": tail[0] + " <-> " + tail[1]}
			res.Findings = append(res.Findings, f)
		}
	}

	res.Metrics["loop.window_size"] = float64(len(window))
	res.Metrics["loop.distinct_calls"] = float64(len(counts))
	return res, nil
}

// CallSignature is re-exported from core, where it lives because three
// unrelated controls key off it: loop detection here, idempotency in the tool
// broker, and the scope binding on a human approval. One definition means a
// change to the canonicalisation cannot silently desynchronise them.
func CallSignature(c core.ToolCall) string { return core.CallSignature(c) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
