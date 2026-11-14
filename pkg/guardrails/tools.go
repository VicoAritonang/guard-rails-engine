package guardrails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/agent"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Tool execution types, shared with the gateway's broker.
type (
	// Assessment is the tool control plane's verdict on one call: its tier,
	// the controls that applied, and what is still required (approval, dry
	// run, idempotency key, capability).
	Assessment = agent.Assessment
	// Requirement is a control the caller has not satisfied yet, with the
	// remedy that satisfies it.
	Requirement = agent.Requirement
	// Receipt is the hash-chained audit record of one brokered call.
	Receipt = agent.Receipt
)

// ToolExecutor runs your tools. ExecuteTool calls Preview for a dry run and
// Execute for the real effect, and only after every control has passed.
type ToolExecutor interface {
	// Preview describes the effect without causing it. It is the text a
	// person reads before approving.
	Preview(ctx context.Context, call ToolCall) (string, error)
	// Execute causes the effect.
	Execute(ctx context.Context, call ToolCall) (ToolResult, error)
}

// ToolFuncs adapts two functions to ToolExecutor. A nil PreviewFunc describes
// the call by its name and arguments.
type ToolFuncs struct {
	PreviewFunc func(ctx context.Context, call ToolCall) (string, error)
	ExecuteFunc func(ctx context.Context, call ToolCall) (ToolResult, error)
}

// ToolRun is one call submitted to ExecuteTool.
type ToolRun struct {
	Call    ToolCall
	Session *Session

	ApprovalToken  string
	IdempotencyKey string
	DryRun         bool
}

// ToolOutcome is what ExecuteTool did.
type ToolOutcome struct {
	Assessment Assessment
	// Executed is true when Execute ran. Preview is set after a dry run.
	Executed bool
	DryRun   bool
	Preview  string
	// Result is what the tool returned, after the tool-result rails: hand
	// this to the model, never the raw result. Nil when the rails withheld it.
	Result *ToolResult
	// ResultDecision is the tool-result stage's decision on Result.
	ResultDecision *Decision
	Receipt        *Receipt
	// Session is the agent state after the call. Pass it on the next one.
	Session *Session
}

// ErrToolRefused is returned when the control plane refused a call or a
// requirement is still open. Inspect ToolOutcome.Assessment.Requirements for
// what to do: approval_required → Engine.Approve; dry_run_required → run again
// with DryRun; idempotency_missing → set IdempotencyKey.
var ErrToolRefused = errors.New("guardrails: tool call refused")

// ToolRefusedError carries the assessment alongside ErrToolRefused.
type ToolRefusedError struct {
	Reason     string
	Assessment Assessment
}

func (e *ToolRefusedError) Error() string { return "guardrails: tool call refused: " + e.Reason }
func (e *ToolRefusedError) Unwrap() error { return ErrToolRefused }

// ExecuteTool runs one tool call under the full tool control plane, the way
// the gateway's /v1/agent/execute and MCP gateway do:
//
//  1. assess the call (catalog tier, capability, taint, rate, amount, egress,
//     idempotency, dry run, approval);
//  2. if allowed, call exec.Preview (DryRun) or exec.Execute;
//  3. record the effect in the session (dry runs, spent approvals,
//     idempotency claims, taint from what the tool returned);
//  4. run the tool-result rails on what came back.
//
// Runtime only performs step 1. Use ExecuteTool when your process executes
// the tools itself: without step 3, a dry run never unlocks the real call and
// an approval is never spent.
//
// A refusal returns the outcome and a *ToolRefusedError (errors.Is
// ErrToolRefused). A result the rails withheld returns the outcome, a nil
// Result and a *BlockedError (errors.Is ErrBlocked). An error from exec is
// returned as is, with the call still committed: a failed payment may still
// have happened.
func (e *Engine) ExecuteTool(ctx context.Context, run ToolRun, exec ToolExecutor) (*ToolOutcome, error) {
	ev := e.engine.ToolEvaluator()
	if ev == nil {
		return nil, errors.New("guardrails: ExecuteTool needs the tool_safety guard enabled")
	}
	if exec == nil {
		return nil, errors.New("guardrails: ExecuteTool needs a ToolExecutor")
	}
	broker, err := agent.NewBroker(ev, executorAdapter{exec}, nil)
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	sess := run.Session
	if sess == nil {
		sess = &core.SessionState{}
	}
	if sess.TraceID == "" {
		sess.TraceID = newTrace()
	}
	o := broker.Do(ctx, agent.Request{
		Trace: sess.TraceID, Call: run.Call, Session: sess,
		IdempotencyKey: run.IdempotencyKey, ApprovalToken: run.ApprovalToken, DryRun: run.DryRun,
	})
	out := &ToolOutcome{Assessment: o.Assessment, Executed: o.Executed, DryRun: o.DryRun,
		Preview: o.Preview, Receipt: o.Receipt, Session: o.Session}

	if !o.Executed && !(o.DryRun && o.Preview != "") {
		if o.Error != "" && o.Assessment.Allowed() {
			return out, errors.New(o.Error)
		}
		return out, &ToolRefusedError{Reason: refusalReason(&o.Assessment, o.Error), Assessment: o.Assessment}
	}
	if !o.Executed || o.Result == nil {
		return out, nil // a completed dry run
	}

	res, err := e.ToolResult(ctx, Request{ToolResults: []ToolResult{*o.Result}, Session: out.Session})
	if res != nil {
		out.ResultDecision, out.Session = res.Decision, res.Session
		if !res.Blocked && len(res.ToolResults) > 0 {
			r := res.ToolResults[0]
			out.Result = &r
		}
	}
	if o.Error != "" && err == nil {
		err = errors.New(o.Error)
	}
	return out, err
}

func refusalReason(a *Assessment, execErr string) string {
	var parts []string
	for _, r := range a.Requirements {
		parts = append(parts, r.Control+": "+r.Message)
	}
	for _, f := range a.Findings {
		if f.Severity >= core.SeverityHigh {
			parts = append(parts, f.Message+" ("+f.Category+")")
		}
	}
	if len(parts) == 0 && execErr != "" {
		parts = append(parts, execErr)
	}
	if len(parts) == 0 {
		return "refused by the tool control plane"
	}
	return strings.Join(parts, "; ")
}

type executorAdapter struct{ x ToolExecutor }

func (a executorAdapter) Preview(ctx context.Context, t *agent.Tool, args map[string]any) (string, error) {
	return a.x.Preview(ctx, ToolCall{Name: t.Name, Arguments: args})
}

func (a executorAdapter) Execute(ctx context.Context, t *agent.Tool, args map[string]any) (ToolResult, error) {
	res, err := a.x.Execute(ctx, ToolCall{Name: t.Name, Arguments: args})
	if res.Name == "" {
		res.Name = t.Name
	}
	return res, err
}

// Preview implements ToolExecutor.
func (f ToolFuncs) Preview(ctx context.Context, call ToolCall) (string, error) {
	if f.PreviewFunc != nil {
		return f.PreviewFunc(ctx, call)
	}
	return fmt.Sprintf("%s(%v)", call.Name, call.Arguments), nil
}

// Execute implements ToolExecutor.
func (f ToolFuncs) Execute(ctx context.Context, call ToolCall) (ToolResult, error) {
	if f.ExecuteFunc == nil {
		return ToolResult{}, fmt.Errorf("no executor for tool %q", call.Name)
	}
	return f.ExecuteFunc(ctx, call)
}

func newTrace() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("trace_%d", time.Now().UnixNano())
	}
	return "trace_" + hex.EncodeToString(b)
}
