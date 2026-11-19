// Package toolguard is the agent module of the embeddable engine: the
// runtime-stage guards (tool catalog and control plane, tool policy, loop and
// budget breakers) and Execute, which runs your own tools under them.
//
//	g, err := engine.New(engine.Options{ToolCatalogFile: "tools.yaml"},
//		textguard.Module(), toolguard.Module())
//	out, err := toolguard.Execute(ctx, g, toolguard.Run{Call: call, Session: sess}, exec)
//
// Execute scans what a tool returned at the tool-result stage, so load
// textguard (or at least textguard.Module(textguard.ToolResult)) with it.
package toolguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/agent"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards/registry"
	"go.vicoworks.com/guard-rails-engine/internal/guards/runtime"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/engine"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/internal/link"
)

// Guard names, for Module.
const (
	ToolSafety    = config.GuardToolSafety
	ToolPolicy    = config.GuardToolPolicy
	LoopBreaker   = config.GuardLoop
	BudgetBreaker = config.GuardBudget
)

// Module returns the runtime-stage guards, or only the named ones. An unknown
// name makes engine.New fail. Execute and Approve need ToolSafety.
func Module(guards ...string) engine.Module {
	return registry.Select(registry.Merge("toolguard", runtime.Module()), guards...)
}

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

// Executor runs your tools. Execute calls Preview for a dry run and Execute
// for the real effect, and only after every control has passed.
type Executor interface {
	// Preview describes the effect without causing it. It is the text a
	// person reads before approving.
	Preview(ctx context.Context, call engine.ToolCall) (string, error)
	// Execute causes the effect.
	Execute(ctx context.Context, call engine.ToolCall) (engine.ToolResult, error)
}

// Funcs adapts two functions to Executor. A nil PreviewFunc describes the
// call by its name and arguments.
type Funcs struct {
	PreviewFunc func(ctx context.Context, call engine.ToolCall) (string, error)
	ExecuteFunc func(ctx context.Context, call engine.ToolCall) (engine.ToolResult, error)
}

// Run is one call submitted to Execute.
type Run struct {
	Call    engine.ToolCall
	Session *engine.Session

	ApprovalToken  string
	IdempotencyKey string
	DryRun         bool
}

// Outcome is what Execute did.
type Outcome struct {
	Assessment Assessment
	// Executed is true when Execute ran. Preview is set after a dry run.
	Executed bool
	DryRun   bool
	Preview  string
	// Result is what the tool returned, after the tool-result rails: hand
	// this to the model, never the raw result. Nil when the rails withheld it.
	Result *engine.ToolResult
	// ResultDecision is the tool-result stage's decision on Result.
	ResultDecision *engine.Decision
	Receipt        *Receipt
	// Session is the agent state after the call. Pass it on the next one.
	Session *engine.Session
}

// ErrRefused is returned when the control plane refused a call or a
// requirement is still open. Inspect Outcome.Assessment.Requirements for
// what to do: approval_required → Approve; dry_run_required → run again
// with DryRun; idempotency_missing → set IdempotencyKey.
var ErrRefused = errors.New("guardrails: tool call refused")

// RefusedError carries the assessment alongside ErrRefused.
type RefusedError struct {
	Reason     string
	Assessment Assessment
}

func (e *RefusedError) Error() string { return "guardrails: tool call refused: " + e.Reason }
func (e *RefusedError) Unwrap() error { return ErrRefused }

// ErrApprovalsUnavailable is returned by Approve when the engine has no
// tool_safety guard, so there is nothing to sign approvals with.
var ErrApprovalsUnavailable = errors.New("guardrails: approvals unavailable (tool_safety is disabled)")

func evaluator(g *engine.Engine) *agent.Evaluator {
	e := link.Core(g)
	if e == nil {
		return nil
	}
	return runtime.Evaluator(e)
}

// Approve mints a single-use approval for one exact tool call, after a person
// reviewed it. Runtime blocks an irreversible call with a
// tool.approval_required finding; show the call to someone, then pass the
// returned token as Request.ApprovalToken (or Run.ApprovalToken) on the retry.
//
// The token is bound to the call's signature (tool name and arguments, byte
// for byte), expires after tool_safety's approval_ttl_seconds, and is spent on
// first use within the session. approver must identify the person: an
// unattributed approval cannot answer the one question an audit asks.
//
// Tokens verify on any Engine built with the same Options.Secret, so set one
// when the approving process and the executing process differ.
func Approve(g *engine.Engine, call engine.ToolCall, approver, reason string) (string, error) {
	ev := evaluator(g)
	if ev == nil || ev.Options().Approver == nil {
		return "", ErrApprovalsUnavailable
	}
	token, _, err := ev.Options().Approver.Issue("", call.Name, core.CallSignature(call), approver, reason)
	if err != nil {
		return "", fmt.Errorf("guardrails: %w", err)
	}
	return token, nil
}

// Execute runs one tool call under the full tool control plane, the way
// the gateway's /v1/agent/execute and MCP gateway do:
//
//  1. assess the call (catalog tier, capability, taint, rate, amount, egress,
//     idempotency, dry run, approval);
//  2. if allowed, call exec.Preview (DryRun) or exec.Execute;
//  3. record the effect in the session (dry runs, spent approvals,
//     idempotency claims, taint from what the tool returned);
//  4. run the tool-result rails on what came back.
//
// Engine.Runtime only performs step 1. Use Execute when your process executes
// the tools itself: without step 3, a dry run never unlocks the real call and
// an approval is never spent.
//
// A refusal returns the outcome and a *RefusedError (errors.Is ErrRefused).
// A result the rails withheld returns the outcome, a nil Result and a
// *engine.BlockedError (errors.Is engine.ErrBlocked). An error from exec is
// returned as is, with the call still committed: a failed payment may still
// have happened.
func Execute(ctx context.Context, g *engine.Engine, run Run, exec Executor) (*Outcome, error) {
	ev := evaluator(g)
	if ev == nil {
		return nil, fmt.Errorf("%w: Execute needs the tool_safety guard (toolguard)", engine.ErrNotLoaded)
	}
	if exec == nil {
		return nil, errors.New("guardrails: Execute needs an Executor")
	}
	// Checked before the tool runs, not when its result arrives: by then the
	// side effect has happened and the result can only be thrown away.
	if !link.Core(g).Provides(core.StageToolResult) {
		return nil, fmt.Errorf("%w: Execute scans tool results; load textguard with toolguard", engine.ErrNotLoaded)
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
	out := &Outcome{Assessment: o.Assessment, Executed: o.Executed, DryRun: o.DryRun,
		Preview: o.Preview, Receipt: o.Receipt, Session: o.Session}

	if !o.Executed && !(o.DryRun && o.Preview != "") {
		if o.Error != "" && o.Assessment.Allowed() {
			return out, errors.New(o.Error)
		}
		return out, &RefusedError{Reason: refusalReason(&o.Assessment, o.Error), Assessment: o.Assessment}
	}
	if !o.Executed || o.Result == nil {
		return out, nil // a completed dry run
	}

	res, err := g.ToolResult(ctx, engine.Request{ToolResults: []engine.ToolResult{*o.Result}, Session: out.Session})
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

type executorAdapter struct{ x Executor }

func (a executorAdapter) Preview(ctx context.Context, t *agent.Tool, args map[string]any) (string, error) {
	return a.x.Preview(ctx, engine.ToolCall{Name: t.Name, Arguments: args})
}

func (a executorAdapter) Execute(ctx context.Context, t *agent.Tool, args map[string]any) (engine.ToolResult, error) {
	res, err := a.x.Execute(ctx, engine.ToolCall{Name: t.Name, Arguments: args})
	if res.Name == "" {
		res.Name = t.Name
	}
	return res, err
}

// Preview implements Executor.
func (f Funcs) Preview(ctx context.Context, call engine.ToolCall) (string, error) {
	if f.PreviewFunc != nil {
		return f.PreviewFunc(ctx, call)
	}
	return fmt.Sprintf("%s(%v)", call.Name, call.Arguments), nil
}

// Execute implements Executor.
func (f Funcs) Execute(ctx context.Context, call engine.ToolCall) (engine.ToolResult, error) {
	if f.ExecuteFunc == nil {
		return engine.ToolResult{}, fmt.Errorf("no executor for tool %q", call.Name)
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
