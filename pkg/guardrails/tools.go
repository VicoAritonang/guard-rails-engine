package guardrails

import (
	"context"

	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/toolguard"
)

// Tool execution types, from package toolguard.
type (
	// Assessment is the tool control plane's verdict on one call: its tier,
	// the controls that applied, and what is still required (approval, dry
	// run, idempotency key, capability).
	Assessment = toolguard.Assessment
	// Requirement is a control the caller has not satisfied yet, with the
	// remedy that satisfies it.
	Requirement = toolguard.Requirement
	// Receipt is the hash-chained audit record of one brokered call.
	Receipt = toolguard.Receipt

	// ToolExecutor runs your tools. ExecuteTool calls Preview for a dry run
	// and Execute for the real effect, and only after every control has passed.
	ToolExecutor = toolguard.Executor
	// ToolFuncs adapts two functions to ToolExecutor. A nil PreviewFunc
	// describes the call by its name and arguments.
	ToolFuncs = toolguard.Funcs
	// ToolRun is one call submitted to ExecuteTool.
	ToolRun = toolguard.Run
	// ToolOutcome is what ExecuteTool did.
	ToolOutcome = toolguard.Outcome
	// ToolRefusedError carries the assessment alongside ErrToolRefused.
	ToolRefusedError = toolguard.RefusedError
)

var (
	// ErrToolRefused is returned when the control plane refused a call or a
	// requirement is still open. Inspect ToolOutcome.Assessment.Requirements
	// for what to do: approval_required → Engine.Approve; dry_run_required →
	// run again with DryRun; idempotency_missing → set IdempotencyKey.
	ErrToolRefused = toolguard.ErrRefused
	// ErrApprovalsUnavailable is returned by Approve when the tool_safety
	// guard is disabled, so there is nothing to sign approvals with.
	ErrApprovalsUnavailable = toolguard.ErrApprovalsUnavailable
)

// ExecuteTool runs one tool call under the full tool control plane; see
// toolguard.Execute.
func (e *Engine) ExecuteTool(ctx context.Context, run ToolRun, exec ToolExecutor) (*ToolOutcome, error) {
	return toolguard.Execute(ctx, e.Engine, run, exec)
}

// Approve mints a single-use approval for one exact tool call, after a person
// reviewed it; see toolguard.Approve. Put it behind your own admin UI, not in
// the agent loop.
func (e *Engine) Approve(call ToolCall, approver, reason string) (string, error) {
	return toolguard.Approve(e.Engine, call, approver, reason)
}
