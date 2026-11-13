// Package guardrails embeds the engine in a Go program, with no gateway to run.
//
// Use it when the application owns its model calls and wants the checks in
// process: there is no network hop, and nothing to deploy. To check calls from
// a service that talks to a separate gateway, use pkg/sdk instead. Both return
// the same decisions, because both run the same pipelines.
//
//	g, err := guardrails.New(guardrails.Options{})
//	if err != nil {
//		return err
//	}
//	in, err := g.Inbound(ctx, guardrails.Request{
//		Messages: []guardrails.Message{{Role: guardrails.RoleUser, Content: prompt}},
//	})
//	if errors.Is(err, guardrails.ErrBlocked) {
//		return refuse(in.Reason)
//	}
//	// Send in.Messages, the rewritten payload, not the originals.
//	answer := callYourModel(in.Messages)
//	out, err := g.Outbound(ctx, guardrails.Request{Completion: answer, Vault: in.Vault})
//	if errors.Is(err, guardrails.ErrBlocked) {
//		return refuse(out.Reason)
//	}
//	return out.Completion // placeholders are restored here
//
// An Engine is safe for concurrent use and holds no per-request state.
package guardrails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
)

// The payload types are the engine's own, so a value moves between this package
// and a decision without being copied or converted.
type (
	// Message is one chat turn.
	Message = core.Message
	// Role names who wrote a message.
	Role = core.Role
	// ToolCall is a tool invocation the model proposed.
	ToolCall = core.ToolCall
	// ToolResult is what a tool returned.
	ToolResult = core.ToolResult
	// Usage carries token accounting.
	Usage = core.Usage
	// Decision is the verdict of one stage.
	Decision = core.Decision
	// Finding is one detection inside a decision.
	Finding = core.Finding
	// Session is an agent's accumulated state. The caller owns it and passes it
	// back on each step, which is what lets the tool rails see a trajectory.
	Session = core.SessionState
	// Vault maps placeholders back to the values they masked. Treat it as
	// sensitive: it holds those values in memory for the life of one exchange.
	Vault = core.Vault
)

// Message roles.
const (
	RoleSystem    = core.RoleSystem
	RoleUser      = core.RoleUser
	RoleAssistant = core.RoleAssistant
	RoleTool      = core.RoleTool
)

// Options configures an Engine. The zero value is the balanced policy with a
// random secret.
type Options struct {
	// Policy overrides the built-in balanced policy. Use config.StrictPolicy,
	// or config.LoadPolicy to read a YAML file.
	Policy *config.Policy

	// Secret keys the redaction vault and approval signatures. When empty, a
	// random one is generated, which is right for a single process. Set the same
	// value everywhere if a placeholder or an approval has to survive a restart
	// or cross a process boundary.
	Secret []byte
}

// Engine runs the four guardrail stages.
type Engine struct {
	engine *guards.Engine
	secret []byte
}

// New builds an Engine, and fails if the policy does not validate.
func New(opts Options) (*Engine, error) {
	pol := opts.Policy
	if pol == nil {
		pol = config.DefaultPolicy()
	}
	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("guardrails: policy: %w", err)
	}
	secret := opts.Secret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("guardrails: generate secret: %w", err)
		}
	}
	engine, err := guards.Build(pol, guards.Deps{Secret: secret})
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	return &Engine{engine: engine, secret: secret}, nil
}

// Request is the payload submitted to a stage. Each stage reads its own fields.
type Request struct {
	Tenant string
	Model  string

	// System and Messages are read by Inbound.
	System   string
	Messages []Message

	// ToolCalls is read by Runtime, along with History and Step.
	ToolCalls []ToolCall
	History   []ToolCall
	Step      int

	// ToolResults is read by ToolResult.
	ToolResults []ToolResult

	// Completion is read by Outbound. Context holds the retrieved documents the
	// groundedness guard compares the answer against.
	Completion string
	Context    []string

	// Usage and CostUSD feed the budget breaker.
	Usage   Usage
	CostUSD float64

	// Session is the agent's state; the tool rails update it in place.
	Session *Session

	// Vault carries the placeholders of this exchange. Pass Inbound's Result.Vault
	// to Outbound, or the masked values cannot be restored. Leave it nil on the
	// first call of an exchange.
	Vault *Vault

	Meta map[string]any
}

// Result is a decision plus the payload as the engine left it.
type Result struct {
	Decision *Decision
	Blocked  bool
	Reason   string

	// System, Messages, Completion and ToolResults come back rewritten. Send
	// these onward, not your originals: forwarding the originals silently
	// defeats the redaction.
	System      string
	Messages    []Message
	Completion  string
	ToolResults []ToolResult

	// Vault holds this exchange's placeholders; see Request.Vault.
	Vault *Vault

	// Session is the agent state as the stage left it; see Request.Session.
	Session *Session
}

// ErrBlocked is returned when policy refuses the payload.
var ErrBlocked = errors.New("guardrails: blocked by policy")

// BlockedError carries the decision alongside ErrBlocked.
type BlockedError struct {
	Reason   string
	Decision *Decision
}

func (e *BlockedError) Error() string { return "guardrails: blocked by policy: " + e.Reason }
func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Inbound checks a prompt before it reaches a provider.
func (e *Engine) Inbound(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, e.engine.Inbound, req)
}

// Runtime checks proposed tool calls inside an agent loop.
func (e *Engine) Runtime(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, e.engine.Runtime, req)
}

// ToolResult checks what a tool returned, before the model reads it.
func (e *Engine) ToolResult(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, e.engine.ToolResult, req)
}

// Outbound checks a completion before it reaches the user, and restores the
// values Inbound masked when given its Vault.
func (e *Engine) Outbound(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, e.engine.Outbound, req)
}

func (e *Engine) run(ctx context.Context, pipe *core.Pipeline, req Request) (*Result, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("guardrails: transaction id: %w", err)
	}
	vault := req.Vault
	if vault == nil {
		vault = core.NewVault(e.secret)
	}
	tx := &core.Transaction{
		ID: "tx_" + hex.EncodeToString(id), Tenant: req.Tenant, Model: req.Model,
		System: req.System, Messages: req.Messages,
		ToolCalls: req.ToolCalls, History: req.History, Step: req.Step,
		ToolResults: req.ToolResults,
		Completion:  req.Completion, Context: req.Context,
		Usage: req.Usage, CostUSD: req.CostUSD,
		Session: req.Session, Meta: req.Meta,
		StartedAt: time.Now(), Vault: vault,
	}
	dec, err := pipe.Execute(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	res := &Result{
		Decision: dec, Blocked: dec.Blocked(),
		System: tx.System, Messages: tx.Messages, Completion: tx.Completion,
		ToolResults: tx.ToolResults, Vault: vault, Session: tx.Session,
	}
	if res.Blocked {
		res.Reason = dec.Reason()
		return res, &BlockedError{Reason: res.Reason, Decision: dec}
	}
	return res, nil
}
