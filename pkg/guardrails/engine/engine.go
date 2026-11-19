// Package engine is the core of the embeddable library: the four stages and
// the payload types, with no guard compiled in. A program adds the guards it
// needs as modules, and links nothing else.
//
//	import (
//		"go.vicoworks.com/guard-rails/pkg/guardrails/engine"
//		"go.vicoworks.com/guard-rails/pkg/guardrails/textguard"
//	)
//
//	g, err := engine.New(engine.Options{}, textguard.Module())
//
// The modules, from lightest to heaviest:
//
//	textguard   PII, secrets, injection, topic, quota, leak, restore,
//	            format, schema, grounding, retrieved content (tool_result)
//	ruleguard   your own keyword, regex and URL rules
//	toolguard   agent tools: catalog, approvals, dry runs, loop and budget
//	            breakers; ExecuteTool and Approve
//	mediaguard  attachments: PDF, Office, HTML, images, audio; OCR and
//	            speech-to-text backends. The only module that adds
//	            third-party code and net/http
//
// Package guardrails is this package with every module loaded. Its types are
// these, so code written against one works with the other.
//
// A stage no loaded module can check returns ErrNotLoaded instead of an empty
// decision, and attachments are refused without mediaguard rather than passed
// unread: leaving a module out narrows what the engine does, never what it
// claims to do.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.vicoworks.com/guard-rails/config"
	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/guards/registry"
	"go.vicoworks.com/guard-rails/pkg/guardrails/internal/link"
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

	// Part is an attachment of a message or tool result: an image, document,
	// audio or video. Set Data (raw bytes) or URL (a data: URI, or a remote
	// URL when the media guard allows fetching) plus Name or MIME. Parts need
	// the mediaguard module.
	Part = core.Part
	// Modality names a part's kind.
	Modality = core.Modality
	// Extraction is the ingest report attached to every processed part.
	Extraction = core.Extraction

	// Module is a set of guards to compile in. Get one from textguard,
	// ruleguard, toolguard or mediaguard.
	Module = registry.Module
)

// Message roles.
const (
	RoleSystem    = core.RoleSystem
	RoleUser      = core.RoleUser
	RoleAssistant = core.RoleAssistant
	RoleTool      = core.RoleTool
)

// Modalities.
const (
	ModalityText     = core.ModalityText
	ModalityImage    = core.ModalityImage
	ModalityAudio    = core.ModalityAudio
	ModalityVideo    = core.ModalityVideo
	ModalityDocument = core.ModalityDocument
)

// Options configures an Engine. The zero value is the balanced policy with a
// random secret.
type Options struct {
	// Policy overrides the built-in balanced policy. Use StrictPolicy, or
	// LoadPolicy to read a YAML file. Entries for guards no loaded module
	// provides are ignored.
	Policy *Policy

	// Secret keys the redaction vault and approval signatures. When empty, a
	// random one is generated, which is right for a single process. Set the same
	// value everywhere if a placeholder or an approval has to survive a restart
	// or cross a process boundary.
	Secret []byte

	// ToolCatalogFile is a YAML tool catalog (see README, "Bring your own
	// tools"). The runtime stage refuses any tool it cannot grade, so an agent
	// with tools of its own needs one. It sets tool_safety's catalog_file on
	// the policy, overriding a value the policy already had, and needs the
	// toolguard module.
	ToolCatalogFile string
}

// Policies. Load one from YAML with LoadPolicy, or start from a profile and
// change fields in Go.
var (
	// DefaultPolicy is the balanced profile: mask PII, block high-confidence
	// attacks, flag the rest, fail open except where failure is unbounded.
	DefaultPolicy = config.DefaultPolicy
	// StrictPolicy is the enterprise profile: fail closed, medium blocks, no
	// PII restore, irreversible tools above T3 refused.
	StrictPolicy = config.StrictPolicy
	// LoadPolicy reads a YAML policy layered over the balanced defaults.
	LoadPolicy = config.LoadPolicy
)

// Policy is a complete, versioned rule set.
type Policy = config.Policy

// Engine runs the four guardrail stages with the guards its modules provide.
// It is safe for concurrent use and holds no per-request state.
type Engine struct {
	core   *registry.Engine
	secret []byte
}

func init() {
	link.Core = func(e any) *registry.Engine {
		if g, ok := e.(*Engine); ok && g != nil {
			return g.core
		}
		return nil
	}
}

// New builds an Engine from the given modules, and fails if the policy does
// not validate. At least one module is required.
func New(opts Options, modules ...Module) (*Engine, error) {
	if len(modules) == 0 {
		return nil, errors.New("guardrails: no modules: pass textguard.Module() or another module, or use package guardrails for all of them")
	}
	pol := opts.Policy
	if pol == nil {
		pol = config.DefaultPolicy()
	}
	if opts.ToolCatalogFile != "" {
		ts := pol.Guards[config.GuardToolSafety]
		if ts == nil {
			return nil, fmt.Errorf("guardrails: ToolCatalogFile is set but the policy has no tool_safety guard")
		}
		if ts.Params == nil {
			ts.Params = map[string]any{}
		}
		ts.Params["catalog_file"] = opts.ToolCatalogFile
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
	e, err := registry.Assemble(pol, registry.Deps{Secret: secret}, modules)
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	if opts.ToolCatalogFile != "" && e.Guard(config.GuardToolSafety) == nil {
		return nil, errors.New("guardrails: ToolCatalogFile needs the toolguard module")
	}
	return &Engine{core: e, secret: secret}, nil
}

// Guards lists the guards this engine constructed, enabled or not. Use it to
// confirm at startup that the guards you rely on are compiled in.
func (e *Engine) Guards() []string { return e.core.Guards() }

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

	// ApprovalToken, IdempotencyKey and DryRun are read by Runtime. They are
	// properties of the request your agent loop makes, not arguments the
	// model chose, which is why they are not on the ToolCall: a model that
	// could set its own approval token would be approving its own actions.
	//
	// ApprovalToken comes from Approve (toolguard), after a person reviewed
	// the exact call. IdempotencyKey lets an irreversible call be retried
	// without running twice. DryRun asks the rails to assess without counting
	// the call as executed.
	ApprovalToken  string
	IdempotencyKey string
	DryRun         bool

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

// ErrNotLoaded is returned when a request needs a module the engine was built
// without: a stage none of its guards check, or attachments without
// mediaguard. Nothing was checked, so nothing may be forwarded.
var ErrNotLoaded = errors.New("guardrails: module not loaded")

// Inbound checks a prompt before it reaches a provider.
func (e *Engine) Inbound(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, core.StageInbound, req)
}

// Runtime checks proposed tool calls inside an agent loop. It needs toolguard.
func (e *Engine) Runtime(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, core.StageRuntime, req)
}

// ToolResult checks what a tool returned, before the model reads it.
func (e *Engine) ToolResult(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, core.StageToolResult, req)
}

// Outbound checks a completion before it reaches the user, and restores the
// values Inbound masked when given its Vault.
func (e *Engine) Outbound(ctx context.Context, req Request) (*Result, error) {
	return e.run(ctx, core.StageOutbound, req)
}

// ScanFile checks one file as a user attachment: the shortcut for an upload
// form or a RAG ingestion job. Use ToolResult with a Part instead when the
// file came from a tool or the web, which applies the stricter prior. It
// needs mediaguard.
func (e *Engine) ScanFile(ctx context.Context, name string, data []byte) (*Result, error) {
	return e.Inbound(ctx, Request{Messages: []Message{{Role: RoleUser, Parts: []Part{{Name: name, Data: data}}}}})
}

func (e *Engine) run(ctx context.Context, stage core.Stage, req Request) (*Result, error) {
	if !e.core.Provides(stage) {
		return nil, fmt.Errorf("%w: no loaded module has a guard for the %s stage", ErrNotLoaded, stage)
	}
	pipe, err := e.core.Pipeline(stage)
	if err != nil {
		return nil, fmt.Errorf("guardrails: %w", err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("guardrails: transaction id: %w", err)
	}
	vault := req.Vault
	if vault == nil {
		vault = core.NewVault(e.secret)
	}
	meta := req.Meta
	if req.ApprovalToken != "" || req.IdempotencyKey != "" || req.DryRun {
		meta = make(map[string]any, len(req.Meta)+3)
		for k, v := range req.Meta {
			meta[k] = v
		}
		if req.ApprovalToken != "" {
			meta["approval_token"] = req.ApprovalToken
		}
		if req.IdempotencyKey != "" {
			meta["idempotency_key"] = req.IdempotencyKey
		}
		if req.DryRun {
			meta["dry_run"] = true
		}
	}
	tx := &core.Transaction{
		ID: "tx_" + hex.EncodeToString(id), Tenant: req.Tenant, Model: req.Model,
		System: req.System, Messages: req.Messages,
		ToolCalls: req.ToolCalls, History: req.History, Step: req.Step,
		ToolResults: req.ToolResults,
		Completion:  req.Completion, Context: req.Context,
		Usage: req.Usage, CostUSD: req.CostUSD,
		Session: req.Session, Meta: meta,
		StartedAt: time.Now(), Vault: vault,
	}
	// Without an ingest step, the guards would read an attachment as empty
	// text and pass it: refuse instead. Only the two stages that ingest read
	// parts at all.
	ingests := stage == core.StageInbound || stage == core.StageToolResult
	if ingests && e.core.Ingestor() == nil && tx.HasParts() {
		return nil, fmt.Errorf("%w: the request has attachments and mediaguard is not loaded", ErrNotLoaded)
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
