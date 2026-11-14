// Package guardrails embeds the engine in a Go program, with no gateway to run.
//
//	go get go.vicoworks.com/guard-rails-engine@latest
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
// Beyond text: ScanFile and Message.Parts check documents, images and audio
// (see MediaBackends for OCR and speech-to-text); ToolResult checks retrieved
// content before it reaches a prompt; ExecuteTool runs your agent's tools
// under the tool control plane, with dry runs and human approval (Approve).
// The guide is docs/go-library.md in the repository.
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

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards"
	"go.vicoworks.com/guard-rails-engine/internal/media"
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
	// URL when the media guard allows fetching) plus Name or MIME.
	Part = core.Part
	// Modality names a part's kind.
	Modality = core.Modality
	// Extraction is the ingest report attached to every processed part.
	Extraction = core.Extraction

	// MediaBackends are the optional model-backed readers for attachments.
	MediaBackends = media.Backends
	// TextReader reads the text in an image (OCR).
	TextReader = media.TextReader
	// Transcriber turns speech into text.
	Transcriber = media.Transcriber
	// ImageClassifier judges an image's content directly.
	ImageClassifier = media.ImageClassifier
	// ImageVerdict is an image classifier's answer.
	ImageVerdict = media.ImageVerdict
)

// Modalities.
const (
	ModalityText     = core.ModalityText
	ModalityImage    = core.ModalityImage
	ModalityAudio    = core.ModalityAudio
	ModalityVideo    = core.ModalityVideo
	ModalityDocument = core.ModalityDocument
)

// OCRFunc adapts a function to TextReader, so any OCR library or service can
// be plugged in without a wrapper type:
//
//	Media: guardrails.MediaBackends{OCR: guardrails.OCRFunc("tesseract", myOCR)}
func OCRFunc(name string, fn func(ctx context.Context, data []byte, mime string) (string, error)) TextReader {
	return ocrFunc{name, fn}
}

type ocrFunc struct {
	name string
	fn   func(context.Context, []byte, string) (string, error)
}

func (o ocrFunc) Name() string { return o.name }
func (o ocrFunc) ReadImage(ctx context.Context, data []byte, mime string) (string, error) {
	return o.fn(ctx, data, mime)
}

// TranscribeFunc adapts a function to Transcriber.
func TranscribeFunc(name string, fn func(ctx context.Context, data []byte, mime, filename string) (string, error)) Transcriber {
	return transcribeFunc{name, fn}
}

type transcribeFunc struct {
	name string
	fn   func(context.Context, []byte, string, string) (string, error)
}

func (t transcribeFunc) Name() string { return t.name }
func (t transcribeFunc) Transcribe(ctx context.Context, data []byte, mime, filename string) (string, error) {
	return t.fn(ctx, data, mime, filename)
}

// NewOpenAITranscriber returns a Transcriber for any OpenAI-compatible
// /audio/transcriptions endpoint: OpenAI, Groq, LocalAI, speaches,
// faster-whisper-server.
func NewOpenAITranscriber(baseURL, apiKey, model string) Transcriber {
	return &media.OpenAITranscriber{BaseURL: baseURL, APIKey: apiKey, Model: model}
}

// NewHTTPOCR returns a TextReader that posts images to an OCR sidecar and
// reads back {"text": ...} or text/plain.
func NewHTTPOCR(url, token string) TextReader { return &media.HTTPOCR{URL: url, Token: token} }

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

	// Media plugs in OCR, speech-to-text and image classifiers. Without them,
	// documents (PDF, Office, HTML, ...) and image metadata are still read,
	// and anything that could not be read is reported as a finding.
	Media MediaBackends

	// ToolCatalogFile is a YAML tool catalog (see README, "Bring your own
	// tools"). The runtime stage refuses any tool it cannot grade, so an agent
	// with tools of its own needs one. It sets tool_safety's catalog_file on
	// the policy, overriding a value the policy already had.
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
	engine, err := guards.Build(pol, guards.Deps{Secret: secret, Media: opts.Media})
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

	// ApprovalToken, IdempotencyKey and DryRun are read by Runtime. They are
	// properties of the request your agent loop makes, not arguments the
	// model chose, which is why they are not on the ToolCall: a model that
	// could set its own approval token would be approving its own actions.
	//
	// ApprovalToken comes from Engine.Approve, after a person reviewed the
	// exact call. IdempotencyKey lets an irreversible call be retried without
	// running twice. DryRun asks the rails to assess without counting the
	// call as executed.
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

// ScanFile checks one file as a user attachment: the shortcut for an upload
// form or a RAG ingestion job. Use ToolResult with a Part instead when the
// file came from a tool or the web, which applies the stricter prior.
func (e *Engine) ScanFile(ctx context.Context, name string, data []byte) (*Result, error) {
	return e.Inbound(ctx, Request{Messages: []Message{{Role: RoleUser, Parts: []Part{{Name: name, Data: data}}}}})
}

// ErrApprovalsUnavailable is returned by Approve when the tool_safety guard
// is disabled, so there is nothing to sign approvals with.
var ErrApprovalsUnavailable = errors.New("guardrails: approvals unavailable (tool_safety is disabled)")

// Approve mints a single-use approval for one exact tool call, after a person
// reviewed it. Runtime blocks an irreversible call with a
// tool.approval_required finding; show the call to someone, then pass the
// returned token as Request.ApprovalToken on the retry.
//
// The token is bound to the call's signature (tool name and arguments, byte
// for byte), expires after tool_safety's approval_ttl_seconds, and is spent on
// first use within the session. approver must identify the person: an
// unattributed approval cannot answer the one question an audit asks.
//
// Tokens verify on any Engine built with the same Options.Secret, so set one
// when the approving process and the executing process differ.
func (e *Engine) Approve(call ToolCall, approver, reason string) (string, error) {
	ev := e.engine.ToolEvaluator()
	if ev == nil || ev.Options().Approver == nil {
		return "", ErrApprovalsUnavailable
	}
	token, _, err := ev.Options().Approver.Issue("", call.Name, core.CallSignature(call), approver, reason)
	if err != nil {
		return "", fmt.Errorf("guardrails: %w", err)
	}
	return token, nil
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
