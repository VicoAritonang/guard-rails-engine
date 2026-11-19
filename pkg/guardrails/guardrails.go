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
// This package loads every module. A program that needs fewer can build the
// same Engine from package engine and only the modules it uses (textguard,
// ruleguard, toolguard, mediaguard), and compile nothing else: a text-only
// build links no PDF parser and no net/http. The types are shared, so code
// moves between the two by changing the constructor.
//
// An Engine is safe for concurrent use and holds no per-request state.
package guardrails

import (
	"context"

	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/engine"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/mediaguard"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/ruleguard"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/textguard"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/toolguard"
)

// The types are package engine's, and its modules', so a value moves between
// this package and those without being copied or converted.
type (
	// Message is one chat turn.
	Message = engine.Message
	// Role names who wrote a message.
	Role = engine.Role
	// ToolCall is a tool invocation the model proposed.
	ToolCall = engine.ToolCall
	// ToolResult is what a tool returned.
	ToolResult = engine.ToolResult
	// Usage carries token accounting.
	Usage = engine.Usage
	// Decision is the verdict of one stage.
	Decision = engine.Decision
	// Finding is one detection inside a decision.
	Finding = engine.Finding
	// Session is an agent's accumulated state. The caller owns it and passes it
	// back on each step, which is what lets the tool rails see a trajectory.
	Session = engine.Session
	// Vault maps placeholders back to the values they masked. Treat it as
	// sensitive: it holds those values in memory for the life of one exchange.
	Vault = engine.Vault

	// Part is an attachment of a message or tool result: an image, document,
	// audio or video. Set Data (raw bytes) or URL (a data: URI, or a remote
	// URL when the media guard allows fetching) plus Name or MIME.
	Part = engine.Part
	// Modality names a part's kind.
	Modality = engine.Modality
	// Extraction is the ingest report attached to every processed part.
	Extraction = engine.Extraction

	// MediaBackends are the optional model-backed readers for attachments.
	MediaBackends = mediaguard.Backends
	// TextReader reads the text in an image (OCR).
	TextReader = mediaguard.TextReader
	// Transcriber turns speech into text.
	Transcriber = mediaguard.Transcriber
	// ImageClassifier judges an image's content directly.
	ImageClassifier = mediaguard.ImageClassifier
	// ImageVerdict is an image classifier's answer.
	ImageVerdict = mediaguard.ImageVerdict

	// Policy is a complete, versioned rule set.
	Policy = engine.Policy
	// Request is the payload submitted to a stage. Each stage reads its own
	// fields.
	Request = engine.Request
	// Result is a decision plus the payload as the engine left it.
	Result = engine.Result
	// BlockedError carries the decision alongside ErrBlocked.
	BlockedError = engine.BlockedError
)

// Modalities.
const (
	ModalityText     = engine.ModalityText
	ModalityImage    = engine.ModalityImage
	ModalityAudio    = engine.ModalityAudio
	ModalityVideo    = engine.ModalityVideo
	ModalityDocument = engine.ModalityDocument
)

// Message roles.
const (
	RoleSystem    = engine.RoleSystem
	RoleUser      = engine.RoleUser
	RoleAssistant = engine.RoleAssistant
	RoleTool      = engine.RoleTool
)

// Policies. Load one from YAML with LoadPolicy, or start from a profile and
// change fields in Go.
var (
	// DefaultPolicy is the balanced profile: mask PII, block high-confidence
	// attacks, flag the rest, fail open except where failure is unbounded.
	DefaultPolicy = engine.DefaultPolicy
	// StrictPolicy is the enterprise profile: fail closed, medium blocks, no
	// PII restore, irreversible tools above T3 refused.
	StrictPolicy = engine.StrictPolicy
	// LoadPolicy reads a YAML policy layered over the balanced defaults.
	LoadPolicy = engine.LoadPolicy
)

// Errors.
var (
	// ErrBlocked is returned when policy refuses the payload.
	ErrBlocked = engine.ErrBlocked
	// ErrNotLoaded is returned when a request needs a guard the engine does
	// not have, such as ExecuteTool with a policy that has no tool_safety.
	ErrNotLoaded = engine.ErrNotLoaded
)

// OCRFunc adapts a function to TextReader, so any OCR library or service can
// be plugged in without a wrapper type:
//
//	Media: guardrails.MediaBackends{OCR: guardrails.OCRFunc("tesseract", myOCR)}
func OCRFunc(name string, fn func(ctx context.Context, data []byte, mime string) (string, error)) TextReader {
	return mediaguard.OCRFunc(name, fn)
}

// TranscribeFunc adapts a function to Transcriber.
func TranscribeFunc(name string, fn func(ctx context.Context, data []byte, mime, filename string) (string, error)) Transcriber {
	return mediaguard.TranscribeFunc(name, fn)
}

// NewOpenAITranscriber returns a Transcriber for any OpenAI-compatible
// /audio/transcriptions endpoint: OpenAI, Groq, LocalAI, speaches,
// faster-whisper-server.
func NewOpenAITranscriber(baseURL, apiKey, model string) Transcriber {
	return mediaguard.NewOpenAITranscriber(baseURL, apiKey, model)
}

// NewHTTPOCR returns a TextReader that posts images to an OCR sidecar and
// reads back {"text": ...} or text/plain.
func NewHTTPOCR(url, token string) TextReader { return mediaguard.NewHTTPOCR(url, token) }

// Options configures an Engine. The zero value is the balanced policy with a
// random secret.
type Options struct {
	// Policy overrides the built-in balanced policy. Use StrictPolicy, or
	// LoadPolicy to read a YAML file.
	Policy *Policy

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

// Engine runs the four guardrail stages with every guard the project ships.
// The embedded *engine.Engine is what the module packages take, for example
// toolguard.Execute(ctx, g.Engine, ...).
type Engine struct {
	*engine.Engine
}

// New builds an Engine with every module, and fails if the policy does not
// validate.
func New(opts Options) (*Engine, error) {
	e, err := engine.New(engine.Options{Policy: opts.Policy, Secret: opts.Secret, ToolCatalogFile: opts.ToolCatalogFile},
		textguard.Module(), ruleguard.Module(), toolguard.Module(), mediaguard.Module(opts.Media))
	if err != nil {
		return nil, err
	}
	return &Engine{e}, nil
}
