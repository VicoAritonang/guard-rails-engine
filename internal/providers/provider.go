// Package providers adapts upstream model APIs to one narrow interface, so the
// guardrail pipeline never has to know which vendor is behind it.
package providers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// Request is a provider-neutral completion request.
type Request struct {
	Model     string
	System    string
	Messages  []core.Message
	MaxTokens int

	// Tools is passed through opaquely. The engine inspects proposed tool
	// calls at the runtime stage but does not need to model tool schemas.
	Tools []map[string]any

	// Metadata is forwarded where the provider supports it (tenant tagging).
	Metadata map[string]string

	// Effort overrides the adapter's default reasoning effort for this call.
	// The model catalog sets it, because effort vocabularies are per model:
	// GPT-5 accepts "minimal", Groq's gpt-oss does not.
	Effort string
}

// Response is a provider-neutral completion.
type Response struct {
	Model      string
	Text       string
	StopReason string
	Usage      core.Usage
	ToolCalls  []core.ToolCall

	// Provider names the upstream that actually served the call, and Route the
	// catalog alias that was requested. They differ from the request whenever
	// a fallback fired, which is exactly when an operator needs to know.
	Provider string
	Route    string
	// Attempts lists every upstream tried, in order, including the failures
	// that triggered a fallback. Empty when no router was involved.
	Attempts []Attempt
	// Latency is the wall-clock of the upstream call that succeeded.
	Latency time.Duration

	// RefusalCategory is set when the provider's safety layer declined the
	// request. It is surfaced rather than converted into an error because a
	// refusal is a successful, billable API call with a valid response -- and
	// an operator debugging "why did this return nothing" needs to see the
	// difference between a refusal and a timeout.
	RefusalCategory string
}

// Refused reports whether the provider's own safety layer declined.
func (r *Response) Refused() bool { return r.StopReason == "refusal" }

// Provider is the upstream contract.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (*Response, error)
}

// TokenCounter is implemented by providers that can count tokens exactly.
//
// The quota guard deliberately does not use this -- it must not make a network
// call to admit a request -- but the CLI and the eval harness do, to calibrate
// the local estimator against ground truth.
type TokenCounter interface {
	CountTokens(ctx context.Context, req Request) (int, error)
}

// ErrNotConfigured is returned when a provider is selected but its credentials
// or settings are missing.
var ErrNotConfigured = errors.New("providers: not configured")

// New builds a provider by name.
func New(name string, opts Options) (Provider, error) {
	switch name {
	case "", "mock":
		return NewMock(opts.Mock), nil
	case "anthropic":
		return NewAnthropic(opts.Anthropic)
	case "openai":
		return NewOpenAI(opts.OpenAI)
	case "groq":
		return NewGroq(opts.Groq)
	case "replay":
		return NewReplay(opts.ReplayPath)
	default:
		return nil, fmt.Errorf("providers: unknown provider %q (want mock|openai|groq|anthropic|replay)", name)
	}
}

// Options carries per-provider settings.
type Options struct {
	Mock       MockOptions
	OpenAI     OpenAIOptions
	Groq       OpenAIOptions
	Anthropic  AnthropicOptions
	ReplayPath string
}

// DefaultOpenAIModel is used when neither the request nor the configuration
// names a model.
const DefaultOpenAIModel = "gpt-5"
