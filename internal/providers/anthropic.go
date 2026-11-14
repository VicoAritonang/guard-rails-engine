package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// AnthropicOptions configures the upstream client.
type AnthropicOptions struct {
	APIKey  string
	BaseURL string
	// Model is used when a request does not name one.
	DefaultModel string
	// MaxTokens is used when a request does not set one.
	DefaultMaxTokens int
	Timeout          time.Duration
	MaxRetries       int

	// Effort maps to output_config.effort: low | medium | high | xhigh | max.
	// Empty leaves the provider default (high).
	Effort string

	// DisableThinking turns off adaptive thinking. Left off by default because
	// thinking is on by default on current models and turning it off has
	// documented failure modes; exposed because a latency-sensitive
	// classification workload behind this proxy may genuinely want it.
	DisableThinking bool
}

// Anthropic is the first-party Claude adapter.
//
// Two design notes.
//
// First, this proxy does not silently reroute traffic. The Messages API offers
// server-side refusal fallbacks that re-serve a declined request on a different
// model; that is a good feature for an application and the wrong default for a
// governance gateway, because it would change which model -- and which price --
// a tenant's request ran on without the tenant asking. Refusals are surfaced
// verbatim instead, and an operator who wants fallback behaviour can implement
// it against the RefusalCategory this adapter returns.
//
// Second, sampling parameters are deliberately absent. Temperature, top_p and
// top_k are rejected with a 400 on current Claude models; accepting them here
// and forwarding them would turn a client mistake into an upstream error that
// looks like a gateway bug.
type Anthropic struct {
	client anthropic.Client
	opts   AnthropicOptions
}

func NewAnthropic(opts AnthropicOptions) (*Anthropic, error) {
	if opts.DefaultModel == "" {
		opts.DefaultModel = "claude-opus-5"
	}
	if opts.DefaultMaxTokens <= 0 {
		// Sized to stay under the SDK's non-streaming HTTP timeout while
		// leaving room for a substantial answer.
		opts.DefaultMaxTokens = 16000
	}
	switch {
	case opts.MaxRetries == 0:
		opts.MaxRetries = 2
	case opts.MaxRetries < 0:
		opts.MaxRetries = 0 // explicit opt-out; never pass a negative to the SDK
	}

	var clientOpts []option.RequestOption
	// An unset API key does not mean there are no credentials: the SDK also
	// resolves ANTHROPIC_AUTH_TOKEN, an `ant auth login` profile, and workload
	// identity federation. Only pass the key when we were actually given one,
	// so those paths keep working.
	if opts.APIKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(opts.APIKey))
	}
	if opts.BaseURL != "" {
		clientOpts = append(clientOpts, option.WithBaseURL(opts.BaseURL))
	}
	if opts.Timeout > 0 {
		clientOpts = append(clientOpts, option.WithRequestTimeout(opts.Timeout))
	}
	clientOpts = append(clientOpts, option.WithMaxRetries(opts.MaxRetries))

	return &Anthropic{client: anthropic.NewClient(clientOpts...), opts: opts}, nil
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) Complete(ctx context.Context, req Request) (*Response, error) {
	params, err := a.params(req)
	if err != nil {
		return nil, err
	}

	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return nil, classifyError(err)
	}

	out := &Response{
		Model:      string(msg.Model),
		StopReason: string(msg.StopReason),
		Usage: core.Usage{
			InputTokens:      int(msg.Usage.InputTokens),
			OutputTokens:     int(msg.Usage.OutputTokens),
			CacheReadTokens:  int(msg.Usage.CacheReadInputTokens),
			CacheWriteTokens: int(msg.Usage.CacheCreationInputTokens),
		},
	}

	// Check stop_reason before reading content: a refusal is HTTP 200 with an
	// empty or partial content block, and treating it as a normal completion
	// produces a confusing empty answer instead of an actionable signal.
	if msg.StopReason == anthropic.StopReasonRefusal {
		out.RefusalCategory = string(msg.StopDetails.Category)
		if out.RefusalCategory == "" {
			out.RefusalCategory = "unspecified"
		}
	}

	for _, block := range msg.Content {
		switch v := block.AsAny().(type) {
		case anthropic.TextBlock:
			out.Text += v.Text
		case anthropic.ToolUseBlock:
			call := core.ToolCall{ID: v.ID, Name: v.Name}
			if raw, err := json.Marshal(v.Input); err == nil {
				call.Raw = string(raw)
				var args map[string]any
				// Tool inputs must be parsed, never string-matched: current
				// models vary their JSON escaping of the same value.
				if err := json.Unmarshal(raw, &args); err == nil {
					call.Arguments = args
				}
			}
			out.ToolCalls = append(out.ToolCalls, call)
		}
	}
	return out, nil
}

// CountTokens returns the provider's exact token count.
func (a *Anthropic) CountTokens(ctx context.Context, req Request) (int, error) {
	params, err := a.params(req)
	if err != nil {
		return 0, err
	}
	res, err := a.client.Messages.CountTokens(ctx, anthropic.MessageCountTokensParams{
		Model:    params.Model,
		System:   anthropic.MessageCountTokensParamsSystemUnion{OfTextBlockArray: params.System},
		Messages: params.Messages,
	})
	if err != nil {
		return 0, classifyError(err)
	}
	return int(res.InputTokens), nil
}

func (a *Anthropic) params(req Request) (anthropic.MessageNewParams, error) {
	model := req.Model
	if model == "" {
		model = a.opts.DefaultModel
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = a.opts.DefaultMaxTokens
	}

	msgs, err := toSDKMessages(req.Messages)
	if err != nil {
		return anthropic.MessageNewParams{}, err
	}
	if len(msgs) == 0 {
		return anthropic.MessageNewParams{}, errors.New("anthropic: request has no messages")
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: int64(maxTokens),
		Messages:  msgs,
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System}}
	}

	if a.opts.DisableThinking {
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfDisabled: &anthropic.ThinkingConfigDisabledParam{},
		}
	} else {
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
	}
	if a.opts.Effort != "" {
		params.OutputConfig = anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffort(a.opts.Effort),
		}
	}
	return params, nil
}

// toSDKMessages converts the neutral message list, merging consecutive turns
// of the same role. The Messages API requires strictly alternating roles, and
// a client that splits one user turn across two messages is common enough that
// rejecting it would be needlessly hostile.
func toSDKMessages(in []core.Message) ([]anthropic.MessageParam, error) {
	var out []anthropic.MessageParam
	var pendingRole core.Role
	var pending string
	var attachments []anthropic.ContentBlockParamUnion

	flush := func() {
		if pending == "" && len(attachments) == 0 {
			return
		}
		// Attachments first, then the text: Anthropic recommends placing
		// images and documents before the question about them.
		blocks := append([]anthropic.ContentBlockParamUnion{}, attachments...)
		if pending != "" {
			blocks = append(blocks, anthropic.NewTextBlock(pending))
		}
		if pendingRole == core.RoleAssistant {
			out = append(out, anthropic.NewAssistantMessage(blocks...))
		} else {
			out = append(out, anthropic.NewUserMessage(blocks...))
		}
		pending = ""
		attachments = nil
	}

	for _, m := range in {
		role := m.Role
		if role == core.RoleTool {
			role = core.RoleUser // tool results ride as user content here
		}
		if role != core.RoleUser && role != core.RoleAssistant {
			continue // system content travels in the System field
		}
		if role != pendingRole && (pending != "" || len(attachments) > 0) {
			flush()
		}
		pendingRole = role
		content := m.Content
		for _, p := range m.Parts {
			if b, ok := anthropicBlock(p); ok && role == core.RoleUser {
				attachments = append(attachments, b)
				continue
			}
			if t := p.AsText().Text; t != "" {
				content += "\n\n" + t
			}
		}
		if content == "" {
			continue
		}
		if pending != "" {
			pending += "\n\n"
		}
		pending += content
	}
	flush()

	if len(out) > 0 && out[0].Role == anthropic.MessageParamRoleAssistant {
		return nil, errors.New("anthropic: conversation cannot start with an assistant turn")
	}
	return out, nil
}

// anthropicBlock converts an attachment the Messages API accepts natively:
// raster images and PDFs. Everything else travels as its extracted text.
func anthropicBlock(p core.Part) (anthropic.ContentBlockParamUnion, bool) {
	if len(p.Data) == 0 {
		return anthropic.ContentBlockParamUnion{}, false
	}
	switch {
	case p.Type == core.ModalityImage && (p.MIME == "image/png" || p.MIME == "image/jpeg" || p.MIME == "image/gif" || p.MIME == "image/webp"):
		return anthropic.NewImageBlockBase64(p.MIME, base64.StdEncoding.EncodeToString(p.Data)), true
	case p.Type == core.ModalityDocument && p.MIME == "application/pdf":
		return anthropic.NewDocumentBlock(anthropic.Base64PDFSourceParam{Data: base64.StdEncoding.EncodeToString(p.Data)}), true
	}
	return anthropic.ContentBlockParamUnion{}, false
}

// UpstreamError distinguishes a retryable upstream failure from a client error,
// so the server layer can map it to the right HTTP status instead of turning
// every provider hiccup into a 500.
type UpstreamError struct {
	StatusCode int
	Retryable  bool
	Err        error
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream error (status %d): %v", e.StatusCode, e.Err)
}
func (e *UpstreamError) Unwrap() error { return e.Err }

func classifyError(err error) error {
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		// Connection failures and context cancellation land here.
		return &UpstreamError{StatusCode: 502, Retryable: true, Err: err}
	}
	switch code := apiErr.StatusCode; {
	case code == 400, code == 404, code == 422:
		return &UpstreamError{StatusCode: code, Retryable: false, Err: err}
	case code == 401, code == 403:
		return &UpstreamError{StatusCode: code, Retryable: false, Err: err}
	case code == 429:
		return &UpstreamError{StatusCode: 429, Retryable: true, Err: err}
	case code >= 500:
		return &UpstreamError{StatusCode: 502, Retryable: true, Err: err}
	default:
		return &UpstreamError{StatusCode: code, Retryable: false, Err: err}
	}
}
