package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// OpenAIOptions configures the upstream client.
type OpenAIOptions struct {
	APIKey  string
	BaseURL string

	// DefaultModel is used when a request does not name one.
	DefaultModel string
	// DefaultMaxTokens is used when a request does not set one.
	DefaultMaxTokens int

	Timeout time.Duration

	// MaxRetries bounds SDK-level retries. Zero selects the default of 2; a
	// negative value disables retries entirely. Both are clamped before they
	// reach the SDK, whose WithMaxRetries panics on a negative argument -- and
	// a configuration value must never be able to panic a constructor.
	MaxRetries int

	// Organization and Project scope billing and rate limits when the account
	// has more than one. Both are optional.
	Organization string
	Project      string

	// ReasoningEffort maps to the reasoning_effort parameter on the o-series
	// and GPT-5 models: minimal | low | medium | high. Empty leaves the
	// provider default, and it is silently ignored by non-reasoning models.
	ReasoningEffort string

	// Name overrides the provider name reported to telemetry. It is how the
	// same adapter is told apart when it drives an OpenAI-compatible vendor
	// such as Groq: "openai" on a Groq request would put Groq's latency and
	// spend on OpenAI's row of every dashboard.
	Name string

	// foreignHost is set by the constructors of OpenAI-compatible vendors. It
	// strips the OpenAI-only organisation and project headers, which the SDK
	// otherwise picks up from the ambient environment and would forward to a
	// third party.
	foreignHost bool
}

// OpenAI is the OpenAI Chat Completions adapter.
//
// Two choices are worth stating, because both are places where forwarding a
// client's request verbatim would produce an upstream error that looks like a
// gateway bug.
//
// First, this sends max_completion_tokens, never max_tokens. The older
// parameter is rejected outright by the reasoning models (o-series, GPT-5) and
// would silently cap the wrong budget elsewhere, because reasoning tokens are
// billed as output but are not part of the visible completion.
//
// Second, sampling parameters are deliberately absent. temperature, top_p and
// their relatives are rejected with a 400 on the reasoning models; accepting
// them at the gateway and passing them through would turn a client mistake into
// an opaque upstream failure.
type OpenAI struct {
	client openai.Client
	opts   OpenAIOptions
}

func NewOpenAI(opts OpenAIOptions) (*OpenAI, error) {
	if opts.DefaultModel == "" {
		opts.DefaultModel = DefaultOpenAIModel
	}
	if opts.DefaultMaxTokens <= 0 {
		// Sized to leave room for a substantial answer without risking the
		// SDK's non-streaming HTTP timeout.
		opts.DefaultMaxTokens = 16000
	}
	switch {
	case opts.MaxRetries == 0:
		opts.MaxRetries = 2
	case opts.MaxRetries < 0:
		opts.MaxRetries = 0 // explicit opt-out; never pass a negative to the SDK
	}
	if opts.Name == "" {
		opts.Name = "openai"
	}
	switch opts.ReasoningEffort {
	case "", "minimal", "low", "medium", "high":
	default:
		return nil, fmt.Errorf("openai: reasoning_effort %q must be minimal|low|medium|high",
			opts.ReasoningEffort)
	}

	var clientOpts []option.RequestOption
	// Only pass the key when we actually have one: with it unset the SDK still
	// resolves OPENAI_API_KEY from the environment itself, and overriding that
	// with an empty string would break a deployment that relies on it.
	if opts.APIKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(opts.APIKey))
	}
	if opts.BaseURL != "" {
		// A base URL override is also how this adapter targets any
		// OpenAI-compatible endpoint: Azure OpenAI, vLLM, Ollama, Groq,
		// OpenRouter or a local gateway.
		clientOpts = append(clientOpts, option.WithBaseURL(opts.BaseURL))
	}
	if opts.Organization != "" {
		clientOpts = append(clientOpts, option.WithOrganization(opts.Organization))
	}
	if opts.Project != "" {
		clientOpts = append(clientOpts, option.WithProject(opts.Project))
	}
	if opts.Timeout > 0 {
		clientOpts = append(clientOpts, option.WithRequestTimeout(opts.Timeout))
	}
	clientOpts = append(clientOpts, option.WithMaxRetries(opts.MaxRetries))
	if opts.foreignHost {
		clientOpts = append(clientOpts,
			option.WithHeaderDel("OpenAI-Organization"),
			option.WithHeaderDel("OpenAI-Project"))
	}

	return &OpenAI{client: openai.NewClient(clientOpts...), opts: opts}, nil
}

func (a *OpenAI) Name() string { return a.opts.Name }

func (a *OpenAI) Complete(ctx context.Context, req Request) (*Response, error) {
	params, err := a.params(req)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, classifyOpenAIError(err)
	}
	if len(resp.Choices) == 0 {
		return nil, &UpstreamError{
			StatusCode: 502, Retryable: true,
			Err: errors.New("openai: response contained no choices"),
		}
	}

	choice := resp.Choices[0]
	out := &Response{
		Model:      resp.Model,
		Text:       choice.Message.Content,
		StopReason: string(choice.FinishReason),
		Usage: core.Usage{
			// prompt_tokens INCLUDES cached_tokens, so the cached portion is
			// subtracted out here and priced separately. Counting both at the
			// full input rate would overstate spend by up to 10x on exactly
			// the cache-heavy workloads an operator most wants to measure.
			InputTokens:     int(resp.Usage.PromptTokens - resp.Usage.PromptTokensDetails.CachedTokens),
			OutputTokens:    int(resp.Usage.CompletionTokens),
			CacheReadTokens: int(resp.Usage.PromptTokensDetails.CachedTokens),

			// CacheWriteTokens is deliberately left at zero. OpenAI's
			// cache_write_tokens is another breakdown of prompt_tokens, not an
			// addition to them, and OpenAI bills cache writes at the ordinary
			// input rate rather than at a premium. Those tokens are therefore
			// already counted, correctly, in InputTokens above -- populating
			// this field too would double-charge them. (Anthropic is the
			// opposite: its cache writes carry a 1.25x premium, which is why
			// the field exists at all.)
		},
	}
	if out.Usage.InputTokens < 0 {
		out.Usage.InputTokens = int(resp.Usage.PromptTokens)
	}

	// A refusal is a successful, billable call with a valid response body.
	// Surfacing it rather than raising means an operator debugging "why did
	// this return nothing" can tell a refusal apart from a timeout.
	if r := choice.Message.Refusal; r != "" {
		out.RefusalCategory = "refusal"
		if out.Text == "" {
			out.Text = r
		}
	}

	for _, call := range choice.Message.ToolCalls {
		tc := core.ToolCall{
			ID:   call.ID,
			Name: call.Function.Name,
			Raw:  call.Function.Arguments,
		}
		// Tool arguments arrive as a JSON string and must be parsed, never
		// string-matched: escaping of the same value varies between models.
		var args map[string]any
		if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err == nil {
			tc.Arguments = args
		}
		out.ToolCalls = append(out.ToolCalls, tc)
	}
	return out, nil
}

func (a *OpenAI) params(req Request) (openai.ChatCompletionNewParams, error) {
	model := req.Model
	if model == "" {
		model = a.opts.DefaultModel
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = a.opts.DefaultMaxTokens
	}

	msgs := make([]openai.ChatCompletionMessageParamUnion, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, openai.SystemMessage(req.System))
	}
	for _, m := range req.Messages {
		switch {
		case m.Role == core.RoleAssistant && len(m.ToolCalls) > 0:
			am := openai.ChatCompletionAssistantMessageParam{}
			if m.Content != "" {
				am.Content.OfString = openai.String(m.Content)
			}
			for _, tc := range m.ToolCalls {
				args := tc.Raw
				if args == "" {
					b, _ := json.Marshal(tc.Arguments)
					args = string(b)
				}
				am.ToolCalls = append(am.ToolCalls, openai.ChatCompletionMessageToolCallUnionParam{
					OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
						ID:       tc.ID,
						Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{Name: tc.Name, Arguments: args},
					}})
			}
			msgs = append(msgs, openai.ChatCompletionMessageParamUnion{OfAssistant: &am})
		case m.Role == core.RoleTool && m.ToolCallID != "":
			msgs = append(msgs, openai.ToolMessage(m.Content, m.ToolCallID))
		case m.Role == core.RoleAssistant:
			msgs = append(msgs, openai.AssistantMessage(m.Content))
		case m.Role == core.RoleSystem:
			msgs = append(msgs, openai.SystemMessage(m.Content))
		default:
			// Tool results ride as user content; the runtime stage has already
			// inspected the calls that produced them.
			msgs = append(msgs, openai.UserMessage(m.Content))
		}
	}
	if len(msgs) == 0 {
		return openai.ChatCompletionNewParams{}, errors.New("openai: request has no messages")
	}

	params := openai.ChatCompletionNewParams{
		Model:               shared.ChatModel(model),
		Messages:            msgs,
		MaxCompletionTokens: openai.Int(int64(maxTokens)),
	}
	// Tools are declared as functions. Their schemas come from the gateway's
	// own catalog, so the model is only ever offered tools the control plane
	// knows how to grade.
	for _, t := range req.Tools {
		name, _ := t["name"].(string)
		if name == "" {
			continue
		}
		fd := shared.FunctionDefinitionParam{Name: name}
		if d, _ := t["description"].(string); d != "" {
			fd.Description = openai.String(d)
		}
		if p, ok := t["parameters"].(map[string]any); ok {
			fd.Parameters = shared.FunctionParameters(p)
		}
		params.Tools = append(params.Tools, openai.ChatCompletionFunctionTool(fd))
	}

	// A per-request effort (set by the model catalog) wins over the adapter
	// default: one adapter serves models whose effort vocabularies differ.
	effort := req.Effort
	if effort == "" {
		effort = a.opts.ReasoningEffort
	}
	if effort != "" && effort != "none" {
		params.ReasoningEffort = shared.ReasoningEffort(effort)
	}
	return params, nil
}

// classifyOpenAIError maps an upstream failure onto a status the gateway can
// return, so a provider hiccup does not surface as a generic 500.
func classifyOpenAIError(err error) error {
	var apiErr *openai.Error
	if !errors.As(err, &apiErr) {
		// Connection failures, DNS, and context cancellation land here.
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
