package providers

import "fmt"

// GroqBaseURL is Groq's OpenAI-compatible endpoint.
const GroqBaseURL = "https://api.groq.com/openai/v1"

// DefaultGroqModel is used when a Groq request names no model.
const DefaultGroqModel = "openai/gpt-oss-20b"

// NewGroq drives Groq through the OpenAI adapter.
//
// Groq speaks the Chat Completions wire format, so a second SDK would be a
// second set of retry, timeout and error-classification semantics to keep in
// step for no gain. What does differ is credential handling, and that is the
// reason this constructor exists rather than "set OPENAI_BASE_URL":
//
//   - The key is mandatory. The OpenAI SDK falls back to OPENAI_API_KEY from the
//     ambient environment when no key is passed, so an unset GROQ_API_KEY would
//     silently send the OpenAI credential to a third party.
//   - The OpenAI organisation and project headers are stripped for the same
//     reason: the SDK reads them from the environment too.
//   - The provider reports itself as "groq", so latency and spend land on the
//     right row of every dashboard.
func NewGroq(opts OpenAIOptions) (*OpenAI, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("%w: groq requires GROQ_API_KEY (refusing to fall back to the OpenAI key)",
			ErrNotConfigured)
	}
	if opts.BaseURL == "" {
		opts.BaseURL = GroqBaseURL
	}
	if opts.DefaultModel == "" {
		opts.DefaultModel = DefaultGroqModel
	}
	if opts.DefaultMaxTokens <= 0 {
		// Groq reserves max_completion_tokens against the tokens-per-minute
		// limit before generating anything. The OpenAI adapter's 16k default
		// would exhaust a free-tier minute in one request.
		opts.DefaultMaxTokens = 2048
	}
	opts.Name = "groq"
	opts.Organization, opts.Project = "", ""
	opts.foreignHost = true
	return NewOpenAI(opts)
}
