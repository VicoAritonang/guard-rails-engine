package providers

import "fmt"

// NewLocal drives a self-hosted OpenAI-compatible server: vLLM, Ollama
// (/v1), llama.cpp server, LM Studio, TGI, LocalAI, NVIDIA NIM.
//
// This is how the open-weight guard models are meant to run next to the
// gateway -- Llama Guard 4, Qwen3Guard, Granite Guardian, gpt-oss-safeguard,
// Nemotron safety -- with no per-call fee and no data leaving the network.
// Like the Groq constructor it never falls back to the ambient OpenAI key,
// because that would send the OpenAI credential to whatever LOCAL_BASE_URL
// names.
func NewLocal(opts OpenAIOptions) (*OpenAI, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("%w: local requires LOCAL_BASE_URL (e.g. http://ollama:11434/v1)", ErrNotConfigured)
	}
	if opts.APIKey == "" {
		opts.APIKey = "local" // most local servers ignore the key but the SDK requires one
	}
	if opts.DefaultMaxTokens <= 0 {
		opts.DefaultMaxTokens = 1024
	}
	opts.Name = "local"
	opts.Organization, opts.Project = "", ""
	opts.foreignHost = true
	return NewOpenAI(opts)
}
