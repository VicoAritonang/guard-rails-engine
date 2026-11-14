package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration, derived entirely from the environment.
//
// Twelve-factor rather than a config file, because the policy is already a
// file: splitting deployment concerns (ports, keys, timeouts) from governance
// concerns (what counts as a violation) means an SRE can roll a replica without
// touching security rules, and a security engineer can change a rule without
// learning the deployment.
type Config struct {
	Addr            string
	RequestTimeout  time.Duration
	ShutdownTimeout time.Duration
	DrainDelay      time.Duration
	MaxBodyBytes    int64

	PolicyPath   string
	StrictPolicy bool
	PricingPath  string

	Provider         string
	DefaultModel     string
	DefaultMaxTokens int
	Effort           string
	ReplayPath       string

	OpenAIAPIKey       string
	OpenAIBaseURL      string
	OpenAIOrganization string
	OpenAIProject      string

	AnthropicAPIKey  string
	AnthropicBaseURL string

	GroqAPIKey  string
	GroqBaseURL string

	// Local is any self-hosted OpenAI-compatible server (vLLM, Ollama, TGI,
	// llama.cpp, NIM): where open-weight guard models run beside the gateway.
	LocalAPIKey  string
	LocalBaseURL string

	// Media backends. MediaOCR is a catalog route (vision OCR through the
	// router) or an http(s) URL (an OCR sidecar). MediaTranscribe is openai,
	// groq, local, or the base URL of an OpenAI-compatible speech-to-text
	// server. MediaImageClassifiers are "moderation" and/or catalog routes
	// of a multimodal guard model (Llama Guard 4).
	MediaOCR              string
	MediaOCRToken         string
	MediaTranscribe       string
	MediaTranscribeModel  string
	MediaTranscribeKey    string
	MediaImageClassifiers []string
	// MediaUploadBytes bounds a multipart upload to /v1/guard/media.
	MediaUploadBytes int64

	// ModelsPath points at the model catalog. When set, the gateway builds a
	// router over every provider that has credentials, and Provider becomes
	// the default for model names the catalog does not list.
	ModelsPath string

	// Response cache. CacheSize 0 disables the exact cache; the semantic cache
	// is separately opt-in because it trades correctness for hit rate.
	CacheSize              int
	CacheTTL               time.Duration
	SemanticCache          bool
	SemanticCacheThreshold float64

	// Semantic tier (model-based classifiers behind the deterministic guards).
	JudgeMode          string
	JudgeClassifiers   []string
	JudgeStages        []string
	JudgeTimeout       time.Duration
	JudgeParallel      bool
	JudgeFailClosed    bool
	JudgeEscalateAbove float64
	JudgeCombine       string
	// JudgeValidate runs the semantic tier on /v1/guard/{stage} as well as on
	// the proxy, so a team using the SDKs gets the same coverage as one
	// using the OpenAI-compatible endpoint.
	JudgeValidate bool

	// UpstreamMaxRetries is the SDK retry budget per upstream call: 0 keeps the
	// SDK default (2), negative disables retries. Experiments disable them so
	// a rate-limit back-off is never counted as model latency.
	UpstreamMaxRetries int

	// MCPPath points at the MCP gateway config; empty disables /mcp and the
	// agent runtime.
	MCPPath string
	// ExperimentsDir is served read-only to the showcase page.
	ExperimentsDir string
	// ExperimentsRun lets the web page start experiments. They spend real API
	// quota, so this is off unless switched on.
	ExperimentsRun bool
	// EvalCorpus is the labelled corpus the detectors experiment reads.
	EvalCorpus string

	// OTLPEndpoint enables trace export (host:port of an OTLP/HTTP receiver).
	OTLPEndpoint string
	// OTLPInsecure sends traces over plain HTTP. It suits a collector on the
	// same network; a hosted backend needs it off.
	OTLPInsecure bool
	// LogFile, when set, receives a copy of every log line as JSON, for a log
	// shipper to tail. Stdout stays the primary sink.
	LogFile string

	// EnvFile records which .env file was loaded, or "" if none was found. It
	// is logged at startup so it is obvious which file supplied a credential.
	EnvFile string

	APIKeys []string
	// AdminKeys, when set, are the only keys that may mint approvals, re-pin a
	// quarantined tool or start an experiment. Without them an agent holding an
	// ordinary API key could approve its own irreversible calls.
	AdminKeys []string
	Secret    []byte

	// InsecureDev accepts an open gateway on a non-loopback address. It exists
	// for a container whose port is published on the host's loopback only, which
	// the process cannot see from inside.
	InsecureDev bool

	LogLevel        string
	LogFormat       string
	AuditEnabled    bool
	AuditLogAllowed bool
	TracingEnabled  bool
	TenantMetrics   bool
	Dashboard       bool

	// SecretGenerated records that no secret was supplied. It is surfaced at
	// startup because a per-replica random secret silently breaks the
	// mask/unmask round-trip the moment there is more than one replica.
	SecretGenerated bool
}

// FromEnv loads .env (if present), then reads and validates the environment.
//
// The .env file is read first so its values are visible to everything below,
// but LoadDotEnv never overwrites a variable that is already set -- see its doc
// comment for why that ordering is the safe one.
func FromEnv() (*Config, error) {
	envFile := envStr("GUARDRAILS_ENV_FILE", ".env")
	if err := LoadDotEnv(envFile); err != nil {
		return nil, err
	}
	loaded := ""
	if _, err := os.Stat(envFile); err == nil {
		loaded = envFile
	}

	c := &Config{
		EnvFile:         loaded,
		Addr:            envStr("GUARDRAILS_ADDR", "127.0.0.1:8080"),
		RequestTimeout:  envDur("GUARDRAILS_REQUEST_TIMEOUT", 60*time.Second),
		ShutdownTimeout: envDur("GUARDRAILS_SHUTDOWN_TIMEOUT", 25*time.Second),
		DrainDelay:      envDur("GUARDRAILS_DRAIN_DELAY", 2*time.Second),
		MaxBodyBytes:    int64(envInt("GUARDRAILS_MAX_BODY_BYTES", 8<<20)),

		PolicyPath:   envStr("GUARDRAILS_POLICY", ""),
		StrictPolicy: envBool("GUARDRAILS_STRICT", false),
		PricingPath:  envStr("GUARDRAILS_PRICING", ""),

		Provider: envStr("GUARDRAILS_PROVIDER", "mock"),
		// DefaultModel is resolved after the provider is known, because the
		// right default depends on it.
		DefaultModel:     envStr("GUARDRAILS_DEFAULT_MODEL", ""),
		DefaultMaxTokens: envInt("GUARDRAILS_DEFAULT_MAX_TOKENS", 16000),
		Effort:           envStr("GUARDRAILS_EFFORT", ""),
		ReplayPath:       envStr("GUARDRAILS_REPLAY_CASSETTE", ""),

		OpenAIAPIKey:       os.Getenv("OPENAI_API_KEY"),
		OpenAIBaseURL:      os.Getenv("OPENAI_BASE_URL"),
		OpenAIOrganization: os.Getenv("OPENAI_ORG_ID"),
		OpenAIProject:      os.Getenv("OPENAI_PROJECT_ID"),

		AnthropicAPIKey:  os.Getenv("ANTHROPIC_API_KEY"),
		AnthropicBaseURL: os.Getenv("ANTHROPIC_BASE_URL"),

		GroqAPIKey:  os.Getenv("GROQ_API_KEY"),
		GroqBaseURL: os.Getenv("GROQ_BASE_URL"),

		LocalAPIKey:  os.Getenv("LOCAL_API_KEY"),
		LocalBaseURL: os.Getenv("LOCAL_BASE_URL"),

		MediaOCR:              envStr("GUARDRAILS_MEDIA_OCR", ""),
		MediaOCRToken:         os.Getenv("GUARDRAILS_MEDIA_OCR_TOKEN"),
		MediaTranscribe:       envStr("GUARDRAILS_MEDIA_TRANSCRIBE", ""),
		MediaTranscribeModel:  envStr("GUARDRAILS_MEDIA_TRANSCRIBE_MODEL", ""),
		MediaTranscribeKey:    os.Getenv("GUARDRAILS_MEDIA_TRANSCRIBE_API_KEY"),
		MediaImageClassifiers: envList("GUARDRAILS_MEDIA_IMAGE_CLASSIFIERS", ""),
		MediaUploadBytes:      int64(envInt("GUARDRAILS_MEDIA_UPLOAD_BYTES", 32<<20)),

		ModelsPath: envStr("GUARDRAILS_MODELS", ""),

		CacheSize:              envInt("GUARDRAILS_CACHE_SIZE", 1000),
		CacheTTL:               envDur("GUARDRAILS_CACHE_TTL", time.Hour),
		SemanticCache:          envBool("GUARDRAILS_SEMANTIC_CACHE", false),
		SemanticCacheThreshold: envFloat("GUARDRAILS_SEMANTIC_CACHE_THRESHOLD", 0.95),

		JudgeMode:          envStr("GUARDRAILS_JUDGE_MODE", "off"),
		JudgeClassifiers:   envList("GUARDRAILS_JUDGE_CLASSIFIERS", "prompt-guard-86m"),
		JudgeStages:        envList("GUARDRAILS_JUDGE_STAGES", "inbound"),
		JudgeTimeout:       envDur("GUARDRAILS_JUDGE_TIMEOUT", 3*time.Second),
		JudgeParallel:      envBool("GUARDRAILS_JUDGE_PARALLEL", false),
		JudgeFailClosed:    envBool("GUARDRAILS_JUDGE_FAIL_CLOSED", false),
		JudgeEscalateAbove: envFloat("GUARDRAILS_JUDGE_ESCALATE_ABOVE", 0.25),
		JudgeCombine:       envStr("GUARDRAILS_JUDGE_COMBINE", "any"),
		JudgeValidate:      envBool("GUARDRAILS_JUDGE_VALIDATE", true),

		UpstreamMaxRetries: envInt("GUARDRAILS_UPSTREAM_MAX_RETRIES", 0),
		OTLPEndpoint:       envStr("GUARDRAILS_OTLP_ENDPOINT", ""),
		OTLPInsecure:       envBool("GUARDRAILS_OTLP_INSECURE", true),
		InsecureDev:        envBool("GUARDRAILS_INSECURE_DEV", false),
		MCPPath:            envStr("GUARDRAILS_MCP", ""),
		ExperimentsDir:     envStr("GUARDRAILS_EXPERIMENTS_DIR", ""),
		ExperimentsRun:     envBool("GUARDRAILS_EXPERIMENTS_RUN", false),
		EvalCorpus:         envStr("GUARDRAILS_EVAL_CORPUS", "testdata/eval"),
		LogFile:            envStr("GUARDRAILS_LOG_FILE", ""),

		LogLevel:        envStr("GUARDRAILS_LOG_LEVEL", "info"),
		LogFormat:       envStr("GUARDRAILS_LOG_FORMAT", "json"),
		AuditEnabled:    envBool("GUARDRAILS_AUDIT", true),
		AuditLogAllowed: envBool("GUARDRAILS_AUDIT_LOG_ALLOWED", false),
		TracingEnabled:  envBool("GUARDRAILS_TRACING", false),
		TenantMetrics:   envBool("GUARDRAILS_TENANT_METRICS", false),
		Dashboard:       envBool("GUARDRAILS_DASHBOARD", true),
	}

	c.APIKeys = keyList("GUARDRAILS_API_KEYS")
	c.AdminKeys = keyList("GUARDRAILS_ADMIN_KEYS")

	if raw := os.Getenv("GUARDRAILS_SECRET"); raw != "" {
		if len(raw) < 16 {
			return nil, fmt.Errorf("GUARDRAILS_SECRET must be at least 16 characters")
		}
		c.Secret = []byte(raw)
	} else {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate secret: %w", err)
		}
		c.Secret = []byte(hex.EncodeToString(buf))
		c.SecretGenerated = true
	}

	switch c.Provider {
	case "mock", "openai", "groq", "anthropic", "local", "replay":
	default:
		return nil, fmt.Errorf(
			"GUARDRAILS_PROVIDER %q must be mock, openai, groq, anthropic, local or replay", c.Provider)
	}
	if c.Provider == "local" && c.LocalBaseURL == "" {
		return nil, fmt.Errorf("LOCAL_BASE_URL is required when the provider is local (e.g. http://ollama:11434/v1)")
	}
	switch c.JudgeMode {
	case "off", "shadow", "cascade", "always":
	default:
		return nil, fmt.Errorf("GUARDRAILS_JUDGE_MODE %q must be off, shadow, cascade or always", c.JudgeMode)
	}
	if c.SemanticCacheThreshold <= 0 || c.SemanticCacheThreshold > 1 {
		return nil, fmt.Errorf("GUARDRAILS_SEMANTIC_CACHE_THRESHOLD must be in (0,1]")
	}
	if c.Provider == "replay" && c.ReplayPath == "" {
		return nil, fmt.Errorf("GUARDRAILS_REPLAY_CASSETTE is required when the provider is replay")
	}
	if c.DefaultModel == "" {
		c.DefaultModel = defaultModelFor(c.Provider)
	}
	if c.Provider == "local" && c.DefaultModel == "" {
		return nil, fmt.Errorf("GUARDRAILS_DEFAULT_MODEL is required when the provider is local (the model id your server loaded)")
	}

	// Effort is spelled differently by the two providers and the vocabularies
	// only partly overlap. Validating against the wrong one would either reject
	// a legal value or forward an illegal one, so it is checked per provider.
	switch c.Provider {
	case "openai", "groq", "local":
		switch c.Effort {
		case "", "minimal", "low", "medium", "high":
		default:
			return nil, fmt.Errorf(
				"GUARDRAILS_EFFORT %q must be minimal, low, medium or high for OpenAI", c.Effort)
		}
	case "anthropic":
		switch c.Effort {
		case "", "low", "medium", "high", "xhigh", "max":
		default:
			return nil, fmt.Errorf(
				"GUARDRAILS_EFFORT %q must be low, medium, high, xhigh or max for Anthropic", c.Effort)
		}
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return nil, fmt.Errorf("GUARDRAILS_LOG_FORMAT %q must be json or text", c.LogFormat)
	}
	if c.MaxBodyBytes < 1024 {
		return nil, fmt.Errorf("GUARDRAILS_MAX_BODY_BYTES must be at least 1024")
	}
	if c.PolicyPath != "" && c.StrictPolicy {
		return nil, fmt.Errorf("set either GUARDRAILS_POLICY or GUARDRAILS_STRICT, not both")
	}
	return c, nil
}

// publishedSecrets are values that appear in this repository's examples.
// Anyone can read them, so anyone can forge an approval signed with one.
var publishedSecrets = map[string]bool{
	"change-me-to-a-long-random-string": true,
	"local-dev-secret-key-32chars":      true,
}

// WeakSecret reports whether the secret is one of the published examples.
func (c *Config) WeakSecret() bool { return publishedSecrets[string(c.Secret)] }

// CheckExposure refuses a configuration that would publish an open gateway.
//
// It is separate from FromEnv because only the server listens: grctl reads the
// same environment and has nothing to expose. A gateway holding a provider key
// and answering anyone on the network is a free proxy billed to its operator,
// and a published secret lets anyone forge a human approval, so both stop the
// process rather than scroll past as a warning. A loopback address is exempt,
// and GUARDRAILS_INSECURE_DEV covers a container published on loopback only.
func (c *Config) CheckExposure() error {
	if c.InsecureDev || loopbackAddr(c.Addr) {
		return nil
	}
	if c.WeakSecret() {
		return fmt.Errorf("GUARDRAILS_SECRET is a published example value and %s is reachable from the network: "+
			"generate one with `openssl rand -hex 32`", c.Addr)
	}
	upstream := c.Provider != "mock" || c.OpenAIAPIKey != "" || c.AnthropicAPIKey != "" || c.GroqAPIKey != ""
	if len(c.APIKeys) == 0 && upstream {
		return fmt.Errorf("no GUARDRAILS_API_KEYS set and %s is reachable from the network, so anyone could spend "+
			"your provider quota: set API keys, listen on 127.0.0.1, or set GUARDRAILS_INSECURE_DEV=true "+
			"for a port published on loopback only", c.Addr)
	}
	return nil
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func keyList(env string) []string {
	var out []string
	for _, k := range strings.Split(os.Getenv(env), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envList(key, def string) []string {
	raw := envStr(key, def)
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// defaultModelFor picks the model used when the caller names none.
//
// This is provider-specific on purpose. A single global default would send
// "claude-opus-5" to OpenAI the moment someone switched providers without also
// remembering to change the model, and the resulting 404 would arrive with no
// hint that the two settings are coupled.
func defaultModelFor(provider string) string {
	switch provider {
	case "openai":
		return "gpt-5"
	case "anthropic":
		return "claude-opus-5"
	case "groq":
		return "openai/gpt-oss-20b"
	case "local":
		return "" // a local server serves whatever it loaded; there is no sensible guess
	default:
		return "mock-model"
	}
}
