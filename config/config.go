package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	// LogFile, when set, receives a copy of every log line as JSON, for a log
	// shipper to tail. Stdout stays the primary sink.
	LogFile string

	// EnvFile records which .env file was loaded, or "" if none was found. It
	// is logged at startup so it is obvious which file supplied a credential.
	EnvFile string

	APIKeys []string
	Secret  []byte

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
		Addr:            envStr("GUARDRAILS_ADDR", ":8080"),
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

		UpstreamMaxRetries: envInt("GUARDRAILS_UPSTREAM_MAX_RETRIES", 0),
		OTLPEndpoint:       envStr("GUARDRAILS_OTLP_ENDPOINT", ""),
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

	if raw := os.Getenv("GUARDRAILS_API_KEYS"); raw != "" {
		for _, k := range strings.Split(raw, ",") {
			if k = strings.TrimSpace(k); k != "" {
				c.APIKeys = append(c.APIKeys, k)
			}
		}
	}

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
	case "mock", "openai", "groq", "anthropic", "replay":
	default:
		return nil, fmt.Errorf(
			"GUARDRAILS_PROVIDER %q must be mock, openai, groq, anthropic or replay", c.Provider)
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

	// Effort is spelled differently by the two providers and the vocabularies
	// only partly overlap. Validating against the wrong one would either reject
	// a legal value or forward an illegal one, so it is checked per provider.
	switch c.Provider {
	case "openai", "groq":
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
	default:
		return "mock-model"
	}
}
