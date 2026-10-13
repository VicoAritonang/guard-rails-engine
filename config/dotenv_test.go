package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDotEnvParsing(t *testing.T) {
	path := writeEnv(t, `
# a comment line
GR_PLAIN=hello
export GR_EXPORTED=exported-value
GR_DQUOTED="spaced value"
GR_SQUOTED='literal $NOTVAR value'
GR_EMPTY=
GR_SPACES  =   trimmed
GR_ESCAPES="line\nbreak"
GR_INLINE_COMMENT=value # trailing comment
GR_HASH_IN_VALUE=sk-proj-abc#def
GR_EQUALS_IN_VALUE=base64==
`)
	for k := range map[string]bool{
		"GR_PLAIN": true, "GR_EXPORTED": true, "GR_DQUOTED": true, "GR_SQUOTED": true,
		"GR_EMPTY": true, "GR_SPACES": true, "GR_ESCAPES": true,
		"GR_INLINE_COMMENT": true, "GR_HASH_IN_VALUE": true, "GR_EQUALS_IN_VALUE": true,
	} {
		t.Setenv(k, "") // register for cleanup
		os.Unsetenv(k)
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GR_PLAIN":    "hello",
		"GR_EXPORTED": "exported-value",
		"GR_DQUOTED":  "spaced value",
		"GR_SQUOTED":  "literal $NOTVAR value",
		"GR_EMPTY":    "",
		"GR_SPACES":   "trimmed",
		"GR_ESCAPES":  "line\nbreak",
		// A trailing comment is stripped only when preceded by whitespace...
		"GR_INLINE_COMMENT": "value",
		// ...so a "#" inside a generated key or password survives intact. This
		// is the case that silently truncates credentials in naive parsers.
		"GR_HASH_IN_VALUE": "sk-proj-abc#def",
		// Base64 padding must not be mistaken for a second assignment.
		"GR_EQUALS_IN_VALUE": "base64==",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestRealEnvironmentWins is the security-relevant property. A committed .env
// must never be able to shadow a credential the platform injected.
func TestRealEnvironmentWins(t *testing.T) {
	t.Setenv("GR_PRECEDENCE", "from-real-environment")
	path := writeEnv(t, "GR_PRECEDENCE=from-dotenv-file\n")

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("GR_PRECEDENCE"); got != "from-real-environment" {
		t.Errorf("the .env file overrode the real environment: got %q", got)
	}
}

// An empty-but-set variable still counts as set: unsetting it is the only way
// to ask for the file's value.
func TestEmptyRealValueStillWins(t *testing.T) {
	t.Setenv("GR_EMPTY_WINS", "")
	path := writeEnv(t, "GR_EMPTY_WINS=from-file\n")

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("GR_EMPTY_WINS"); got != "" {
		t.Errorf("an explicitly empty environment value was overridden: got %q", got)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "definitely-absent")); err != nil {
		t.Errorf("a missing .env should be fine in production, got: %v", err)
	}
}

func TestMalformedLineIsRejected(t *testing.T) {
	// Failing loudly beats silently ignoring a line the author believed was
	// setting a credential.
	for _, body := range []string{
		"THIS_LINE_HAS_NO_EQUALS\n",
		"=novalue\n",
		"BAD KEY=value\n",
	} {
		if err := LoadDotEnv(writeEnv(t, body)); err == nil {
			t.Errorf("malformed line %q was accepted", body)
		}
	}
}

func TestProviderDefaultsAreCoupledToTheProvider(t *testing.T) {
	cases := map[string]string{
		"openai":    "gpt-5",
		"anthropic": "claude-opus-5",
		"mock":      "mock-model",
	}
	for provider, want := range cases {
		if got := defaultModelFor(provider); got != want {
			t.Errorf("defaultModelFor(%q) = %q, want %q", provider, got, want)
		}
	}
}

func TestFromEnvResolvesOpenAI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := "GUARDRAILS_PROVIDER=openai\n" +
		"OPENAI_API_KEY=sk-proj-test-key\n" +
		"GUARDRAILS_SECRET=a-sufficiently-long-secret\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Point FromEnv at the temp file and make sure nothing leaks in from the
	// developer's own shell.
	t.Setenv("GUARDRAILS_ENV_FILE", path)
	for _, k := range []string{
		"GUARDRAILS_PROVIDER", "OPENAI_API_KEY", "GUARDRAILS_SECRET",
		"GUARDRAILS_DEFAULT_MODEL", "GUARDRAILS_EFFORT", "GUARDRAILS_POLICY",
		"GUARDRAILS_STRICT",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "openai" {
		t.Errorf("provider = %q", cfg.Provider)
	}
	if cfg.OpenAIAPIKey != "sk-proj-test-key" {
		t.Errorf("api key not loaded from .env: %q", cfg.OpenAIAPIKey)
	}
	if cfg.DefaultModel != "gpt-5" {
		t.Errorf("default model = %q, want the OpenAI default", cfg.DefaultModel)
	}
	if cfg.EnvFile != path {
		t.Errorf("EnvFile = %q, want %q", cfg.EnvFile, path)
	}
	if cfg.SecretGenerated {
		t.Error("secret should have come from the file, not been generated")
	}
}

// TestEffortIsValidatedPerProvider: the two vocabularies only partly overlap,
// so validating against the wrong one either rejects a legal value or forwards
// an illegal one.
func TestEffortIsValidatedPerProvider(t *testing.T) {
	cases := []struct {
		provider string
		effort   string
		wantErr  bool
	}{
		{"openai", "minimal", false},
		{"openai", "high", false},
		{"openai", "xhigh", true}, // Anthropic-only
		{"anthropic", "xhigh", false},
		{"anthropic", "max", false},
		{"anthropic", "minimal", true}, // OpenAI-only
	}
	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.effort, func(t *testing.T) {
			t.Setenv("GUARDRAILS_ENV_FILE", filepath.Join(t.TempDir(), "absent"))
			t.Setenv("GUARDRAILS_PROVIDER", tc.provider)
			t.Setenv("GUARDRAILS_EFFORT", tc.effort)
			t.Setenv("GUARDRAILS_SECRET", "a-sufficiently-long-secret")

			_, err := FromEnv()
			if tc.wantErr && err == nil {
				t.Errorf("effort %q should be rejected for %s", tc.effort, tc.provider)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("effort %q should be accepted for %s: %v", tc.effort, tc.provider, err)
			}
		})
	}
}
