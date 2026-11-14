package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// fakeOpenAI stands in for the API. Driving the real SDK against it exercises
// the actual serialisation and response-parsing path -- which is where the
// mistakes live -- without a network call or a bill.
func fakeOpenAI(t *testing.T, respBody string, status int) (*httptest.Server, *[]byte) {
	t.Helper()
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

const okCompletion = `{
  "id": "chatcmpl-test",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "gpt-5",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "Hello from the model."},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 1000,
    "completion_tokens": 50,
    "total_tokens": 1050,
    "prompt_tokens_details": {"cached_tokens": 800, "cache_write_tokens": 200}
  }
}`

func newTestOpenAI(t *testing.T, baseURL string) *OpenAI {
	t.Helper()
	p, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: baseURL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOpenAIUsageAccounting is the billing-critical one. prompt_tokens INCLUDES
// cached_tokens, so counting both at the full input rate would overstate a
// cache-heavy request several-fold.
func TestOpenAIUsageAccounting(t *testing.T) {
	srv, _ := fakeOpenAI(t, okCompletion, http.StatusOK)
	p := newTestOpenAI(t, srv.URL)

	resp, err := p.Complete(context.Background(), Request{
		Model:    "gpt-5",
		Messages: []core.Message{{Role: core.RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Usage.InputTokens != 200 {
		t.Errorf("InputTokens = %d, want 200 (1000 prompt - 800 cached)", resp.Usage.InputTokens)
	}
	if resp.Usage.CacheReadTokens != 800 {
		t.Errorf("CacheReadTokens = %d, want 800", resp.Usage.CacheReadTokens)
	}
	if resp.Usage.OutputTokens != 50 {
		t.Errorf("OutputTokens = %d, want 50", resp.Usage.OutputTokens)
	}
	// OpenAI bills cache writes at the ordinary input rate and reports them as
	// a breakdown of prompt_tokens, so they are already inside InputTokens.
	// Populating this field too would double-charge them.
	if resp.Usage.CacheWriteTokens != 0 {
		t.Errorf("CacheWriteTokens = %d, want 0; see the comment in openai.go",
			resp.Usage.CacheWriteTokens)
	}
	if resp.Text != "Hello from the model." || resp.StopReason != "stop" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// TestOpenAISendsMaxCompletionTokens: max_tokens is rejected outright by the
// reasoning models, so sending the modern parameter is not optional.
func TestOpenAISendsMaxCompletionTokens(t *testing.T) {
	srv, captured := fakeOpenAI(t, okCompletion, http.StatusOK)
	p := newTestOpenAI(t, srv.URL)

	if _, err := p.Complete(context.Background(), Request{
		Model:     "gpt-5",
		System:    "You are a support assistant.",
		Messages:  []core.Message{{Role: core.RoleUser, Content: "hi"}},
		MaxTokens: 4321,
	}); err != nil {
		t.Fatal(err)
	}

	var sent map[string]any
	if err := json.Unmarshal(*captured, &sent); err != nil {
		t.Fatalf("could not parse the outgoing request: %v", err)
	}
	if _, legacy := sent["max_tokens"]; legacy {
		t.Error("sent the legacy max_tokens parameter")
	}
	if got, ok := sent["max_completion_tokens"].(float64); !ok || int(got) != 4321 {
		t.Errorf("max_completion_tokens = %v, want 4321", sent["max_completion_tokens"])
	}
	// Sampling parameters must not be forwarded: the reasoning models 400 on
	// them, which would look like a gateway bug rather than a client mistake.
	for _, banned := range []string{"temperature", "top_p", "top_k", "frequency_penalty"} {
		if _, present := sent[banned]; present {
			t.Errorf("forwarded the %s parameter", banned)
		}
	}

	msgs, _ := sent["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected a system message plus the user turn, got %d", len(msgs))
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "system" {
		t.Errorf("first message role = %v, want system", first["role"])
	}
}

func TestOpenAIRoleMapping(t *testing.T) {
	srv, captured := fakeOpenAI(t, okCompletion, http.StatusOK)
	p := newTestOpenAI(t, srv.URL)

	if _, err := p.Complete(context.Background(), Request{
		Model: "gpt-5",
		Messages: []core.Message{
			{Role: core.RoleUser, Content: "first"},
			{Role: core.RoleAssistant, Content: "reply"},
			{Role: core.RoleTool, Content: "tool output"},
			{Role: core.RoleUser, Content: "second"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	var sent struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(*captured, &sent); err != nil {
		t.Fatal(err)
	}
	// Tool results ride as user content; the runtime stage already inspected
	// the calls that produced them.
	want := []string{"user", "assistant", "user", "user"}
	if len(sent.Messages) != len(want) {
		t.Fatalf("got %d messages, want %d", len(sent.Messages), len(want))
	}
	for i, w := range want {
		if sent.Messages[i].Role != w {
			t.Errorf("message %d role = %q, want %q", i, sent.Messages[i].Role, w)
		}
	}
}

func TestOpenAIErrorClassification(t *testing.T) {
	cases := []struct {
		status     int
		wantStatus int
		retryable  bool
	}{
		{http.StatusUnauthorized, 401, false},
		{http.StatusNotFound, 404, false},
		{http.StatusTooManyRequests, 429, true},
		{http.StatusInternalServerError, 502, true},
		{http.StatusBadGateway, 502, true},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv, _ := fakeOpenAI(t, `{"error":{"message":"nope","type":"x"}}`, tc.status)
			// One attempt only: retries would make a 429 test slow.
			p, err := NewOpenAI(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL, MaxRetries: -1})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Complete(context.Background(), Request{
				Model:    "gpt-5",
				Messages: []core.Message{{Role: core.RoleUser, Content: "hi"}},
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			var ue *UpstreamError
			if !asUpstream(err, &ue) {
				t.Fatalf("error was not classified: %v", err)
			}
			if ue.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", ue.StatusCode, tc.wantStatus)
			}
			if ue.Retryable != tc.retryable {
				t.Errorf("retryable = %v, want %v", ue.Retryable, tc.retryable)
			}
		})
	}
}

func TestOpenAIRejectsEmptyMessages(t *testing.T) {
	p := newTestOpenAI(t, "http://127.0.0.1:1")
	_, err := p.Complete(context.Background(), Request{Model: "gpt-5"})
	if err == nil || !strings.Contains(err.Error(), "no messages") {
		t.Errorf("expected a no-messages error, got %v", err)
	}
}

func TestOpenAIRejectsBadReasoningEffort(t *testing.T) {
	if _, err := NewOpenAI(OpenAIOptions{ReasoningEffort: "xhigh"}); err == nil {
		t.Error("xhigh is Anthropic vocabulary and should be rejected for OpenAI")
	}
	for _, ok := range []string{"", "minimal", "low", "medium", "high"} {
		if _, err := NewOpenAI(OpenAIOptions{ReasoningEffort: ok}); err != nil {
			t.Errorf("effort %q should be accepted: %v", ok, err)
		}
	}
}

func TestProviderFactoryKnowsOpenAI(t *testing.T) {
	p, err := New("openai", Options{OpenAI: OpenAIOptions{APIKey: "sk-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "openai" {
		t.Errorf("Name() = %q", p.Name())
	}
	if _, err := New("gemini", Options{}); err == nil {
		t.Error("an unknown provider should be rejected")
	}
}

func asUpstream(err error, target **UpstreamError) bool {
	for err != nil {
		if ue, ok := err.(*UpstreamError); ok {
			*target = ue
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
