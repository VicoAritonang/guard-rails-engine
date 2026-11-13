package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// The proxy speaks the OpenAI chat completions dialect, because that is the one
// every SDK and framework can already be pointed at by changing a base URL. The
// engine's own fields ride alongside the OpenAI ones, so a client that knows
// about them loses nothing and a client that does not never sees them.

// wireChat is the request as it arrives on the wire.
type wireChat struct {
	Model               string          `json:"model"`
	Tenant              string          `json:"tenant"`
	System              string          `json:"system"`
	Messages            []wireMessage   `json:"messages"`
	MaxTokens           int             `json:"max_tokens"`
	MaxCompletionTokens int             `json:"max_completion_tokens"`
	Context             []string        `json:"context"`
	Meta                map[string]any  `json:"meta"`
	Cache               *bool           `json:"cache"`
	Stream              bool            `json:"stream"`
	StreamOptions       *streamOptions  `json:"stream_options"`
	N                   int             `json:"n"`
	Tools               json.RawMessage `json:"tools"`
	Functions           json.RawMessage `json:"functions"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type wireMessage struct {
	Role       core.Role       `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name"`
	ToolCalls  json.RawMessage `json:"tool_calls"`
	ToolCallID string          `json:"tool_call_id"`
}

// handledParams are the request fields the proxy acts on. Anything else is
// accepted and reported in guardrails.ignored_params: the upstream API grows new
// parameters faster than a gateway can list them, so refusing them would break
// clients on every SDK release, and dropping them silently would hide that a
// setting had no effect.
var handledParams = map[string]bool{
	"model": true, "tenant": true, "system": true, "messages": true, "max_tokens": true,
	"max_completion_tokens": true, "context": true, "meta": true, "cache": true, "stream": true,
	"stream_options": true, "n": true, "tools": true, "functions": true, "tool_choice": true,
}

// errUnsupported marks a request the proxy refuses rather than half-serves.
var errUnsupported = errors.New("unsupported")

func decodeChat(r *http.Request) (*chatRequest, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var wire wireChat
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}

	// Tools are refused, not dropped. Forwarding them would let a model call
	// tools outside the control plane, and dropping them would answer as if the
	// tools had never been offered.
	if hasItems(wire.Tools) || hasItems(wire.Functions) {
		return nil, fmt.Errorf("%w: tools are not forwarded by the proxy; broker them through /mcp or /v1/agent/execute, "+
			"or check each call with /v1/guard/runtime", errUnsupported)
	}
	if wire.N > 1 {
		return nil, fmt.Errorf("%w: n must be 1: every completion has to pass the outbound stage", errUnsupported)
	}

	req := &chatRequest{
		Model: wire.Model, Tenant: wire.Tenant, System: wire.System, Context: wire.Context,
		Meta: wire.Meta, Cache: wire.Cache, Stream: wire.Stream,
		MaxTokens: wire.MaxTokens,
	}
	if wire.MaxCompletionTokens > 0 {
		req.MaxTokens = wire.MaxCompletionTokens
	}
	if wire.StreamOptions != nil {
		req.IncludeUsage = wire.StreamOptions.IncludeUsage
	}
	for name := range fields {
		if !handledParams[name] {
			req.Ignored = append(req.Ignored, name)
		}
	}
	sort.Strings(req.Ignored)

	for i, m := range wire.Messages {
		if hasItems(m.ToolCalls) || m.Role == core.RoleTool {
			return nil, fmt.Errorf("%w: messages[%d] is a tool turn, which the proxy does not forward", errUnsupported, i)
		}
		text, err := textContent(m.Content)
		if err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
		// System turns move to the System field, the one place every provider
		// adapter reads and every guard treats as the operator's instructions.
		if m.Role == core.RoleSystem || m.Role == "developer" {
			if req.System != "" {
				req.System += "\n\n"
			}
			req.System += text
			continue
		}
		req.Messages = append(req.Messages, core.Message{Role: m.Role, Content: text, Name: m.Name})
	}
	return req, nil
}

func hasItems(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "[]"
}

// textContent reads a message body, which OpenAI clients send either as a
// string or as a list of typed parts.
func textContent(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", errors.New("content must be a string or a list of text parts")
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		// The guards read text. An image or file would reach the provider
		// unscanned, so it is refused rather than passed along.
		if p.Type != "text" {
			return "", fmt.Errorf("%w: content part %q cannot be scanned, only text is accepted", errUnsupported, p.Type)
		}
		texts = append(texts, p.Text)
	}
	return strings.Join(texts, "\n"), nil
}

// chatChoice and the fields below are the OpenAI response shape.
type chatChoice struct {
	Index        int          `json:"index"`
	Message      *chatMessage `json:"message,omitempty"`
	Delta        *chatMessage `json:"delta,omitempty"`
	FinishReason *string      `json:"finish_reason"`
}

type chatMessage struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// chatUsage reports tokens under both vocabularies.
type chatUsage struct {
	core.Usage
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func usageOf(u core.Usage) chatUsage {
	return chatUsage{Usage: u, PromptTokens: u.InputTokens, CompletionTokens: u.OutputTokens,
		TotalTokens: u.InputTokens + u.OutputTokens}
}

// finishReason maps each provider's stop vocabulary onto OpenAI's.
func finishReason(stop string) string {
	switch stop {
	case "length", "max_tokens":
		return "length"
	case "content_filter", "refusal":
		return "content_filter"
	default:
		return "stop"
	}
}

func newChatResponse(id string, created time.Time, content, stop string) chatResponse {
	reason := finishReason(stop)
	return chatResponse{
		ID: id, Object: "chat.completion", Created: created.Unix(), Content: content, StopReason: stop,
		Choices: []chatChoice{{Message: &chatMessage{Role: "assistant", Content: content}, FinishReason: &reason}},
	}
}

// chatChunk is one server-sent event of a streamed completion.
type chatChunk struct {
	ID         string          `json:"id"`
	Object     string          `json:"object"`
	Created    int64           `json:"created"`
	Model      string          `json:"model"`
	Choices    []chatChoice    `json:"choices"`
	Usage      *chatUsage      `json:"usage,omitempty"`
	Guardrails *guardrailsMeta `json:"guardrails,omitempty"`
}

// writeChatStream delivers a finished completion as an event stream.
//
// The completion is complete before the first byte goes out. The outbound stage
// judges the whole answer, and a token already on the user's screen cannot be
// withdrawn, so a guardrail that streams live is a guardrail that reports after
// the fact. A blocked answer therefore arrives as an ordinary 422, never as a
// stream that stops halfway. The cost is time to first token.
func writeChatStream(w http.ResponseWriter, resp chatResponse, includeUsage bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(c chatChunk) {
		c.ID, c.Object, c.Created, c.Model = resp.ID, "chat.completion.chunk", resp.Created, resp.Model
		raw, err := json.Marshal(c)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
	}

	send(chatChunk{Choices: []chatChoice{{Delta: &chatMessage{Role: "assistant", Content: resp.Content}}}})
	last := chatChunk{Choices: []chatChoice{{Delta: &chatMessage{}, FinishReason: resp.Choices[0].FinishReason}}, Guardrails: &resp.Guardrails}
	send(last)
	if includeUsage {
		usage := resp.Usage
		send(chatChunk{Choices: []chatChoice{}, Usage: &usage})
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	_ = http.NewResponseController(w).Flush()
}

// modelEntry is one row of the OpenAI model list.
type modelEntry struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}
