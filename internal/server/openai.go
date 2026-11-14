package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
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
		text, parts, err := textContent(m.Content)
		if err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
		if len(parts) > 0 && m.Role != core.RoleUser {
			return nil, fmt.Errorf("%w: messages[%d]: attachments are accepted on user turns only", errUnsupported, i)
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
		req.Messages = append(req.Messages, core.Message{Role: m.Role, Content: text, Name: m.Name, Parts: parts})
	}
	return req, nil
}

func hasItems(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "[]"
}

// wirePart is one OpenAI content part. Both the Chat Completions spellings
// (image_url, input_audio, file) and the Responses API spellings
// (input_text, input_image, input_file) are accepted, since SDKs and
// frameworks emit either.
type wirePart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	ImageURL json.RawMessage `json:"image_url"`
	Detail   string          `json:"detail"`
	Audio    *struct {
		Data   string `json:"data"`
		Format string `json:"format"`
	} `json:"input_audio"`
	File *struct {
		FileData string `json:"file_data"`
		FileID   string `json:"file_id"`
		Filename string `json:"filename"`
	} `json:"file"`
	// Responses API flat fields.
	FileData string `json:"file_data"`
	FileID   string `json:"file_id"`
	Filename string `json:"filename"`
}

// textContent reads a message body, which OpenAI clients send either as a
// string or as a list of typed parts. Text parts are joined into the turn's
// content; images, audio and files become core.Parts, which the ingest step
// turns into text for the guards before anything is forwarded.
func textContent(raw json.RawMessage) (string, []core.Part, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil, nil
	}
	var wire []wirePart
	if err := json.Unmarshal(raw, &wire); err != nil {
		return "", nil, errors.New("content must be a string or a list of content parts")
	}
	var (
		texts []string
		parts []core.Part
	)
	for i, p := range wire {
		switch p.Type {
		case "text", "input_text":
			texts = append(texts, p.Text)
		case "image_url", "input_image":
			url, detail := imageURL(p)
			if url == "" {
				return "", nil, fmt.Errorf("content[%d]: image part has no url", i)
			}
			parts = append(parts, core.Part{Type: core.ModalityImage, URL: url, Detail: detail})
		case "input_audio":
			if p.Audio == nil || p.Audio.Data == "" {
				return "", nil, fmt.Errorf("content[%d]: input_audio has no data", i)
			}
			data, err := base64.StdEncoding.DecodeString(p.Audio.Data)
			if err != nil {
				return "", nil, fmt.Errorf("content[%d]: input_audio data is not base64", i)
			}
			parts = append(parts, core.Part{Type: core.ModalityAudio, Data: data, Format: p.Audio.Format,
				MIME: "audio/" + strings.ReplaceAll(p.Audio.Format, "mp3", "mpeg")})
		case "file", "input_file":
			data, id, name := p.FileData, p.FileID, p.Filename
			if p.File != nil {
				data, id, name = p.File.FileData, p.File.FileID, p.File.Filename
			}
			if id != "" && data == "" {
				// An uploaded file id names bytes the gateway never saw.
				return "", nil, fmt.Errorf("%w: content[%d] references file_id %q; send file_data inline so it can be scanned",
					errUnsupported, i, id)
			}
			part := core.Part{Type: core.ModalityDocument, Name: name}
			if strings.HasPrefix(data, "data:") {
				part.URL = data
			} else if b, err := base64.StdEncoding.DecodeString(data); err == nil {
				part.Data = b
			} else {
				return "", nil, fmt.Errorf("content[%d]: file_data must be base64 or a data: URI", i)
			}
			parts = append(parts, part)
		default:
			return "", nil, fmt.Errorf("%w: content part %q is not supported", errUnsupported, p.Type)
		}
	}
	return strings.Join(texts, "\n"), parts, nil
}

func imageURL(p wirePart) (string, string) {
	if len(p.ImageURL) == 0 {
		return "", ""
	}
	var s string
	if json.Unmarshal(p.ImageURL, &s) == nil {
		return s, p.Detail
	}
	var obj struct {
		URL    string `json:"url"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(p.ImageURL, &obj)
	return obj.URL, obj.Detail
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
