// Package mcp puts the guardrails control plane in front of Model Context
// Protocol servers.
//
// An MCP server is a third party with two channels into an agent: the tool
// definitions it advertises (which the model reads as instructions) and the
// results it returns (which the model reads as data, and treats as
// instructions anyway). Both are attack surface, and neither is visible to a
// guard that only inspects user prompts. The gateway here is an MCP server to
// the agent and an MCP client to the upstream servers, and it enforces at
// three points:
//
//  1. Discovery: every tool definition is scanned for poisoning (instructions
//     hidden in descriptions), shadowing (descriptions that try to alter how
//     OTHER tools are used) and pinned by hash, so a definition that changes
//     after approval -- a rug pull -- is quarantined instead of trusted.
//  2. Invocation: every tools/call goes through the same broker as
//     /v1/agent/execute -- risk tier, capability, schema, egress allowlist,
//     taint, lethal trifecta, dry run and single-use human approval -- BEFORE
//     anything is forwarded. A tool call is an effect, and an effect cannot be
//     taken back.
//  3. Results: what the upstream returned passes the tool-result rails before
//     the agent sees it, and marks the session as having ingested untrusted
//     content, which is what arms the taint and trifecta checks for every
//     later call.
package mcp

import (
	"encoding/base64"
	"encoding/json"
	"path"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// ProtocolVersion is the MCP revision this gateway speaks.
const ProtocolVersion = "2025-06-18"

// Request is a JSON-RPC 2.0 request or notification (no ID).
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether no response is expected.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

// Standard JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// Tool is an MCP tool definition.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations *Annotations    `json:"annotations,omitempty"`
}

// Annotations are behaviour hints a server attaches to a tool.
//
// The MCP specification says clients must treat them as untrusted unless the
// server is trusted, and the gateway takes that literally: a hint can make a
// tool look MORE dangerous than its default grade, never less. A server that
// marks wire_transfer readOnlyHint=true is exactly the server whose hints must
// not lower the bar.
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Content is one block of a tool result: text, image, audio, or an
// embedded resource.
type Content struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	Data     string    `json:"data,omitempty"`     // base64, for image and audio blocks
	MimeType string    `json:"mimeType,omitempty"` // for image and audio blocks
	Resource *Resource `json:"resource,omitempty"`
}

// Resource is an embedded resource block.
type Resource struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"` // base64
}

// Parts converts the non-text blocks of a result into attachments for the
// ingest step. A screenshot an MCP browser returns is as attacker-authorable
// as the page text it shows, and an agent reads both.
func (c *CallResult) Parts() []core.Part {
	var out []core.Part
	for _, b := range c.Content {
		switch b.Type {
		case "image", "audio":
			data, err := base64.StdEncoding.DecodeString(b.Data)
			if err != nil {
				continue
			}
			mod := core.ModalityImage
			if b.Type == "audio" {
				mod = core.ModalityAudio
			}
			out = append(out, core.Part{Type: mod, MIME: b.MimeType, Data: data})
		case "resource":
			if b.Resource == nil {
				continue
			}
			name := path.Base(b.Resource.URI)
			if b.Resource.Blob != "" {
				data, err := base64.StdEncoding.DecodeString(b.Resource.Blob)
				if err != nil {
					continue
				}
				out = append(out, core.Part{MIME: b.Resource.MimeType, Name: name, Data: data})
			} else if b.Resource.Text != "" {
				out = append(out, core.Part{Type: core.ModalityDocument, MIME: firstMIME(b.Resource.MimeType), Name: name,
					Data: []byte(b.Resource.Text)})
			}
		}
	}
	return out
}

func firstMIME(m string) string {
	if m == "" {
		return "text/plain"
	}
	return m
}

// CallResult is the result of tools/call.
type CallResult struct {
	Content           []Content `json:"content"`
	IsError           bool      `json:"isError,omitempty"`
	StructuredContent any       `json:"structuredContent,omitempty"`
}

// Text concatenates the text blocks of a result.
func (c *CallResult) Text() string {
	var s string
	for _, b := range c.Content {
		if b.Type == "text" {
			if s != "" {
				s += "\n"
			}
			s += b.Text
		}
	}
	return s
}

// callParams are the params of tools/call. Meta carries the gateway-specific
// controls a client can satisfy: an approval token, an idempotency key.
type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Meta      struct {
		ApprovalToken  string `json:"approval_token,omitempty"`
		IdempotencyKey string `json:"idempotency_key,omitempty"`
		DryRun         bool   `json:"dry_run,omitempty"`
	} `json:"_meta,omitzero"`
}

func errResp(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}}
}

func okResp(id json.RawMessage, result any) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Result: result}
}
