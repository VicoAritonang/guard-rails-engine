package mcp

import (
	"encoding/json"
	"io"
	"net/http"
)

// ServeHTTP implements the MCP Streamable HTTP transport (JSON responses).
//
// Every request is a single JSON-RPC message. The gateway answers with a
// plain JSON body rather than an SSE stream: it has no server-initiated
// messages to send, and the transport lets the server choose.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			g.EndSession(id)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		// No server-to-client stream is offered.
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeRPC(w, http.StatusBadRequest, errResp(nil, CodeParseError, "unreadable body"))
		return
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, http.StatusBadRequest, errResp(nil, CodeInvalidRequest, "expected a single JSON-RPC 2.0 message"))
		return
	}
	ctx := r.Context()

	if req.Method == "initialize" {
		id, _ := g.NewSession("mcp-")
		w.Header().Set("Mcp-Session-Id", id)
		writeRPC(w, http.StatusOK, okResp(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "guardrails-mcp-gateway", "version": "1"},
			"instructions": "Every tool call passes the guardrails control plane: risk tiers, capabilities, egress allowlist, taint, " +
				"lethal-trifecta detection, dry runs and single-use human approval for irreversible effects. Refusals explain " +
				"exactly what is missing. Tool results are scanned before you see them.",
		}))
		return
	}

	sid := r.Header.Get("Mcp-Session-Id")
	state, ok := g.Session(sid)
	if !ok {
		// 404 tells a client its session is gone and it must re-initialise.
		writeRPC(w, http.StatusNotFound, errResp(req.ID, CodeInvalidRequest, "unknown or expired session; send initialize"))
		return
	}
	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "ping":
		writeRPC(w, http.StatusOK, okResp(req.ID, map[string]any{}))
	case "tools/list":
		g.maybeSync(ctx)
		writeRPC(w, http.StatusOK, okResp(req.ID, map[string]any{"tools": g.listTools()}))
	case "tools/call":
		var p callParams
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			writeRPC(w, http.StatusOK, errResp(req.ID, CodeInvalidParams, "tools/call needs a name"))
			return
		}
		out := g.Call(ctx, state, p.Name, p.Arguments, CallMeta{ApprovalToken: p.Meta.ApprovalToken,
			IdempotencyKey: p.Meta.IdempotencyKey, DryRun: p.Meta.DryRun})
		// A refusal is a tool result with isError, not a protocol error: the
		// model should read it and adapt, which it cannot do with an RPC fault.
		writeRPC(w, http.StatusOK, okResp(req.ID, CallResult{
			Content:           []Content{{Type: "text", Text: out.Result}},
			IsError:           out.Status != "executed" && out.Status != "dry_run",
			StructuredContent: map[string]any{"guardrails": out},
		}))
	default:
		writeRPC(w, http.StatusOK, errResp(req.ID, CodeMethodNotFound, "method not supported: "+req.Method))
	}
}

// listTools renders the exposed catalog as MCP tool definitions. Upstream
// tools are passed through with their original schema; quarantined ones are
// simply absent.
func (g *Gateway) listTools() []Tool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []Tool
	for _, f := range g.functionToolsLocked() {
		schema, _ := json.Marshal(f["parameters"])
		out = append(out, Tool{Name: f["name"].(string), Description: f["description"].(string), InputSchema: schema})
	}
	return out
}

func writeRPC(w http.ResponseWriter, status int, resp *Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
