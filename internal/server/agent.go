package server

import (
	"context"
	"net/http"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/agent"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/mcp"
	"go.vicoworks.com/guard-rails-engine/internal/telemetry"
)

// The agent endpoints are the enforcement point for tool execution.
//
// /v1/guard/runtime answers "may this call run" and leaves the running to the
// caller, which is the right shape for a team that already has an agent
// runtime. /v1/agent/execute runs the call itself, which is the right shape for
// a team that would otherwise have to be trusted to honour the answer. Both
// share one evaluator, so they cannot disagree.

// agentExecuteRequest is the broker payload.
type agentExecuteRequest struct {
	Trace   string             `json:"trace,omitempty"`
	Call    core.ToolCall      `json:"call"`
	Session *core.SessionState `json:"session,omitempty"`

	IdempotencyKey string `json:"idempotency_key,omitempty"`
	ApprovalToken  string `json:"approval_token,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

// agentApproveRequest mints a grant for one specific call.
type agentApproveRequest struct {
	Trace     string `json:"trace,omitempty"`
	Tool      string `json:"tool"`
	Signature string `json:"signature"`
	Approver  string `json:"approver"`
	Reason    string `json:"reason,omitempty"`
}

type agentApproveResponse struct {
	Token string       `json:"token"`
	Grant *agent.Grant `json:"grant"`
}

func (s *Server) handleAgentTools(w http.ResponseWriter, r *http.Request) {
	ev := s.evaluator()
	if ev == nil {
		writeError(w, http.StatusServiceUnavailable, "tool_safety_disabled",
			"the tool_safety guard is not enabled in the active policy")
		return
	}
	opts := ev.Options()
	writeJSON(w, http.StatusOK, map[string]any{
		"tools":            ev.Catalog().Tools(),
		"capabilities":     ev.Catalog().Capabilities(),
		"max_tier":         opts.MaxTier.String(),
		"egress_allowlist": opts.EgressAllowlist,
		"lint":             ev.Lint(),
	})
}

func (s *Server) handleAgentExecute(w http.ResponseWriter, r *http.Request) {
	broker := s.broker
	if broker == nil {
		writeError(w, http.StatusServiceUnavailable, "tool_safety_disabled",
			"the tool_safety guard is not enabled in the active policy")
		return
	}

	var req agentExecuteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Call.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "call.name is required")
		return
	}
	if req.Trace == "" {
		req.Trace = requestID(r.Context())
	}

	out := broker.Do(r.Context(), agent.Request{
		Trace:          req.Trace,
		Call:           req.Call,
		Session:        req.Session,
		IdempotencyKey: req.IdempotencyKey,
		ApprovalToken:  req.ApprovalToken,
		DryRun:         req.DryRun,
	})

	// A refused call is 403, not 200-with-a-flag. The caller here is an agent
	// runtime, and an HTTP client that has to read a body field to discover it
	// was denied is an HTTP client that will eventually forget to.
	status := http.StatusOK
	if !out.Assessment.Allowed() {
		status = http.StatusForbidden
	}
	writeJSON(w, status, out)
}

func (s *Server) handleAgentApprove(w http.ResponseWriter, r *http.Request) {
	ev := s.evaluator()
	if ev == nil || ev.Options().Approver == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals_unavailable",
			"no approval signing key is configured")
		return
	}

	var req agentApproveRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// This endpoint mints authority, so it is the one place in the API where a
	// missing field is worth a hard 400 rather than a default. An approval with
	// no approver is an audit trail that cannot answer the only question anyone
	// will ask about it.
	switch {
	case req.Tool == "":
		writeError(w, http.StatusBadRequest, "invalid_request", "tool is required")
		return
	case req.Signature == "":
		writeError(w, http.StatusBadRequest, "invalid_request",
			"signature is required: an approval is bound to one exact call, "+
				"not to a tool name")
		return
	case req.Approver == "":
		writeError(w, http.StatusBadRequest, "invalid_request",
			"approver is required: an unattributed approval is not an approval")
		return
	}

	token, grant, err := ev.Options().Approver.Issue(
		req.Trace, req.Tool, req.Signature, req.Approver, req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.log.Info("approval issued",
		"grant", grant.ID, "tool", grant.Tool, "approver", grant.Approver,
		"signature", grant.Signature, "expires_at", grant.ExpiresAt)
	writeJSON(w, http.StatusOK, agentApproveResponse{Token: token, Grant: grant})
}

func (s *Server) evaluator() *agent.Evaluator {
	if s.opts.Engine == nil {
		return nil
	}
	return s.opts.Engine.ToolEvaluator()
}

// auditSink adapts the broker's receipts onto the redacted audit trail.
//
// The indirection exists so internal/telemetry never has to import
// internal/agent: telemetry depends on core and nothing else, which is what
// keeps it usable from every layer without an import cycle.
type auditSink struct{ s *Server }

func (a auditSink) Receipt(r *agent.Receipt) {
	if a.s == nil || a.s.opts.Auditor == nil {
		return
	}
	a.s.opts.Auditor.RecordToolExecution(context.Background(), telemetry.ToolReceipt{
		ID:         r.ID,
		Trace:      r.Trace,
		Tool:       r.Tool,
		Tier:       r.Tier,
		Signature:  r.Signature,
		ArgsDigest: r.ArgsDigest,
		Hash:       r.Hash,
		Approver:   r.Approver,
		Error:      r.Error,
		Controls:   r.Controls,
		DeniedBy:   r.Denied,
		Allowed:    r.Allowed,
		DryRun:     r.DryRun,
		Replay:     r.Replay,
	})
}

// handleAgentRun runs the gateway's own function-calling agent.
//
// The task itself passes the inbound stage first -- an agent is as injectable
// as a chatbot -- and then every tool call the model proposes goes through the
// MCP gateway's single enforcement path. A run that needs a human returns 200
// with status awaiting_approval and the pending call's preview; the caller
// approves via /v1/agent/approve and posts the returned transcript back.
func (s *Server) handleAgentRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.MCP == nil {
		writeError(w, http.StatusServiceUnavailable, "mcp_disabled", "set GUARDRAILS_MCP to enable the agent runtime")
		return
	}
	var req mcp.RunRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Task == "" && len(req.Transcript) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "task is required")
		return
	}
	ctx := r.Context()
	if req.SessionID == "" {
		req.SessionID, _ = s.opts.MCP.NewSession("agent-")
	}
	if req.Task != "" && len(req.Transcript) == 0 {
		// The session's vault masks the task, so the values the model only
		// sees as placeholders can be restored when a tool actually runs.
		tx := &core.Transaction{ID: newID(), Stage: core.StageInbound, Model: req.Model,
			Messages: []core.Message{{Role: core.RoleUser, Content: req.Task}}, StartedAt: time.Now(),
			Vault: s.opts.MCP.Vault(req.SessionID)}
		dec, _ := s.opts.Engine.Inbound.Execute(ctx, tx)
		s.opts.Auditor.Record(ctx, tx, dec)
		s.publishDecision("agent.inbound", tx, dec)
		if dec.Blocked() {
			writeErrorDetails(w, http.StatusUnprocessableEntity, "blocked_by_policy", dec.Reason(), dec)
			return
		}
		req.Task = tx.Messages[0].Content // masked
	}
	writeJSON(w, http.StatusOK, s.opts.MCP.RunAgent(ctx, s.opts.Provider, req))
}
