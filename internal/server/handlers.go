package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// guardRequest is the validate-mode payload.
type guardRequest struct {
	Tenant     string          `json:"tenant,omitempty"`
	Model      string          `json:"model,omitempty"`
	System     string          `json:"system,omitempty"`
	Messages   []core.Message  `json:"messages,omitempty"`
	Completion string          `json:"completion,omitempty"`
	Context    []string        `json:"context,omitempty"`
	ToolCalls  []core.ToolCall `json:"tool_calls,omitempty"`
	History    []core.ToolCall `json:"history,omitempty"`
	Step       int             `json:"step,omitempty"`
	Usage      core.Usage      `json:"usage,omitzero"`
	CostUSD    float64         `json:"cost_usd,omitempty"`
	Meta       map[string]any  `json:"meta,omitempty"`

	// ToolResults feeds the tool-result stage.
	ToolResults []core.ToolResult `json:"tool_results,omitempty"`

	// Session carries the agent's accumulated state. The tool rails are
	// trajectory-aware and the engine holds no per-trace state of its own, so
	// the caller owns this and passes it back each step.
	Session *core.SessionState `json:"session,omitempty"`

	// VaultToken is the token an earlier stage returned. Passing it to the
	// outbound stage is what restores the values inbound masked.
	VaultToken string `json:"vault_token,omitempty"`
}

// guardResponse returns the decision and the payload as the engine left it.
//
// Returning the rewritten payload rather than only the verdict is what makes
// validate mode useful: a caller that keeps its own provider integration still
// needs the masked prompt, not just permission to send the original.
type guardResponse struct {
	Decision   *core.Decision `json:"decision"`
	System     string         `json:"system,omitempty"`
	Messages   []core.Message `json:"messages,omitempty"`
	Completion string         `json:"completion,omitempty"`
	Blocked    bool           `json:"blocked"`
	Reason     string         `json:"reason,omitempty"`

	// ToolResults comes back rewritten -- an oversized result is truncated
	// rather than refused -- for the same reason the messages do: a caller that
	// keeps its own agent loop needs the sanitised text, not just a verdict.
	ToolResults []core.ToolResult `json:"tool_results,omitempty"`

	// Session is the agent state as this stage left it, for the caller to pass
	// back on the next step.
	Session *core.SessionState `json:"session,omitempty"`

	// VaultToken is the encrypted placeholder map, present when this exchange
	// masked anything. The gateway keeps no copy, so the caller holds it until
	// the outbound call.
	VaultToken string `json:"vault_token,omitempty"`
}

func (s *Server) handleGuard(w http.ResponseWriter, r *http.Request) {
	stage := core.Stage(r.PathValue("stage"))
	if stage == "" {
		// The playground route carries the stage in the body instead.
		stage = core.StageInbound
	}

	var req guardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if v, ok := req.Meta["stage"].(string); ok && core.Stage(v).Valid() {
		stage = core.Stage(v)
	}
	if !stage.Valid() {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"stage must be inbound, runtime or outbound")
		return
	}

	pipe, err := s.opts.Engine.Pipeline(stage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	tx := s.transaction(&req, stage)
	if req.VaultToken != "" {
		if err := tx.Vault.Unseal(req.VaultToken); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	dec, _ := pipe.Execute(r.Context(), tx)
	s.opts.Auditor.Record(r.Context(), tx, dec)
	s.publishDecision("guard."+string(stage), tx, dec)

	resp := guardResponse{
		Decision: dec,
		Blocked:  dec.Blocked(),
		System:   tx.System,
		Messages: tx.Messages,
		Session:  tx.Session,
	}
	switch stage {
	case core.StageOutbound:
		resp.Completion = tx.Completion
	case core.StageToolResult:
		resp.ToolResults = tx.ToolResults
	}
	if dec.Blocked() {
		resp.Reason = dec.Reason()
	}
	token, err := tx.Vault.Seal()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "could not seal the vault")
		return
	}
	resp.VaultToken = token

	// Validate mode always returns 200: the caller asked a question and got an
	// answer. A blocked decision is the answer, not a transport failure, and
	// returning 4xx here would make ordinary policy enforcement look like a
	// client bug in every dashboard the caller owns.
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) transaction(req *guardRequest, stage core.Stage) *core.Transaction {
	return &core.Transaction{
		ID:          newID(),
		Tenant:      req.Tenant,
		Stage:       stage,
		Model:       req.Model,
		System:      req.System,
		Messages:    req.Messages,
		Completion:  req.Completion,
		Context:     req.Context,
		ToolCalls:   req.ToolCalls,
		History:     req.History,
		ToolResults: req.ToolResults,
		Session:     req.Session,
		Step:        req.Step,
		Usage:       req.Usage,
		CostUSD:     req.CostUSD,
		Meta:        req.Meta,
		StartedAt:   time.Now(),
		Vault:       core.NewVault(s.opts.Secret),
	}
}

// decodeJSON reads a JSON body with unknown fields rejected.
//
// Silently ignoring an unrecognised field is how a caller ends up believing
// they set a policy option that the server never read.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
