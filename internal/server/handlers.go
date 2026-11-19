package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.vicoworks.com/guard-rails/internal/core"
	"go.vicoworks.com/guard-rails/internal/judge"
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

	// Semantic is the model-classifier outcome, when the semantic tier covers
	// this stage (GUARDRAILS_JUDGE_STAGES) and GUARDRAILS_JUDGE_VALIDATE is on.
	Semantic *judge.Outcome `json:"semantic,omitempty"`
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
			"stage must be inbound, runtime, tool_result or outbound")
		return
	}
	s.runGuard(w, r, stage, &req)
}

// runGuard executes one validate-mode stage and writes the response. Both the
// JSON route and the multipart upload route end here.
func (s *Server) runGuard(w http.ResponseWriter, r *http.Request, stage core.Stage, req *guardRequest) {
	resp, err := s.guard(r.Context(), stage, req)
	if err != nil {
		writeError(w, err.status, err.kind, err.msg)
		return
	}
	// Validate mode always returns 200: the caller asked a question and got an
	// answer. A blocked decision is the answer, not a transport failure, and
	// returning 4xx here would make ordinary policy enforcement look like a
	// client bug in every dashboard the caller owns.
	writeJSON(w, http.StatusOK, resp)
}

// apiError is a failure to evaluate, as opposed to a decision. Each transport
// renders it in its own vocabulary: an HTTP status, a gRPC code.
type apiError struct {
	status int
	kind   string
	msg    string
}

func invalidRequest(msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, kind: "invalid_request", msg: msg}
}

// guard runs one validate-mode stage. It is the single implementation behind
// POST /v1/guard/{stage}, the media upload route and the gRPC Guard method.
func (s *Server) guard(ctx context.Context, stage core.Stage, req *guardRequest) (*guardResponse, *apiError) {
	pipe, err := s.opts.Engine.Pipeline(stage)
	if err != nil {
		return nil, invalidRequest(err.Error())
	}

	tx := s.transaction(req, stage)
	if req.VaultToken != "" {
		if err := tx.Vault.Unseal(req.VaultToken); err != nil {
			return nil, invalidRequest(err.Error())
		}
	}
	dec, _ := pipe.Execute(ctx, tx)
	semantic := s.validateSemantic(ctx, stage, tx, dec)
	s.opts.Auditor.Record(ctx, tx, dec)
	s.publishDecision("guard."+string(stage), tx, dec)

	resp := guardResponse{
		Decision: dec,
		Blocked:  dec.Blocked(),
		System:   tx.System,
		Messages: withoutData(tx.Messages),
		Session:  tx.Session,
		Semantic: semantic,
	}
	switch stage {
	case core.StageOutbound:
		resp.Completion = tx.Completion
	case core.StageToolResult:
		resp.ToolResults = resultsWithoutData(tx.ToolResults)
	}
	if dec.Blocked() {
		resp.Reason = dec.Reason()
	}
	token, err := tx.Vault.Seal()
	if err != nil {
		return nil, &apiError{status: http.StatusInternalServerError, kind: "internal_error", msg: "could not seal the vault"}
	}
	resp.VaultToken = token
	return &resp, nil
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
