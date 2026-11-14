package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/judge"
)

// handleMediaInfo reports what the ingest step can read in this deployment:
// which formats are parsed locally and which backends (OCR, speech-to-text,
// image classifiers) are wired. A team deciding whether to send screenshots
// through the gateway needs to know whether anything reads the pixels.
func (s *Server) handleMediaInfo(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"ingest": s.opts.Engine.Media().Capabilities()}
	g := s.opts.Policy.Guard("media")
	out["limits"] = g.Params
	writeJSON(w, http.StatusOK, out)
}

// handleMediaUpload scans files sent as multipart/form-data, the shape every
// upload form and RAG ingestion job already produces:
//
//	curl -F file=@contract.pdf -F stage=tool_result -F origin=web http://gw/v1/guard/media
//
// Fields: file (repeatable), text (optional prompt to scan with the files),
// stage (inbound | tool_result, default inbound), tenant, origin (tool | web,
// tool_result only), tool (tool name, tool_result only). The answer is the
// ordinary validate-mode response: a decision, plus each file's extraction
// report and redacted text.
func (s *Server) handleMediaUpload(w http.ResponseWriter, r *http.Request) {
	limit := s.opts.MediaUploadBytes
	if limit <= 0 {
		limit = 32 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseMultipartForm(min(limit, 16<<20)); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				fmt.Sprintf("upload exceeds %d bytes (GUARDRAILS_MEDIA_UPLOAD_BYTES)", limit))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "expected multipart/form-data: "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	stage := core.Stage(strings.TrimSpace(r.FormValue("stage")))
	if stage == "" {
		stage = core.StageInbound
	}
	if stage != core.StageInbound && stage != core.StageToolResult {
		writeError(w, http.StatusBadRequest, "invalid_request", "stage must be inbound or tool_result")
		return
	}
	var parts []core.Part
	for _, fh := range r.MultipartForm.File["file"] {
		f, err := fh.Open()
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		parts = append(parts, core.Part{Name: fh.Filename, MIME: fh.Header.Get("Content-Type"), Data: data})
	}
	if len(parts) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "attach at least one file in the \"file\" field")
		return
	}

	req := guardRequest{Tenant: r.FormValue("tenant")}
	text := r.FormValue("text")
	if stage == core.StageToolResult {
		origin := core.Origin(r.FormValue("origin"))
		if origin == "" {
			origin = core.OriginWeb // an uploaded document is somebody else's text until proven otherwise
		}
		tool := r.FormValue("tool")
		if tool == "" {
			tool = "document_upload"
		}
		req.ToolResults = []core.ToolResult{{Name: tool, Content: text, Origin: origin, Parts: parts}}
	} else {
		req.Messages = []core.Message{{Role: core.RoleUser, Content: text, Parts: parts}}
	}
	s.runGuard(w, r, stage, &req)
}

// validateSemantic runs the semantic tier on a validate-mode decision and folds an
// enforced verdict into it, exactly as the proxy does.
func (s *Server) validateSemantic(ctx context.Context, stage core.Stage, tx *core.Transaction, dec *core.Decision) *judge.Outcome {
	tier := s.opts.Tier
	if !s.opts.JudgeValidate || !tier.Applies(stage) || dec.Blocked() {
		return nil
	}
	var text string
	switch stage {
	case core.StageInbound:
		text = judge.UserText(tx.Messages)
	case core.StageOutbound:
		text = tx.Completion
	case core.StageToolResult:
		text = judge.ResultText(tx.ToolResults)
	case core.StageRuntime:
		if len(tx.ToolCalls) == 0 {
			return nil
		}
		text = judge.ToolCallText(tx.Messages, tx.ToolCalls)
	}
	if tier.Mode() == judge.ModeShadow {
		// Shadow never enforces, so it never makes the caller wait.
		go tier.Evaluate(context.WithoutCancel(ctx), stage, text, dec)
		return &judge.Outcome{Reason: "shadow"}
	}
	ctx, cancel := context.WithTimeout(ctx, tier.Options().Timeout+time.Second)
	defer cancel()
	out := tier.Evaluate(ctx, stage, text, dec)
	if out.Enforced {
		f := out.Finding()
		dec.Findings = append([]core.Finding{f}, dec.Findings...)
		dec.Action = core.ActionBlock
	}
	return out
}

// withoutData returns a copy of msgs whose parts carry no bytes. Validate
// mode answers with the payload as the engine left it, and echoing a 20 MB
// upload back is all cost: a part forwarded "native" is unchanged (send the
// bytes you have), and a part the policy converted comes back as text.
func withoutData(msgs []core.Message) []core.Message {
	out := make([]core.Message, len(msgs))
	for i, m := range msgs {
		out[i] = m
		if len(m.Parts) == 0 {
			continue
		}
		out[i].Parts = stripParts(m.Parts)
	}
	return out
}

func resultsWithoutData(rs []core.ToolResult) []core.ToolResult {
	out := make([]core.ToolResult, len(rs))
	for i, r := range rs {
		out[i] = r
		if len(r.Parts) > 0 {
			out[i].Parts = stripParts(r.Parts)
		}
	}
	return out
}

func stripParts(in []core.Part) []core.Part {
	out := make([]core.Part, len(in))
	for j, p := range in {
		p.Data = nil
		if strings.HasPrefix(p.URL, "data:") {
			p.URL = ""
		}
		out[j] = p
	}
	return out
}
