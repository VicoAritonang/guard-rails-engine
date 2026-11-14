package server

import (
	"net/http"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/judge"
)

// decisionView is the console's projection of a stage decision: enough to
// animate which guard fired, never the matched value.
type decisionView struct {
	Stage    string      `json:"stage"`
	Action   string      `json:"action"`
	Category string      `json:"category,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Score    float64     `json:"score,omitempty"`
	Message  string      `json:"message,omitempty"`
	Guard    string      `json:"guard,omitempty"`
	US       int64       `json:"us"`
	Guards   []guardView `json:"guards,omitempty"`
	Findings int         `json:"findings"`
	Redacted int         `json:"redacted,omitempty"`
}

type guardView struct {
	Guard  string `json:"guard"`
	Action string `json:"action"`
	US     int64  `json:"us"`
}

func viewOf(d *core.Decision) *decisionView {
	if d == nil {
		return nil
	}
	v := &decisionView{Stage: string(d.Stage), Action: string(d.Action), US: d.Duration.Microseconds(),
		Findings: len(d.Findings), Redacted: len(d.Mutations)}
	if f, ok := d.TopFinding(); ok {
		v.Category, v.Severity, v.Score, v.Message, v.Guard = f.Category, f.SeverityName, f.Score, f.Message, f.Guard
	}
	for _, r := range d.Runs {
		if r.Skipped {
			continue
		}
		a := string(r.Action)
		if a == "" {
			a = "allow"
		}
		v.Guards = append(v.Guards, guardView{Guard: r.Guard, Action: a, US: r.Duration.Microseconds()})
	}
	return v
}

func semanticView(o *judge.Outcome) map[string]any {
	if o == nil {
		return nil
	}
	m := map[string]any{"ran": o.Ran, "reason": o.Reason, "unsafe": o.Unsafe, "enforced": o.Enforced,
		"ms": o.Duration.Milliseconds(), "disagreement": o.Disagreement}
	for _, v := range o.Verdicts {
		if v.Unsafe || m["classifier"] == nil {
			m["classifier"], m["score"], m["category"] = v.Classifier, v.Score, v.Category
		}
	}
	return m
}

// preview is the masked user text, shortened. It is what the provider saw,
// so it carries vault placeholders rather than personal data.
func preview(msgs []core.Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == core.RoleUser {
			t := strings.Join(strings.Fields(msgs[i].Content), " ")
			if r := []rune(t); len(r) > 140 {
				t = string(r[:139]) + "…"
			}
			return t
		}
	}
	return ""
}

// attachmentView is what the console shows of an attachment: its kind and
// how much of it the guards read. Never its name, bytes or text.
type attachmentView struct {
	Type     string   `json:"type"`
	Format   string   `json:"format,omitempty"`
	Coverage string   `json:"coverage,omitempty"`
	Methods  []string `json:"methods,omitempty"`
	Findings int      `json:"findings,omitempty"`
	MS       int64    `json:"ms,omitempty"`
}

func attachmentsOf(msgs []core.Message, results []core.ToolResult) []attachmentView {
	var out []attachmentView
	add := func(p core.Part) {
		v := attachmentView{Type: string(p.Type), Format: p.MIME}
		if e := p.Extraction; e != nil {
			v.Coverage, v.Methods, v.Findings, v.MS = string(e.Coverage), e.Methods, len(e.Findings), e.DurationMS
		}
		out = append(out, v)
	}
	for _, m := range msgs {
		for _, p := range m.Parts {
			add(p)
		}
	}
	for _, r := range results {
		for _, p := range r.Parts {
			add(p)
		}
	}
	return out
}

func (s *Server) publishDecision(kind string, tx *core.Transaction, d *core.Decision) {
	if s.bus == nil {
		return
	}
	ev := map[string]any{"id": tx.ID, "tenant": tx.Tenant, "preview": preview(tx.Messages), "decision": viewOf(d)}
	if a := attachmentsOf(tx.Messages, tx.ToolResults); len(a) > 0 {
		ev["attachments"] = a
	}
	s.bus.Publish(kind, ev)
}

// publishRequest emits one event per proxied request: the whole journey,
// stage by stage, so the console can animate it end to end.
func (s *Server) publishRequest(id string, req *chatRequest, masked []core.Message, meta *guardrailsMeta, outcome, route, provider string, cost float64) {
	if s.bus == nil {
		return
	}
	s.bus.Publish("request", map[string]any{
		"id": id, "tenant": req.Tenant, "model": req.Model, "route": route, "provider": provider,
		"preview": preview(masked), "outcome": outcome, "cache": meta.Cache,
		"inbound": viewOf(meta.Inbound), "outbound": viewOf(meta.Outbound),
		"semantic": semanticView(meta.SemanticInbound), "semantic_out": semanticView(meta.SemanticOutbound),
		"timing": meta.Timing, "redactions": meta.Redactions, "restored": meta.Restored,
		"fallback": meta.Fallback, "attempts": meta.Attempts, "cost_usd": cost + meta.JudgeCostUSD,
		"trace_id": meta.TraceID, "attachments": attachmentsOf(masked, nil),
	})
}

func (s *Server) handleShowcase(w http.ResponseWriter, r *http.Request) {
	page, err := assets.ReadFile("assets/showcase.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "showcase unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
	// The page is embedded in the binary, so a rebuilt image is a new page:
	// make the browser revalidate instead of showing the one it kept.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}
