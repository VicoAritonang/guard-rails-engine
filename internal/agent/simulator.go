package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// Simulator is an Executor that produces plausible results without touching
// anything real.
//
// It exists so the control plane can be exercised end to end -- including the
// attack paths -- without a mail server, a bank, or a production database. Its
// job is to be honest about what a real executor would return: the right
// origin, the right sensitivity, and content the downstream rails will treat
// exactly as they would treat the real thing.
type Simulator struct {
	// Fixtures overrides the content a read tool returns, keyed by tool name
	// or by "tool:argument". This is how a scenario injects a poisoned web
	// page: the guardrails cannot tell the difference, which is the point.
	Fixtures map[string]string
}

// NewSimulator builds a simulator with the given fixtures.
func NewSimulator(fixtures map[string]string) *Simulator {
	return &Simulator{Fixtures: fixtures}
}

// Preview describes the effect a call would have.
//
// The wording matters more than it looks like it should: this string is what a
// human is shown before they approve an irreversible action, and an approval
// UI that says "approve transfer_funds?" collects a signature on a tool name
// rather than on an action. It names the destination and the amount, because
// those are the fields an injected instruction would have changed.
func (s *Simulator) Preview(_ context.Context, t *Tool, args map[string]any) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s]\n", t.Name, t.Tier())
	fmt.Fprintf(&b, "  effect:  %s\n", t.Description)
	if t.Undo != "" {
		fmt.Fprintf(&b, "  undo:    %s\n", t.Undo)
	} else if t.Reversibility == RevIrreversible {
		fmt.Fprintf(&b, "  undo:    NONE -- this cannot be taken back\n")
	}
	for _, p := range t.Params {
		v, ok := args[p.Name]
		if !ok {
			continue
		}
		label := p.Name
		switch {
		case p.Destination:
			label += " (destination)"
		case p.Amount:
			label += " (amount)"
		}
		fmt.Fprintf(&b, "  %-22s %s\n", label+":", truncate(render(v), 200))
	}
	return b.String(), nil
}

// Execute produces a simulated result.
func (s *Simulator) Execute(_ context.Context, t *Tool, args map[string]any) (core.ToolResult, error) {
	res := core.ToolResult{
		Name:      t.Name,
		Origin:    originFor(t),
		Sensitive: t.Exposure.Has(ExposurePrivate),
	}

	if content, ok := s.fixture(t, args); ok {
		res.Content = content
		return res, nil
	}

	switch t.Reversibility {
	case RevNone:
		res.Content = s.readResult(t, args)
	default:
		// Effect tools return a receipt, not data. A tool that echoes its own
		// arguments back into the context window hands an injected instruction
		// a second chance to be read.
		res.Content = fmt.Sprintf("%s completed (simulated). %s", t.Name, effectSummary(t, args))
	}
	return res, nil
}

func (s *Simulator) fixture(t *Tool, args map[string]any) (string, bool) {
	if len(s.Fixtures) == 0 {
		return "", false
	}
	if v, ok := s.Fixtures[t.Name]; ok {
		return v, true
	}
	for _, p := range t.Params {
		for _, val := range stringValues(args[p.Name]) {
			if v, ok := s.Fixtures[t.Name+":"+val]; ok {
				return v, true
			}
		}
	}
	return "", false
}

func (s *Simulator) readResult(t *Tool, args map[string]any) string {
	switch t.Name {
	case "calculator":
		return fmt.Sprintf("expression %q evaluates to 42 (simulated)", render(args["expression"]))
	case "current_time":
		return "2026-08-29T09:15:00Z (simulated)"
	case "web_search":
		return fmt.Sprintf("3 results for %q (simulated; no page content fetched)",
			truncate(render(args["query"]), 80))
	case "web_fetch":
		return fmt.Sprintf("Contents of %s (simulated page with no instructions in it).",
			truncate(render(args["url"]), 120))
	case "get_customer":
		return `{"customer_id":"cus_8812","name":"A. Nakamura",` +
			`"email":"a.nakamura@example.com","plan":"enterprise","mrr_usd":4200}`
	case "db_query":
		return `[{"order_id":"ord_5591","total_usd":128.40,"status":"shipped"}]`
	case "read_email":
		return "Subject: Invoice question\nFrom: billing@vendor.example\n\n" +
			"Could you confirm the PO number on invoice 88213?"
	case "read_file":
		return fmt.Sprintf("(simulated contents of %s)", render(args["path"]))
	case "list_directory":
		return "notes.md\nreport.pdf\nbudget.xlsx"
	case "kb_search":
		return "KB-114: Refunds are issued to the original payment method within 5 business days."
	case "calendar_read":
		return `[{"title":"Board review","start":"2026-09-02T14:00:00Z","attendees":3}]`
	default:
		return fmt.Sprintf("(simulated result from %s)", t.Name)
	}
}

// effectSummary names what happened, without echoing the payload.
func effectSummary(t *Tool, args map[string]any) string {
	var parts []string
	if p, ok := t.Destination(); ok {
		if vals := stringValues(args[p.Name]); len(vals) > 0 {
			parts = append(parts, fmt.Sprintf("destination=%s",
				redactDestination(ParseDestination(vals[0]))))
		}
	}
	for _, p := range t.Params {
		if p.Amount {
			if v, ok := toFloat(args[p.Name]); ok {
				parts = append(parts, fmt.Sprintf("%s=%.2f", p.Name, v))
			}
		}
	}
	if len(parts) == 0 {
		return "no destination or amount recorded."
	}
	sort.Strings(parts)
	return strings.Join(parts, " ") + "."
}

func originFor(t *Tool) core.Origin {
	if t.Domain == "web" {
		return core.OriginWeb
	}
	return core.OriginTool
}

func render(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return fmt.Sprint(v)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
