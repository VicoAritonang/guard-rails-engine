package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
)

func runScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	stage := fs.String("stage", "inbound", "inbound | runtime | outbound")
	text := fs.String("text", "", "payload to scan")
	file := fs.String("file", "", "read the payload from a file (- for stdin)")
	system := fs.String("system", "", "system prompt (used by the leak guard on outbound)")
	model := fs.String("model", "claude-opus-5", "model name, used for cost estimation")
	policyPath := fs.String("policy", "", "policy YAML")
	strict := fs.Bool("strict", false, "use the built-in strict policy")
	asJSON := fs.Bool("json", false, "emit the raw decision as JSON")
	showAll := fs.Bool("verbose", false, "list every guard that ran, not just the ones that fired")

	if err := fs.Parse(args); err != nil {
		return err
	}

	payload, err := readPayload(*text, *file)
	if err != nil {
		return err
	}
	if strings.TrimSpace(payload) == "" {
		return fmt.Errorf("scan: provide --text or --file")
	}

	st := core.Stage(*stage)
	if !st.Valid() {
		return fmt.Errorf("scan: invalid stage %q", *stage)
	}

	pol, err := loadPolicy(*policyPath, *strict)
	if err != nil {
		return err
	}
	secret := evalSecret()
	engine, err := guards.Build(pol, guards.Deps{Secret: secret})
	if err != nil {
		return err
	}
	pipe, err := engine.Pipeline(st)
	if err != nil {
		return err
	}

	tx := &core.Transaction{
		ID:        "scan-" + time.Now().UTC().Format("150405.000"),
		Stage:     st,
		Model:     *model,
		System:    *system,
		Vault:     core.NewVault(secret),
		StartedAt: time.Now(),
	}
	switch st {
	case core.StageInbound:
		tx.Messages = []core.Message{{Role: core.RoleUser, Content: payload}}
	case core.StageOutbound:
		tx.Completion = payload
	case core.StageRuntime:
		// A runtime payload is a JSON tool call; fall back to treating the
		// whole string as the raw arguments so ad-hoc probing still works.
		var call core.ToolCall
		if err := json.Unmarshal([]byte(payload), &call); err != nil || call.Name == "" {
			call = core.ToolCall{Name: "unknown", Raw: payload}
		} else if call.Raw == "" {
			call.Raw = payload
		}
		tx.ToolCalls = []core.ToolCall{call}
		tx.Step = 1
	}

	before := snapshot(tx, st)
	dec, _ := pipe.Execute(ctx, tx)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(dec)
	}
	printDecision(os.Stdout, dec, before, snapshot(tx, st), *showAll, pol)
	if dec.Blocked() {
		os.Exit(4) // a block is a valid outcome, not a tool error
	}
	return nil
}

func snapshot(tx *core.Transaction, st core.Stage) string {
	switch st {
	case core.StageOutbound:
		return tx.Completion
	case core.StageRuntime:
		if len(tx.ToolCalls) > 0 {
			return tx.ToolCalls[0].Raw
		}
	default:
		if len(tx.Messages) > 0 {
			return tx.Messages[0].Content
		}
	}
	return ""
}

// ANSI colours, disabled when the output is not a terminal or NO_COLOR is set.
var (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		colorReset, colorBold, colorDim = "", "", ""
		colorRed, colorYellow, colorGreen, colorCyan = "", "", "", ""
	}
}

func printDecision(w io.Writer, d *core.Decision, before, after string, showAll bool, pol *config.Policy) {
	verdict, colour := string(d.Action), colorGreen
	switch d.Action {
	case core.ActionBlock:
		colour = colorRed
	case core.ActionRedact:
		colour = colorYellow
	case core.ActionFlag:
		colour = colorCyan
	}

	fmt.Fprintf(w, "\n%s%s%s%s  stage=%s  policy=%s  %s%s%s\n\n",
		colorBold, colour, strings.ToUpper(verdict), colorReset,
		d.Stage, pol.Name, colorDim, d.Duration.Round(time.Microsecond), colorReset)

	if len(d.Findings) == 0 {
		fmt.Fprintf(w, "  no findings\n")
	}
	for _, f := range d.Findings {
		sevColour := colorCyan
		switch f.Severity {
		case core.SeverityCritical, core.SeverityHigh:
			sevColour = colorRed
		case core.SeverityMedium:
			sevColour = colorYellow
		}
		fmt.Fprintf(w, "  %s%-8s%s %s%-28s%s score=%.2f  %s\n",
			sevColour, f.SeverityName, colorReset,
			colorBold, f.Category, colorReset, f.Score, f.Message)
		for _, s := range f.Spans {
			if s.Excerpt != "" {
				fmt.Fprintf(w, "           %s%s[%d:%d] %q%s\n",
					colorDim, s.Field, s.Start, s.End, s.Excerpt, colorReset)
			}
		}
		if len(f.Meta) > 0 {
			fmt.Fprintf(w, "           %s%s%s\n", colorDim, formatMeta(f.Meta), colorReset)
		}
	}

	if before != after {
		fmt.Fprintf(w, "\n  %spayload rewritten:%s\n", colorBold, colorReset)
		fmt.Fprintf(w, "    %s- %s%s\n", colorRed, truncateLine(before, 160), colorReset)
		fmt.Fprintf(w, "    %s+ %s%s\n", colorGreen, truncateLine(after, 160), colorReset)
	}

	if showAll {
		fmt.Fprintf(w, "\n  %sguards:%s\n", colorBold, colorReset)
		for _, r := range d.Runs {
			status := "ok"
			switch {
			case r.Skipped:
				status = "disabled"
			case r.TimedOut:
				status = "TIMEOUT"
			case r.Error != "":
				status = "ERROR"
			}
			fmt.Fprintf(w, "    %s%-16s %-9s %8s  findings=%d%s\n",
				colorDim, r.Guard, status, r.Duration.Round(time.Microsecond), r.Findings, colorReset)
		}
	}

	if d.Degraded {
		fmt.Fprintf(w, "\n  %sWARNING: a guard failed open; detection coverage was reduced%s\n",
			colorYellow, colorReset)
	}
	fmt.Fprintln(w)
}

func formatMeta(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func truncateLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func readPayload(text, file string) (string, error) {
	if text != "" {
		return text, nil
	}
	if file == "" {
		return "", nil
	}
	if file == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(file)
	return string(b), err
}

func jsonEncoder(w io.Writer) *json.Encoder { return json.NewEncoder(w) }
