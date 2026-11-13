package experiment

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/providers"
)

// PIICase is a task that requires the model to reproduce a personal value.
type PIICase struct {
	ID     string   `json:"id"`
	Values []string `json:"values"`
	Text   string   `json:"text"`
}

// PIIOptions configures the redaction round-trip experiment.
type PIIOptions struct {
	Dataset   string
	Models    []string
	Workers   int
	MaxTokens int
}

type piiTrial struct {
	Case  string `json:"case"`
	Model string `json:"model"`

	// Exposure: how many of the case's values reached the provider verbatim.
	ValuesTotal       int    `json:"values_total"`
	ExposedGuarded    int    `json:"exposed_guarded"`
	PlaceholdersSent  int    `json:"placeholders_sent"`
	PlaceholdersKept  int    `json:"placeholders_kept"`
	RawTaskSuccess    bool   `json:"raw_task_success"`
	GuardedSuccess    bool   `json:"guarded_task_success"`
	GuardedRefused    bool   `json:"guarded_refused"`
	RawRefused        bool   `json:"raw_refused"`
	Error             string `json:"error,omitempty"`
	GuardedOutPreview string `json:"guarded_output_preview"`
}

var placeholderRe = regexp.MustCompile(`\[\[PII:[A-Z_]+:[0-9a-f]+\]\]`)

func normValue(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r == ' ' || r == '-' || r == '(' || r == ')' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func containsValue(text, v string) bool {
	return strings.Contains(normValue(text), normValue(v))
}

// RunPII measures what redaction costs in task success, per model.
//
// Masking is free for security and not free for utility: the model now has
// to carry an opaque token through its answer. Whether it does depends on the
// model, and nobody knows which models do until they measure it.
func RunPII(ctx context.Context, env *Env, opts PIIOptions) (*Result, error) {
	cases, err := ReadJSONL[PIICase](opts.Dataset)
	if err != nil {
		return nil, err
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = 300
	}
	system := "You are a helpful assistant for an e-commerce operations team. Follow the user's formatting instructions exactly. " +
		"Some values may appear as tokens like [[PII:EMAIL:abc123]]; treat each token as the real value and copy it exactly where the value belongs."

	type job struct{ m, c int }
	var jobs []job
	for m := range opts.Models {
		for c := range cases {
			jobs = append(jobs, job{m, c})
		}
	}
	trials := make([]piiTrial, len(jobs))
	env.Logf("pii: %d tasks x %d models", len(cases), len(opts.Models))
	ParallelDo(ctx, len(jobs), opts.Workers, func(ctx context.Context, j int) {
		c, model := cases[jobs[j].c], opts.Models[jobs[j].m]
		t := piiTrial{Case: c.ID, Model: model, ValuesTotal: len(c.Values)}

		raw, err := env.LLM.Complete(ctx, providers.Request{Model: model, System: system,
			Messages: []core.Message{{Role: core.RoleUser, Content: c.Text}}, MaxTokens: opts.MaxTokens})
		if err != nil {
			t.Error = err.Error()
			trials[j] = t
			return
		}
		t.RawRefused = providers.LooksLikeRefusal(raw.Text)
		t.RawTaskSuccess = allValues(raw.Text, c.Values)

		vault := core.NewVault(env.Secret)
		in := &core.Transaction{ID: c.ID, Stage: core.StageInbound, System: system,
			Messages: []core.Message{{Role: core.RoleUser, Content: c.Text}}, Vault: vault, StartedAt: time.Now()}
		dec, _ := env.Engine.Inbound.Execute(ctx, in)
		if dec.Blocked() {
			t.Error = "blocked inbound: " + dec.Reason()
			trials[j] = t
			return
		}
		sent := in.Messages[0].Content
		for _, v := range c.Values {
			if containsValue(sent, v) {
				t.ExposedGuarded++
			}
		}
		issued := placeholderRe.FindAllString(sent, -1)
		t.PlaceholdersSent = len(issued)

		g, err := env.LLM.Complete(ctx, providers.Request{Model: model, System: system,
			Messages: in.Messages, MaxTokens: opts.MaxTokens})
		if err != nil {
			t.Error = err.Error()
			trials[j] = t
			return
		}
		for _, p := range issued {
			if strings.Contains(g.Text, p) {
				t.PlaceholdersKept++
			}
		}
		out := &core.Transaction{ID: c.ID, Stage: core.StageOutbound, System: system, Completion: g.Text, Vault: vault, StartedAt: time.Now()}
		_, _ = env.Engine.Outbound.Execute(ctx, out)
		t.GuardedSuccess = allValues(out.Completion, c.Values)
		t.GuardedRefused = providers.LooksLikeRefusal(g.Text)
		t.GuardedOutPreview = trunc(strings.ReplaceAll(out.Completion, "\n", " "), 160)
		trials[j] = t
	})

	res := &Result{}
	for _, t := range trials {
		res.Trials = append(res.Trials, t)
	}
	tbl := Table{Title: "Redaction round-trip by model",
		Columns: []string{"Model", "Tasks", "Task success, raw", "Task success, redacted", "Placeholders preserved", "Refusals, raw", "Refusals, redacted", "Values exposed to provider (redacted)", "Errors"}}
	chart := Chart{Title: "Task success with and without redaction", Format: "pct", Series: []string{"Raw prompt (PII sent to provider)", "Redacted + restored"},
		Note: "A task succeeds when every personal value it needs appears correctly in the final answer the user receives."}
	chart.Values = [][]float64{{}, {}}
	var totalVals, exposed, totalTasks, rawOK, grdOK int
	for _, m := range opts.Models {
		var n, ro, go_, sent, kept, rr, gr, exp, vals, errs int
		for _, t := range trials {
			if t.Model != m {
				continue
			}
			if t.Error != "" {
				errs++
				continue
			}
			n++
			vals += t.ValuesTotal
			exp += t.ExposedGuarded
			sent += t.PlaceholdersSent
			kept += t.PlaceholdersKept
			if t.RawTaskSuccess {
				ro++
			}
			if t.GuardedSuccess {
				go_++
			}
			if t.RawRefused {
				rr++
			}
			if t.GuardedRefused {
				gr++
			}
		}
		totalVals += vals
		exposed += exp
		totalTasks += n
		rawOK += ro
		grdOK += go_
		tbl.Rows = append(tbl.Rows, []string{m, fmt.Sprintf("%d", n), Pct(Ratio(ro, n)), Pct(Ratio(go_, n)), Pct(Ratio(kept, sent)),
			fmt.Sprintf("%d", rr), fmt.Sprintf("%d", gr), fmt.Sprintf("%d/%d", exp, vals), fmt.Sprintf("%d", errs)})
		chart.Categories = append(chart.Categories, m)
		chart.Values[0] = append(chart.Values[0], nanTo0(Ratio(ro, n)))
		chart.Values[1] = append(chart.Values[1], nanTo0(Ratio(go_, n)))
	}

	// Which value kinds slip past detection?
	missTbl := Table{Title: "Values that reached the provider despite redaction", Columns: []string{"Case", "Value kind", "Prompt"}, Rows: [][]string{}}
	seen := map[string]bool{}
	for _, t := range trials {
		if t.ExposedGuarded > 0 && !seen[t.Case] {
			seen[t.Case] = true
			for _, c := range cases {
				if c.ID == t.Case {
					missTbl.Rows = append(missTbl.Rows, []string{c.ID, valueKind(c.Values[0]), trunc(c.Text, 90)})
				}
			}
		}
	}

	res.Headline = []Metric{
		{"PII exposed to providers, no gateway", "100%", fmt.Sprintf("%d values per model sent verbatim", totalVals/max(len(opts.Models), 1))},
		{"PII exposed with redaction", Pct(Ratio(exposed, totalVals)), fmt.Sprintf("%d/%d values", exposed, totalVals)},
		{"Task success cost of redaction", fmt.Sprintf("%+.1f pts", (nanTo0(Ratio(grdOK, totalTasks))-nanTo0(Ratio(rawOK, totalTasks)))*100), "redacted minus raw, all models"},
	}
	coverage := fmt.Sprintf("Redaction kept all %d personal values in this set away from the providers.", totalVals)
	if exposed > 0 {
		coverage = fmt.Sprintf("Redaction kept %d of %d personal values away from the providers; the rest are formats the detectors do not recognise (listed below); detection coverage, not the vault, is the limit.", totalVals-exposed, totalVals)
	}
	res.Findings = []string{
		coverage,
		fmt.Sprintf("Task success went from %s with raw prompts to %s with redact-and-restore across all models.", Pct(Ratio(rawOK, totalTasks)), Pct(Ratio(grdOK, totalTasks))),
		"Placeholder preservation is a model property: models that copy the opaque token verbatim lose nothing to redaction; models that rewrite, drop or 'helpfully' replace it with an invented value lose the task. That makes it a model-selection criterion for any PII-sensitive workload.",
	}
	res.Tables = []Table{tbl}
	if len(missTbl.Rows) > 0 {
		res.Tables = append(res.Tables, missTbl)
	}
	res.Charts = []Chart{chart}
	res.Notes = []string{
		"Values are compared after removing spaces, hyphens and brackets, so a phone number reformatted by the model still counts as correct.",
		"The system prompt tells the model what a placeholder is. Without that line preservation drops further; the instruction is part of a correct deployment.",
		"Exposure is measured on the payload actually sent upstream after the inbound stage.",
	}
	return res, nil
}

func allValues(text string, vals []string) bool {
	for _, v := range vals {
		if !containsValue(text, v) {
			return false
		}
	}
	return true
}

func valueKind(v string) string {
	switch {
	case strings.Contains(v, "@"):
		return "email"
	case strings.HasPrefix(v, "+"):
		return "phone"
	case len(v) > 15 && strings.ContainsAny(v[:2], "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
		return "iban"
	case strings.Count(v, " ") == 3:
		return "card"
	default:
		return "id number"
	}
}
