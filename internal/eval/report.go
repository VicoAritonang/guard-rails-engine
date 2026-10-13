package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// WriteJSON emits the machine-readable report.
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteMarkdown renders the human-readable report.
//
// Ordering is deliberate: the headline safety numbers first, then per-family
// detail, then latency, then failures. Someone skimming a CI artefact should be
// able to answer "did this get worse" from the first ten lines.
func WriteMarkdown(w io.Writer, rep *Report, sweeps []*Sweep, evasion *EvasionReport) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# Guardrail Evaluation Report\n\n")
	fmt.Fprintf(b, "| | |\n|---|---|\n")
	fmt.Fprintf(b, "| Dataset | `%s` (%d cases) |\n", rep.Dataset, rep.Cases)
	fmt.Fprintf(b, "| Policy | `%s` (%s) |\n", rep.PolicyName, rep.Policy)
	fmt.Fprintf(b, "| Generated | %s |\n", rep.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(b, "\n")

	fmt.Fprintf(b, "## Headline\n\n")
	fmt.Fprintf(b, "| Metric | Value | Reading |\n|---|---:|---|\n")
	fmt.Fprintf(b, "| Macro F1 | %s | detection quality averaged across families |\n", fmtPct(rep.MacroF1))
	fmt.Fprintf(b, "| Benign false-positive rate | %s | share of clean traffic disrupted |\n", fmtPct(rep.BenignFPR))
	if rep.ActionScored > 0 {
		fmt.Fprintf(b, "| Enforcement accuracy | %s | correct action on %d pinned cases |\n",
			fmtPct(rep.ActionAccuracy), rep.ActionScored)
	}
	if rep.Degraded > 0 {
		fmt.Fprintf(b, "| Degraded decisions | %d | a guard failed open; coverage was reduced |\n", rep.Degraded)
	}
	if rep.Errors > 0 {
		fmt.Fprintf(b, "| Harness errors | %d | cases that did not run |\n", rep.Errors)
	}
	fmt.Fprintf(b, "\n")

	// Per-family detection.
	fmt.Fprintf(b, "## Detection by family\n\n")
	fmt.Fprintf(b, "| Family | Precision | Recall | F1 | FPR | TP | FP | FN | TN |\n")
	fmt.Fprintf(b, "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, f := range sortedFamilies(rep.ByFamily) {
		c := rep.ByFamily[f]
		fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s | %d | %d | %d | %d |\n",
			f, fmtPct(c.Precision()), fmtPct(c.Recall()), fmtPct(c.F1()), fmtPct(c.FPR()),
			c.TP, c.FP, c.FN, c.TN)
	}
	fmt.Fprintf(b, "\n")

	// Latency against budget.
	if len(rep.LatencyByStage) > 0 {
		fmt.Fprintf(b, "## Latency\n\n")
		fmt.Fprintf(b, "| Stage | n | mean | p50 | p95 | p99 | max | budget | over budget |\n")
		fmt.Fprintf(b, "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, stage := range []string{"inbound", "runtime", "outbound"} {
			l, ok := rep.LatencyByStage[stage]
			if !ok {
				continue
			}
			fmt.Fprintf(b, "| %s | %d | %s | %s | %s | %s | %s | %s | %d |\n",
				stage, l.Count, dur(l.Mean), dur(l.P50), dur(l.P95), dur(l.P99),
				dur(l.Max), dur(l.Budget), l.OverBudget)
		}
		fmt.Fprintf(b, "\n")
	}

	// Evasion resistance.
	if evasion != nil && evasion.Total > 0 {
		fmt.Fprintf(b, "## Evasion resistance (red team)\n\n")
		fmt.Fprintf(b, "%d adversarial variants generated from the labelled attacks; "+
			"each preserves the attack's meaning while changing its bytes.\n\n", evasion.Total)
		fmt.Fprintf(b, "**Overall catch rate: %s** (%d caught, %d evaded)\n\n",
			fmtPct(float64(evasion.Caught)/float64(evasion.Total)), evasion.Caught, evasion.Evaded)
		fmt.Fprintf(b, "| Technique | Variants | Caught | Catch rate | First gap |\n")
		fmt.Fprintf(b, "|---|---:|---:|---:|---|\n")
		names := make([]string, 0, len(evasion.ByMutator))
		for n := range evasion.ByMutator {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			return evasion.ByMutator[names[i]].Rate < evasion.ByMutator[names[j]].Rate
		})
		for _, n := range names {
			m := evasion.ByMutator[n]
			gap := m.SampleGap
			if gap == "" {
				gap = "-"
			}
			fmt.Fprintf(b, "| `%s` | %d | %d | %s | `%s` |\n", n, m.Total, m.Caught, fmtPct(m.Rate), gap)
		}
		fmt.Fprintf(b, "\n")
	}

	// Threshold sweeps.
	for _, sw := range sweeps {
		if sw == nil || len(sw.Points) == 0 {
			continue
		}
		fmt.Fprintf(b, "## Threshold sweep: `%s` (family `%s`)\n\n", sw.Guard, sw.Family)
		fmt.Fprintf(b, "Current threshold **%.2f**; best F1 on this corpus at **%.2f**.\n\n",
			sw.Current, sw.Suggested)
		fmt.Fprintf(b, "```\n%s\n```\n\n", asciiPRCurve(sw))
		fmt.Fprintf(b, "| Threshold | Precision | Recall | F1 | Benign FPR |\n|---:|---:|---:|---:|---:|\n")
		for _, p := range sw.Points {
			marker := ""
			if math.Abs(p.Threshold-sw.Current) < 1e-9 {
				marker = " ← current"
			}
			if math.Abs(p.Threshold-sw.Suggested) < 1e-9 {
				marker += " ← best F1"
			}
			fmt.Fprintf(b, "| %.2f%s | %s | %s | %s | %s |\n",
				p.Threshold, marker, fmtPct(p.Precision), fmtPct(p.Recall),
				fmtPct(p.F1), fmtPct(p.BenignFPR))
		}
		fmt.Fprintf(b, "\n> F1 weights a missed attack and a blocked customer equally. "+
			"If your costs differ, pick the point that matches them, not the F1 peak.\n")

		// A flat precision curve does not mean the detector is perfect; it
		// almost always means the corpus contains no hard negatives -- no
		// benign text close enough to an attack to be caught at a low
		// threshold. Reporting "best F1 at 0.05" without saying so would
		// invite an operator to lower their threshold on the strength of a
		// dataset artefact, which is exactly the mistake a sweep exists to
		// prevent.
		if lo, hi := precisionRange(sw); hi-lo < 0.02 {
			fmt.Fprintf(b, ">\n> **Read this curve with care.** Precision is flat at %s across the "+
				"whole range, which means this corpus contains no benign prompts near enough to an "+
				"attack to be caught at a low threshold. The suggested threshold above is therefore an "+
				"artefact of the dataset, not a recommendation: it says the corpus is too easy, not "+
				"that the threshold should be lowered. Re-run the sweep against a sample of your own "+
				"production traffic before changing it.\n\n", fmtPct(hi))
		} else {
			fmt.Fprintf(b, "\n")
		}
	}

	// Failures, so the report is actionable rather than merely informative.
	writeFailures(b, rep)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeFailures(b *strings.Builder, rep *Report) {
	var missed, spurious, wrongAction []CaseResult
	for _, r := range rep.Results {
		if r.Error != "" {
			continue
		}
		if len(r.Missed) > 0 {
			missed = append(missed, r)
		}
		if len(r.Spurious) > 0 {
			spurious = append(spurious, r)
		}
		if r.Expect != "" && r.Action != r.Expect {
			wrongAction = append(wrongAction, r)
		}
	}
	if len(missed)+len(spurious)+len(wrongAction) == 0 {
		fmt.Fprintf(b, "## Failures\n\nNone. Every case matched its labels and expected action.\n")
		return
	}

	fmt.Fprintf(b, "## Failures\n\n")
	if len(missed) > 0 {
		fmt.Fprintf(b, "### False negatives (%d)\n\nAttacks the engine did not detect.\n\n", len(missed))
		fmt.Fprintf(b, "| Case | Stage | Expected | Detected | Variant |\n|---|---|---|---|---|\n")
		for _, r := range capResults(missed, 40) {
			fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s |\n",
				r.ID, r.Stage, join(r.Missed), joinOrDash(r.Detected), orDash(r.Variant))
		}
		fmt.Fprintf(b, "\n")
	}
	if len(spurious) > 0 {
		fmt.Fprintf(b, "### False positives (%d)\n\nDetections with no matching label. "+
			"These are the findings that erode trust fastest.\n\n", len(spurious))
		fmt.Fprintf(b, "| Case | Stage | Spurious | Labelled | Action |\n|---|---|---|---|---|\n")
		for _, r := range capResults(spurious, 40) {
			fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s |\n",
				r.ID, r.Stage, join(r.Spurious), joinOrDash(r.Expected), r.Action)
		}
		fmt.Fprintf(b, "\n")
	}
	if len(wrongAction) > 0 {
		fmt.Fprintf(b, "### Enforcement mismatches (%d)\n\n"+
			"Detection was right but the policy mapped it to the wrong action.\n\n", len(wrongAction))
		fmt.Fprintf(b, "| Case | Expected | Got |\n|---|---|---|\n")
		for _, r := range capResults(wrongAction, 40) {
			fmt.Fprintf(b, "| `%s` | %s | %s |\n", r.ID, r.Expect, r.Action)
		}
		fmt.Fprintf(b, "\n")
	}
}

// asciiPRCurve draws the precision/recall trade as a small chart, so the shape
// is visible in a terminal or a CI log without opening the HTML report.
func asciiPRCurve(sw *Sweep) string {
	const height = 10
	var b strings.Builder
	b.WriteString("precision (P) and recall (R) vs threshold\n")
	for row := height; row >= 0; row-- {
		level := float64(row) / height
		fmt.Fprintf(&b, "%3.0f%% |", level*100)
		for _, p := range sw.Points {
			ch := ' '
			switch {
			case near(p.Precision, level, 1.0/height) && near(p.Recall, level, 1.0/height):
				ch = '*'
			case near(p.Precision, level, 1.0/height):
				ch = 'P'
			case near(p.Recall, level, 1.0/height):
				ch = 'R'
			}
			b.WriteRune(ch)
			b.WriteRune(' ')
		}
		b.WriteString("\n")
	}
	b.WriteString("     +")
	b.WriteString(strings.Repeat("--", len(sw.Points)))
	b.WriteString("\n      ")
	for _, p := range sw.Points {
		fmt.Fprintf(&b, "%-2.0f", p.Threshold*100)
	}
	b.WriteString("\n      threshold (%)")
	return b.String()
}

func near(v, level, tol float64) bool { return math.Abs(v-level) < tol/2 }

func sortedFamilies(m map[string]Confusion) []string {
	out := make([]string, 0, len(m))
	for f := range m {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func fmtPct(f float64) string {
	if math.IsNaN(f) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", f*100)
}

func dur(d time.Duration) string {
	switch {
	case d == 0:
		return "-"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fus", float64(d.Nanoseconds())/1000)
	default:
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
}

func join(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return "`" + strings.Join(s, "`, `") + "`"
}

func joinOrDash(s []string) string { return join(s) }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func capResults(in []CaseResult, n int) []CaseResult {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// precisionRange returns the minimum and maximum precision across a sweep,
// used to detect a curve that carries no information about the trade-off.
func precisionRange(sw *Sweep) (lo, hi float64) {
	lo, hi = 1, 0
	for _, p := range sw.Points {
		if p.TP+p.FP == 0 {
			continue // precision undefined at this point
		}
		lo = math.Min(lo, p.Precision)
		hi = math.Max(hi, p.Precision)
	}
	if hi < lo {
		return 0, 0
	}
	return lo, hi
}
