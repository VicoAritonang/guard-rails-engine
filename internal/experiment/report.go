package experiment

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Result is one experiment run, written to disk in four forms: result.json
// (machine-readable), trials.jsonl (one row per trial, for re-analysis),
// report.md (reviewable in a PR) and report.html (charts).
type Result struct {
	Experiment string         `json:"experiment"`
	Title      string         `json:"title"`
	Question   string         `json:"question"`
	RunID      string         `json:"run_id"`
	Version    string         `json:"version"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Config     map[string]any `json:"config"`

	Headline []Metric `json:"headline"`
	Findings []string `json:"findings"`
	Tables   []Table  `json:"tables"`
	Charts   []Chart  `json:"charts"`
	Notes    []string `json:"notes,omitempty"`

	Usage Usage `json:"usage"`

	Trials []any `json:"-"`
}

// Usage is what the run cost to produce.
type Usage struct {
	UpstreamCalls int     `json:"upstream_calls"`
	CacheReplays  int     `json:"cache_replays"`
	CostUSD       float64 `json:"cost_usd"`
}

// Metric is a headline number.
type Metric struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Hint  string `json:"hint,omitempty"`
}

// Table is a rendered table.
type Table struct {
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Note    string     `json:"note,omitempty"`
}

// Chart is a horizontal (grouped) bar chart: Values[series][category].
type Chart struct {
	Title      string      `json:"title"`
	Format     string      `json:"format"` // pct | ms | usd | num
	Series     []string    `json:"series"`
	Categories []string    `json:"categories"`
	Values     [][]float64 `json:"values"`
	Note       string      `json:"note,omitempty"`
	// LowerIsBetter is stated in the subtitle so a reader knows which way is good.
	LowerIsBetter bool `json:"lower_is_better,omitempty"`
}

// LedgerEntry is one line of experiments/runs/index.jsonl.
type LedgerEntry struct {
	RunID      string    `json:"run_id"`
	Experiment string    `json:"experiment"`
	Title      string    `json:"title"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	DurationS  float64   `json:"duration_s"`
	Headline   []Metric  `json:"headline"`
	Usage      Usage     `json:"usage"`
	Dir        string    `json:"dir"`
}

// Write persists a result and appends it to the ledger.
func Write(root string, r *Result) (string, error) {
	dir := filepath.Join(root, "runs", r.RunID+"-"+r.Experiment)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "result.json"), raw, 0o644); err != nil {
		return "", err
	}
	var tb strings.Builder
	for _, t := range r.Trials {
		line, _ := json.Marshal(t)
		tb.Write(line)
		tb.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "trials.jsonl"), []byte(tb.String()), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(r)), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte(HTML(r)), 0o644); err != nil {
		return "", err
	}

	entry := LedgerEntry{RunID: r.RunID, Experiment: r.Experiment, Title: r.Title, Version: r.Version,
		StartedAt: r.StartedAt, DurationS: r.FinishedAt.Sub(r.StartedAt).Seconds(),
		Headline: r.Headline, Usage: r.Usage, Dir: filepath.ToSlash(filepath.Join("runs", filepath.Base(dir)))}
	line, _ := json.Marshal(entry)
	f, err := os.OpenFile(filepath.Join(root, "runs", "index.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
	return dir, WriteIndex(root)
}

// Markdown renders a result for review in a pull request.
func Markdown(r *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", r.Title)
	fmt.Fprintf(&b, "**Question.** %s\n\n", r.Question)
	fmt.Fprintf(&b, "Run `%s` · version `%s` · %s · %d upstream calls, %d replayed from the call cache · $%.4f\n\n",
		r.RunID, r.Version, r.StartedAt.Format("2006-01-02 15:04 MST"), r.Usage.UpstreamCalls, r.Usage.CacheReplays, r.Usage.CostUSD)
	if len(r.Headline) > 0 {
		b.WriteString("| | |\n|---|---|\n")
		for _, m := range r.Headline {
			fmt.Fprintf(&b, "| %s | **%s** %s |\n", m.Label, m.Value, m.Hint)
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}
	for _, t := range r.Tables {
		fmt.Fprintf(&b, "## %s\n\n", t.Title)
		b.WriteString("| " + strings.Join(t.Columns, " | ") + " |\n")
		b.WriteString("|" + strings.Repeat("---|", len(t.Columns)) + "\n")
		for _, row := range t.Rows {
			b.WriteString("| " + strings.Join(row, " | ") + " |\n")
		}
		if t.Note != "" {
			fmt.Fprintf(&b, "\n%s\n", t.Note)
		}
		b.WriteString("\n")
	}
	if len(r.Notes) > 0 {
		b.WriteString("## Method notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}
	cfg, _ := json.MarshalIndent(r.Config, "", "  ")
	fmt.Fprintf(&b, "<details><summary>Configuration</summary>\n\n```json\n%s\n```\n</details>\n", cfg)
	return b.String()
}

const pageStyle = `
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 6px}h2{font-size:18px;margin:36px 0 10px}
.sub{color:var(--ink2);margin:0 0 20px}.q{color:var(--ink2);max-width:760px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:14px 16px}.tile .v{font-size:26px;font-weight:650}.tile .l{color:var(--ink2);font-size:13px}.tile .h{color:var(--muted);font-size:12px}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:16px;margin:12px 0;overflow-x:auto}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--ink2);margin:4px 0 8px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
table{border-collapse:collapse;width:100%;font-size:13.5px;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid);white-space:nowrap}th{color:var(--ink2);font-weight:600}
ul.f li{margin:6px 0}.note{color:var(--muted);font-size:13px}a{color:var(--s1)}
svg text{font:12px system-ui,-apple-system,"Segoe UI",sans-serif}
details{margin-top:24px}pre{background:var(--surface);border:1px solid var(--ring);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px}
`

// HTML renders a self-contained report page.
func HTML(r *Result) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(&b, "<title>%s</title><style>%s</style></head><body><main>", html.EscapeString(r.Title), pageStyle)
	b.WriteString(`<p class="note"><a href="../../index.html">← all runs</a></p>`)
	fmt.Fprintf(&b, "<h1>%s</h1><p class=\"sub\">Run %s · version %s · %s · %d upstream calls (%d replayed) · $%.4f</p>",
		esc(r.Title), esc(r.RunID), esc(r.Version), r.StartedAt.Format("2006-01-02 15:04 MST"),
		r.Usage.UpstreamCalls, r.Usage.CacheReplays, r.Usage.CostUSD)
	fmt.Fprintf(&b, "<p class=\"q\"><strong>Question.</strong> %s</p>", esc(r.Question))
	if len(r.Headline) > 0 {
		b.WriteString(`<div class="tiles">`)
		for _, m := range r.Headline {
			fmt.Fprintf(&b, `<div class="tile"><div class="l">%s</div><div class="v">%s</div><div class="h">%s</div></div>`,
				esc(m.Label), esc(m.Value), esc(m.Hint))
		}
		b.WriteString(`</div>`)
	}
	if len(r.Findings) > 0 {
		b.WriteString(`<h2>Findings</h2><ul class="f">`)
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "<li>%s</li>", esc(f))
		}
		b.WriteString(`</ul>`)
	}
	for _, c := range r.Charts {
		b.WriteString(chartHTML(c))
	}
	for _, t := range r.Tables {
		fmt.Fprintf(&b, `<h2>%s</h2><div class="card"><table><thead><tr>`, esc(t.Title))
		for _, c := range t.Columns {
			fmt.Fprintf(&b, "<th>%s</th>", esc(c))
		}
		b.WriteString("</tr></thead><tbody>")
		for _, row := range t.Rows {
			b.WriteString("<tr>")
			for _, cell := range row {
				fmt.Fprintf(&b, "<td>%s</td>", esc(cell))
			}
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
		if t.Note != "" {
			fmt.Fprintf(&b, `<p class="note">%s</p>`, esc(t.Note))
		}
		b.WriteString("</div>")
	}
	if len(r.Notes) > 0 {
		b.WriteString(`<h2>Method notes</h2><ul class="f">`)
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "<li>%s</li>", esc(n))
		}
		b.WriteString(`</ul>`)
	}
	cfg, _ := json.MarshalIndent(r.Config, "", "  ")
	fmt.Fprintf(&b, "<details><summary>Configuration</summary><pre>%s</pre></details>", esc(string(cfg)))
	b.WriteString("</main></body></html>")
	return b.String()
}

var seriesVars = []string{"var(--s1)", "var(--s2)", "var(--s3)", "var(--s4)"}

// chartHTML draws grouped horizontal bars. Thin bars with rounded data-ends,
// a 2px gap between bars of a group, values labelled in text ink, a native
// tooltip on every bar, a legend for two or more series, and the table view
// alongside (every chart in a report is backed by a table).
func chartHTML(c Chart) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<h2>%s</h2><div class="card">`, esc(c.Title))
	sub := c.Note
	if c.LowerIsBetter {
		sub = strings.TrimSpace("Lower is better. " + sub)
	}
	if sub != "" {
		fmt.Fprintf(&b, `<p class="note" style="margin-top:0">%s</p>`, esc(sub))
	}
	if len(c.Series) > 1 {
		b.WriteString(`<div class="legend">`)
		for i, s := range c.Series {
			fmt.Fprintf(&b, `<span><span class="sw" style="background:%s"></span>%s</span>`, seriesVars[i%len(seriesVars)], esc(s))
		}
		b.WriteString(`</div>`)
	}
	maxV := 0.0
	for _, s := range c.Values {
		for _, v := range s {
			if !math.IsNaN(v) && v > maxV {
				maxV = v
			}
		}
	}
	if c.Format == "pct" && maxV < 1 {
		maxV = 1
	}
	if maxV == 0 {
		maxV = 1
	}
	// The label column fits the longest label (about 7px per character at
	// 12px), so labels that differ only at the end stay distinguishable.
	longest := 0
	for _, cat := range c.Categories {
		longest = max(longest, len([]rune(cat)))
	}
	labelW := math.Min(math.Max(float64(longest)*7+16, 120), 420)
	const plotW, barH, gap, groupGap = 620.0, 12.0, 2.0, 14.0
	ns := float64(len(c.Series))
	groupH := ns*barH + (ns-1)*gap
	height := float64(len(c.Categories))*(groupH+groupGap) + 24
	width := labelW + plotW + 90
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" width="100%%" role="img" aria-label="%s">`, width, height, esc(c.Title))
	// Recessive gridlines at quarters.
	for i := 0; i <= 4; i++ {
		x := labelW + plotW*float64(i)/4
		fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="0" y2="%.1f" stroke="var(--grid)" stroke-width="1"/>`, x, x, height-20)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="var(--muted)" text-anchor="middle">%s</text>`, x, height-6, esc(fmtVal(c.Format, maxV*float64(i)/4)))
	}
	fmt.Fprintf(&b, `<line x1="%.1f" x2="%.1f" y1="0" y2="%.1f" stroke="var(--axis)" stroke-width="1"/>`, labelW, labelW, height-20)
	for ci, cat := range c.Categories {
		y0 := float64(ci) * (groupH + groupGap)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="var(--ink2)" text-anchor="end" dominant-baseline="middle">%s</text>`,
			labelW-8, y0+groupH/2, esc(trunc(cat, 58)))
		for si := range c.Series {
			if ci >= len(c.Values[si]) {
				continue
			}
			v := c.Values[si][ci]
			y := y0 + float64(si)*(barH+gap)
			if math.IsNaN(v) {
				fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="var(--muted)" dominant-baseline="middle">n/a</text>`, labelW+6, y+barH/2)
				continue
			}
			w := math.Max(plotW*v/maxV, 0)
			if v > 0 && w < 2 {
				w = 2
			}
			// Rounded data-end, square baseline end: a rect plus a square
			// patch over its left corners.
			fmt.Fprintf(&b, `<g><title>%s · %s: %s</title>`, esc(cat), esc(c.Series[si]), esc(fmtVal(c.Format, v)))
			if w > 0 {
				fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="4" fill="%s"/>`, labelW, y, w, barH, seriesVars[si%len(seriesVars)])
				if w > 4 {
					fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="4" height="%.1f" fill="%s"/>`, labelW, y, barH, seriesVars[si%len(seriesVars)])
				}
			}
			fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="transparent"/>`, labelW, y-1, plotW+80, barH+2)
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="var(--ink)" dominant-baseline="middle">%s</text></g>`,
				labelW+w+6, y+barH/2, esc(fmtVal(c.Format, v)))
		}
	}
	b.WriteString(`</svg></div>`)
	return b.String()
}

func fmtVal(format string, v float64) string {
	switch format {
	case "pct":
		return fmt.Sprintf("%.1f%%", v*100)
	case "ms":
		if v >= 1000 {
			return fmt.Sprintf("%.2fs", v/1000)
		}
		if v < 1 && v > 0 {
			return fmt.Sprintf("%.2fms", v)
		}
		return fmt.Sprintf("%.0fms", v)
	case "usd":
		return fmt.Sprintf("$%.4f", v)
	default:
		if v == math.Trunc(v) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%.2f", v)
	}
}

// WriteIndex regenerates experiments/index.html from the ledger.
func WriteIndex(root string) error {
	entries, err := ReadJSONL[LedgerEntry](filepath.Join(root, "runs", "index.jsonl"))
	if err != nil {
		return err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StartedAt.After(entries[j].StartedAt) })
	latest := map[string]LedgerEntry{}
	var order []string
	for _, e := range entries {
		if _, ok := latest[e.Experiment]; !ok {
			latest[e.Experiment] = e
			order = append(order, e.Experiment)
		}
	}
	sort.Strings(order)

	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintf(&b, "<title>Experiment Ledger</title><style>%s</style></head><body><main>", pageStyle)
	b.WriteString(`<h1>Guardrails experiment ledger</h1><p class="sub">Every run of <code>grctl experiment</code>, newest first. Each run directory holds result.json, trials.jsonl, report.md and report.html.</p>`)
	b.WriteString(`<h2>Latest result per experiment</h2>`)
	for _, name := range order {
		e := latest[name]
		fmt.Fprintf(&b, `<div class="card"><strong><a href="%s/report.html">%s</a></strong> <span class="note">%s · %s</span><div class="tiles">`,
			esc(e.Dir), esc(e.Title), esc(e.RunID), e.StartedAt.Format("2006-01-02 15:04"))
		for _, m := range e.Headline {
			fmt.Fprintf(&b, `<div class="tile"><div class="l">%s</div><div class="v">%s</div><div class="h">%s</div></div>`, esc(m.Label), esc(m.Value), esc(m.Hint))
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`<h2>All runs</h2><div class="card"><table><thead><tr><th>Run</th><th>Experiment</th><th>Version</th><th>Started</th><th>Duration</th><th>Calls (replayed)</th><th>Cost</th></tr></thead><tbody>`)
	for _, e := range entries {
		fmt.Fprintf(&b, `<tr><td><a href="%s/report.html">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td>%.0fs</td><td>%d (%d)</td><td>$%.4f</td></tr>`,
			esc(e.Dir), esc(e.RunID), esc(e.Experiment), esc(e.Version), e.StartedAt.Format("2006-01-02 15:04"),
			e.DurationS, e.Usage.UpstreamCalls, e.Usage.CacheReplays, e.Usage.CostUSD)
	}
	b.WriteString(`</tbody></table></div></main></body></html>`)
	return os.WriteFile(filepath.Join(root, "index.html"), []byte(b.String()), 0o644)
}

func esc(s string) string { return html.EscapeString(s) }

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Pct formats a ratio.
func Pct(v float64) string {
	if math.IsNaN(v) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", v*100)
}

// Ms formats a duration in milliseconds.
func Ms(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// Percentile over durations (nearest-rank).
func Percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(math.Ceil(p*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	return s[idx]
}

// Ratio guards against division by zero.
func Ratio(a, b int) float64 {
	if b == 0 {
		return math.NaN()
	}
	return float64(a) / float64(b)
}

// Rerender rewrites report.html and report.md of every run from its
// result.json, so a rendering fix reaches runs recorded before it.
func Rerender(root string) (int, error) {
	dirs, err := filepath.Glob(filepath.Join(root, "runs", "*", "result.json"))
	if err != nil {
		return 0, err
	}
	for _, f := range dirs {
		raw, err := os.ReadFile(f)
		if err != nil {
			return 0, err
		}
		var r Result
		if err := json.Unmarshal(raw, &r); err != nil {
			return 0, fmt.Errorf("%s: %w", f, err)
		}
		dir := filepath.Dir(f)
		if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte(HTML(&r)), 0o644); err != nil {
			return 0, err
		}
		if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(&r)), 0o644); err != nil {
			return 0, err
		}
	}
	return len(dirs), WriteIndex(root)
}
