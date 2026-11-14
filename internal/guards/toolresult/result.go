// Package toolresult implements the rails that run on what a tool returned,
// before that text is appended to the model's context.
//
// This stage exists because of an asymmetry that is easy to miss. Inbound rails
// inspect what the user wrote, and the user is a party to the conversation.
// Nobody inspects what a tool returned, and a tool result is text from a party
// who is not in the conversation at all: whoever wrote the web page, whoever
// sent the email, whoever filed the support ticket the knowledge base indexed.
// An agent that trusts tool output because the tool is "ours" is trusting every
// author whose text that tool can reach.
package toolresult

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/core/normalize"
	"go.vicoworks.com/guard-rails-engine/internal/guards/inbound"
)

// Guard inspects tool results.
//
// It reuses the inbound injection detector rather than reimplementing one, with
// one change that matters: the same signal is graded higher here. A user
// writing "ignore your previous instructions" is usually testing the product. A
// web page writing it, in a document the user asked to be summarised, has no
// benign reading at all -- the user did not write it, did not see it, and did
// not ask for it. Same detector, different prior, and the prior is where the
// precision comes from.
type Guard struct {
	cfg       *config.GuardConfig
	injection *inbound.Injection

	maxBytes      int
	scanBytes     int
	escalate      bool
	scanInjection bool
}

// New builds the tool-result guard.
func New(cfg *config.GuardConfig) (*Guard, error) {
	g := &Guard{
		cfg:           cfg,
		maxBytes:      cfg.Int("max_result_bytes", 200_000),
		scanBytes:     cfg.Int("scan_bytes", 64_000),
		escalate:      cfg.Bool("escalate_injection", true),
		scanInjection: cfg.Bool("scan_injection", true),
	}
	if g.scanInjection {
		// The sub-detector runs with this guard's threshold, so an operator
		// tuning tool_result does not have to reason about the inbound guard's
		// configuration as well.
		sub := *cfg
		sub.Name = config.GuardInjection
		inj, err := inbound.NewInjection(&sub)
		if err != nil {
			return nil, fmt.Errorf("tool_result: %w", err)
		}
		g.injection = inj
	}
	return g, nil
}

func (g *Guard) Name() string      { return config.GuardToolResult }
func (g *Guard) Stage() core.Stage { return core.StageToolResult }

func (g *Guard) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	if len(tx.ToolResults) == 0 {
		return res, nil
	}
	res.Metrics = map[string]float64{"tool_result.count": float64(len(tx.ToolResults))}

	// Every pattern check runs against the bounded view, not the raw result.
	// Scanning the full 234KB fixture put this stage at a 99ms p99 against a
	// 50ms budget -- found by the eval harness, not by guesswork -- and the
	// bound costs nothing, because checkSize truncates the tail away before
	// the model ever sees it.
	view := g.scanView(tx)

	var totalBytes int
	for i, r := range tx.ToolResults {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		field := fmt.Sprintf("tool_results[%d].content", i)
		totalBytes += len(r.Content)

		// checkSize is the one check that needs the true length: it is the
		// check about the length.
		g.checkSize(&res, field, r)

		scan := view.ToolResults[i]

		// checkHidden looks for the obfuscation itself, so it must see the raw
		// bytes: normalising first would fold away the very characters it is
		// hunting for.
		g.checkHidden(&res, field, scan)

		// The remaining checks split by what they match on, and the split is
		// not cosmetic -- the red-team suite established both halves of it.
		//
		// Phrase checks must run on normalised text: shipped raw, every one of
		// homoglyph, zero_width and leetspeak walked straight through tr-001.
		//
		// Structural checks must run on raw text: the injection preset strips
		// '.', '-', '_' and '/' between word characters and de-leets '@' to
		// 'a', so on folded text "billing-ops@vendor.example" becomes
		// "billingopsavendorexample" -- no @, no dot, and no email pattern can
		// match it. Folding is the right default for words and destroys
		// addresses, so each check gets the text it needs.
		nv := newView(scan.Content)
		g.checkExfilLinks(&res, field, scan.Name, nv)
		g.checkToolDirectives(&res, field, scan.Name, nv)
		g.checkImperativeFraming(&res, field, scan.Name, nv)

		// Attachments a tool returned (a screenshot's OCR, a fetched PDF's
		// text) get the same pattern checks as its text output. They are
		// bounded by the ingest step's own character limit, not scan_bytes.
		for j, p := range r.Parts {
			if p.Text == "" {
				continue
			}
			pf := fmt.Sprintf("tool_results[%d].parts[%d].text", i, j)
			pr := core.ToolResult{Name: r.Name, Content: p.Text, Origin: r.Origin}
			g.checkHidden(&res, pf, pr)
			pv := newView(p.Text)
			g.checkExfilLinks(&res, pf, r.Name, pv)
			g.checkToolDirectives(&res, pf, r.Name, pv)
			g.checkImperativeFraming(&res, pf, r.Name, pv)
		}
	}
	res.Metrics["tool_result.bytes"] = float64(totalBytes)
	res.Metrics["tool_result.scanned_bytes"] = float64(scannedBytes(view))

	if g.injection != nil {
		sub, err := g.injection.Check(ctx, view)
		if err != nil {
			return res, err
		}
		for _, f := range sub.Findings {
			res.Findings = append(res.Findings, g.reframe(f, tx))
		}
		for k, v := range sub.Metrics {
			res.Metrics["tool_result."+k] = v
		}
	}
	return res, nil
}

// scanView returns a transaction whose results are truncated to the scan limit.
//
// Running a full signal sweep over a quarter-megabyte page took the tool-result
// stage to a 58ms p99 against a 50ms budget -- measured, not guessed, by the
// eval harness on the oversized case. Bounding the scan fixes it, and the bound
// is safe for a reason worth stating: content past max_result_bytes is
// truncated away by checkSize before the result reaches the model, so scanning
// beyond that point would be scanning text nothing will ever read. An attacker
// can push a payload past the limit, and it buys them a truncated payload.
func (g *Guard) scanView(tx *core.Transaction) *core.Transaction {
	limit := g.scanBytes
	if g.maxBytes > 0 && g.maxBytes < limit {
		limit = g.maxBytes
	}
	if limit <= 0 {
		return tx
	}
	needed := false
	for _, r := range tx.ToolResults {
		if len(r.Content) > limit {
			needed = true
			break
		}
	}
	if !needed {
		return tx
	}
	view := *tx
	view.ToolResults = make([]core.ToolResult, len(tx.ToolResults))
	copy(view.ToolResults, tx.ToolResults)
	for i, r := range view.ToolResults {
		if len(r.Content) <= limit {
			continue
		}
		cut := limit
		for cut > 0 && !utf8.RuneStart(r.Content[cut]) {
			cut--
		}
		view.ToolResults[i].Content = r.Content[:cut]
	}
	return &view
}

// view pairs the raw text with an aggressively folded copy of it, plus the
// offset map that turns a match in the folded copy back into a span in the
// original. Every phrase check runs against Folded and reports against Raw.
type view struct {
	Raw    string
	Folded normalize.Text
}

func newView(s string) view {
	return view{Raw: s, Folded: normalize.Normalize(s, normalize.ForInjection)}
}

// span maps a match on the folded text back onto the original bytes.
func (v view) span(field string, start, end int) core.Span {
	from, to := v.Folded.Origin(start, end)
	if from < 0 || to > len(v.Raw) || from >= to {
		// Defensive: a bad offset must not panic a guard, and a span that
		// cannot be mapped is still worth reporting without one.
		return core.Span{Field: field}
	}
	return core.Span{Field: field, Start: from, End: to, Excerpt: excerpt(v.Raw, from, to)}
}

func scannedBytes(tx *core.Transaction) int {
	n := 0
	for _, r := range tx.ToolResults {
		n += len(r.Content)
	}
	return n
}

func (g *Guard) checkImperativeFraming(res *core.Result, field, tool string, v view) {
	var classes []string
	var span *core.Span
	note := func(name string, sp core.Span, hit bool) {
		if !hit {
			return
		}
		classes = append(classes, name)
		if span == nil || sp.Start < span.Start {
			cp := sp
			span = &cp
		}
	}

	// Word phrases: folded, so a homoglyph or a leetspeak swap does not hide
	// them.
	folded := v.Folded.Value
	if loc := authorityFraming.FindStringIndex(folded); loc != nil {
		note("authority", v.span(field, loc[0], loc[1]), true)
	}
	if loc := agentAddressing.FindStringIndex(folded); loc != nil {
		note("addressing", v.span(field, loc[0], loc[1]), true)
	}
	// Destination: raw, because the pattern needs a real '@' and a real dot.
	if loc := exfilIntent.FindStringIndex(v.Raw); loc != nil {
		note("exfil_intent", core.Span{Field: field, Start: loc[0], End: loc[1],
			Excerpt: excerpt(v.Raw, loc[0], loc[1])}, true)
	}

	if len(classes) < 2 {
		// One signal alone is not enough. A support article can legitimately
		// say "email us at support@example.com", and a changelog can
		// legitimately contain the words "updated policy". It takes two to be
		// an instruction aimed at the model.
		return
	}
	sev, score := core.SeverityHigh, 0.88
	if len(classes) == 3 {
		sev, score = core.SeverityCritical, 0.96
	}
	f := core.NewFinding(config.GuardToolResult, "instruction_framing",
		"tool_result.instruction_framing", sev, score,
		fmt.Sprintf("output of tool %q is shaped as an instruction to the agent (%s); "+
			"tool results are data, and data that gives orders was written by someone "+
			"who is not in this conversation",
			tool, strings.Join(classes, " + ")))
	if span != nil {
		f.Spans = []core.Span{*span}
	}
	f.Meta = map[string]string{"tool": tool, "signals": strings.Join(classes, ",")}
	res.Findings = append(res.Findings, f)
}

// reframe rewrites an inbound finding into a tool-result finding.
//
// The rewrite is not cosmetic. Leaving the finding attributed to the injection
// guard would put it under the injection guard's policy, so an operator who set
// injection to flag-only for their chatbot would silently be flag-only on
// injected instructions arriving inside tool output -- a very different risk
// they never agreed to.
func (g *Guard) reframe(f core.Finding, tx *core.Transaction) core.Finding {
	f.Guard = g.Name()
	f.Category = "tool_result." + strings.TrimPrefix(f.Category, "injection.")
	if g.escalate && f.Severity < core.SeverityCritical {
		f.Severity++
		f.SeverityName = f.Severity.String()
	}
	origin := "tool"
	if len(f.Spans) > 0 {
		if i, ok := resultIndex(f.Spans[0].Field); ok && i < len(tx.ToolResults) {
			if o := tx.ToolResults[i].Origin; o != "" {
				origin = string(o)
			}
			f.Message = fmt.Sprintf("%s (in output of tool %q)", f.Message, tx.ToolResults[i].Name)
		}
	}
	if f.Meta == nil {
		f.Meta = map[string]string{}
	}
	f.Meta["origin"] = origin
	f.Meta["escalated"] = fmt.Sprint(g.escalate)
	return f
}

// checkSize catches a result large enough to push the real instructions out of
// the context window. Context flooding is a denial-of-integrity attack, not
// just a cost problem: the system prompt is what falls off the end.
func (g *Guard) checkSize(res *core.Result, field string, r core.ToolResult) {
	if g.maxBytes <= 0 || len(r.Content) <= g.maxBytes {
		return
	}
	f := core.NewFinding(config.GuardToolResult, "oversized_result", "tool_result.oversized",
		core.SeverityMedium, 1.0,
		fmt.Sprintf("tool %q returned %d bytes, limit is %d; truncated before it reached the model",
			r.Name, len(r.Content), g.maxBytes))
	f.Spans = []core.Span{{Field: field, Start: g.maxBytes, End: len(r.Content)}}
	f.Meta = map[string]string{"tool": r.Name, "bytes": fmt.Sprint(len(r.Content))}
	res.Findings = append(res.Findings, f)

	// Truncate on a rune boundary: cutting a multi-byte character in half would
	// hand the model invalid UTF-8, which some providers reject outright.
	cut := g.maxBytes
	for cut > 0 && !utf8.RuneStart(r.Content[cut]) {
		cut--
	}
	res.Mutations = append(res.Mutations, core.Mutation{
		Guard:       config.GuardToolResult,
		Field:       field,
		Start:       cut,
		End:         len(r.Content),
		Replacement: "\n[truncated by guardrails: result exceeded the per-result byte limit]",
		Reason:      "oversized tool result",
	})
}

// hiddenPatterns find text placed where a human reviewer will not see it but
// the model will.
var hiddenPatterns = []struct {
	rule, category string
	re             *regexp.Regexp
	severity       core.Severity
	message        string
}{
	{
		rule: "html_comment_instruction", category: "tool_result.hidden_text",
		re:       regexp.MustCompile(`(?is)<!--.{0,400}?\b(?:ignore|disregard|instead|you must|system|assistant|forward|send|email)\b.{0,400}?-->`),
		severity: core.SeverityHigh,
		message:  "an HTML comment in the result contains instruction-shaped text",
	},
	{
		rule: "invisible_css", category: "tool_result.hidden_text",
		re:       regexp.MustCompile(`(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*#?f{3,6}\b)`),
		severity: core.SeverityMedium,
		message:  "the result contains text styled to be invisible to a human reader",
	},
	{
		rule: "zero_width_run", category: "tool_result.hidden_text",
		re:       regexp.MustCompile(`[\x{200B}-\x{200F}\x{2060}-\x{2064}\x{FEFF}]{4,}`),
		severity: core.SeverityMedium,
		message:  "the result contains a run of zero-width characters",
	},
	{
		rule: "unicode_tag_chars", category: "tool_result.hidden_text",
		re:       regexp.MustCompile("[\U000E0000-\U000E007F]{2,}"),
		severity: core.SeverityHigh,
		message:  "the result contains Unicode tag characters, which render as nothing and read as text",
	},
}

func (g *Guard) checkHidden(res *core.Result, field string, r core.ToolResult) {
	for _, p := range hiddenPatterns {
		loc := p.re.FindStringIndex(r.Content)
		if loc == nil {
			continue
		}
		f := core.NewFinding(config.GuardToolResult, p.rule, p.category, p.severity, 0.9,
			fmt.Sprintf("%s (tool %q)", p.message, r.Name))
		f.Spans = []core.Span{{Field: field, Start: loc[0], End: loc[1],
			Excerpt: excerpt(r.Content, loc[0], loc[1])}}
		f.Meta = map[string]string{"tool": r.Name}
		res.Findings = append(res.Findings, f)
	}
}

func (g *Guard) checkExfilLinks(res *core.Result, field, tool string, v view) {
	// Raw: this one matches a URL, and a folded URL is not a URL.
	text := v.Raw
	for _, loc := range reExfilLink.FindAllStringSubmatchIndex(text, 8) {
		url := text[loc[2]:loc[3]]
		if !strings.ContainsAny(url, "?&") {
			continue
		}
		isImage := loc[0] < len(text) && text[loc[0]] == '!'
		sev, kind := core.SeverityMedium, "link"
		if isImage {
			// An image is fetched while the answer renders, so the data leaves
			// without anyone clicking anything.
			sev, kind = core.SeverityHigh, "image"
		}
		f := core.NewFinding(config.GuardToolResult, "exfiltration_markup",
			"tool_result.exfil_markup", sev, 0.8,
			fmt.Sprintf("tool %q returned a markdown %s whose URL carries a long query string; "+
				"if the model repeats it, rendering the answer sends data to that host",
				tool, kind))
		f.Spans = []core.Span{{Field: field, Start: loc[0], End: loc[1],
			Excerpt: excerpt(text, loc[0], loc[1])}}
		f.Meta = map[string]string{"tool": tool, "kind": kind}
		res.Findings = append(res.Findings, f)
	}
}

func (g *Guard) checkToolDirectives(res *core.Result, field, tool string, v view) {
	text := v.Folded.Value
	loc := reToolDirective.FindStringSubmatchIndex(text)
	if loc == nil {
		return
	}
	named := text[loc[2]:loc[3]]
	f := core.NewFinding(config.GuardToolResult, "tool_directive_in_result",
		"tool_result.tool_directive", core.SeverityCritical, 0.93,
		fmt.Sprintf("output of tool %q instructs the agent to call %q; tool results are data, "+
			"and data that names a tool to call is an instruction from whoever wrote it",
			tool, named))
	f.Spans = []core.Span{v.span(field, loc[0], loc[1])}
	f.Meta = map[string]string{"tool": tool, "named_tool": named}
	res.Findings = append(res.Findings, f)
}

func excerpt(s string, start, end int) string {
	if end > len(s) {
		end = len(s)
	}
	if end-start > 160 {
		end = start + 160
	}
	return strings.TrimSpace(s[start:end])
}

func resultIndex(field string) (int, bool) {
	const prefix, suffix = "tool_results[", "].content"
	// A part reference ("tool_results[2].parts[0].text") belongs to result 2.
	if strings.HasPrefix(field, prefix) && strings.Contains(field, "].parts[") {
		field = field[:strings.Index(field, "].parts[")] + suffix
	}
	if !strings.HasPrefix(field, prefix) || !strings.HasSuffix(field, suffix) {
		return 0, false
	}
	n := 0
	for _, r := range field[len(prefix) : len(field)-len(suffix)] {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
