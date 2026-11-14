package media

import (
	"fmt"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// reader accumulates the text of one part and its findings.
type reader struct {
	p   *Processor
	ref core.PartRef
	ext *core.Extraction
	b   strings.Builder
	// hidden collects text a human reader would not see. It is scanned like
	// the rest (a model reads it), and its presence is itself a finding.
	hidden strings.Builder
}

func (r *reader) write(s string) {
	if s == "" || r.b.Len() > r.p.opts.MaxChars+1024 {
		return
	}
	r.b.WriteString(s)
}

func (r *reader) section(title, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	if r.b.Len() > 0 {
		r.write("\n\n")
	}
	if title != "" {
		r.write("[" + title + "]\n")
	}
	r.write(body)
}

func (r *reader) text() string {
	if h := strings.TrimSpace(r.hidden.String()); h != "" {
		r.section("hidden content", h)
	}
	return strings.TrimSpace(r.b.String())
}

func (r *reader) add(rule, category string, sev core.Severity, format string, args ...any) *core.Finding {
	f := finding(r.ref, rule, category, sev, fmt.Sprintf(format, args...))
	r.ext.Findings = append(r.ext.Findings, f)
	return &r.ext.Findings[len(r.ext.Findings)-1]
}

func (r *reader) warn(format string, args ...any) {
	r.ext.Warnings = append(r.ext.Warnings, fmt.Sprintf(format, args...))
}

// hiddenFinding reports hidden text with a bounded excerpt.
func (r *reader) hiddenFinding(where string, chars int, sample string) {
	if chars <= 0 {
		return
	}
	f := r.add("hidden_text", "document.hidden_text", core.SeverityMedium,
		"%s contains %d characters of text hidden from a human reader (%s); it is still read by a model", r.ref.Part.Label(), chars, where)
	f.Meta["hidden_chars"] = fmt.Sprint(chars)
	if s := strings.TrimSpace(sample); s != "" {
		f.Spans[0].Excerpt = truncate(s, 120)
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
