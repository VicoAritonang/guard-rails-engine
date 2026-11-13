package outbound

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards/detect"
)

// Format enforces the shape and safety of rendered output.
//
// The headline check here is markdown image exfiltration, which is the most
// under-appreciated vulnerability in chat products. An injected instruction
// tells the model to emit an image whose URL embeds the conversation; the
// client renders it; the browser fetches it; the attacker's server logs the
// data. Nobody clicks anything, and the completion looks like a blank line.
// Blocking auto-fetching markdown to non-allowlisted hosts closes it.
type Format struct {
	cfg *config.GuardConfig

	maxChars      int
	blockDataURLs bool
	allowedHosts  map[string]bool
	bannedPhrases []string
}

func NewFormat(cfg *config.GuardConfig) (*Format, error) {
	g := &Format{
		cfg:           cfg,
		maxChars:      cfg.Int("max_output_chars", 200000),
		blockDataURLs: cfg.Bool("block_data_urls", true),
		allowedHosts:  map[string]bool{},
		bannedPhrases: cfg.Strings("banned_phrases"),
	}
	for _, h := range cfg.Strings("allowed_link_hosts") {
		g.allowedHosts[strings.ToLower(strings.TrimSpace(h))] = true
	}
	if g.maxChars <= 0 {
		return nil, fmt.Errorf("format: max_output_chars must be positive")
	}
	return g, nil
}

func (g *Format) Name() string      { return config.GuardFormat }
func (g *Format) Stage() core.Stage { return core.StageOutbound }

var (
	// Markdown image: ![alt](url). The alt text is where payloads hide.
	reMdImage = regexp.MustCompile(`!\[[^\]]*\]\(\s*([^)\s]+)[^)]*\)`)
	reMdLink  = regexp.MustCompile(`(?:^|[^!])\[[^\]]*\]\(\s*([^)\s]+)[^)]*\)`)
	// HTML that auto-fetches without user interaction.
	reAutoFetch = regexp.MustCompile(`(?i)<(?:img|iframe|script|object|embed|link|audio|video|source)\b[^>]*>`)
	reJSURL     = regexp.MustCompile(`(?i)\b(?:javascript|vbscript|data):`)
)

func (g *Format) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	out := tx.Completion
	if out == "" {
		return res, nil
	}
	res.Metrics = map[string]float64{"format.output_chars": float64(len(out))}

	if len(out) > g.maxChars {
		f := core.NewFinding(g.Name(), "max_output_chars", "format.oversized",
			core.SeverityMedium, 1.0,
			fmt.Sprintf("completion is %d chars, limit is %d", len(out), g.maxChars))
		res.Findings = append(res.Findings, f)
		// Truncation is offered as a mutation so a policy set to "redact" can
		// deliver a trimmed answer instead of failing the request outright.
		res.Mutations = append(res.Mutations, core.Mutation{
			Guard: g.Name(), Field: core.FieldCompletion,
			Start: g.maxChars, End: len(out),
			Replacement: "\n\n[output truncated by policy]",
			Reason:      "format.oversized",
		})
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	// Images are the exfiltration vector; links are merely a phishing vector.
	// Both are checked, at different severities.
	for _, m := range reMdImage.FindAllStringSubmatchIndex(out, 32) {
		raw := out[m[2]:m[3]]
		if reason, bad := g.badURL(raw); bad {
			f := core.NewFinding(g.Name(), "image_exfiltration", "format.image_exfiltration",
				core.SeverityHigh, 0.9,
				"completion embeds an auto-fetching image to an untrusted host: "+reason)
			f.Spans = []core.Span{{
				Field: core.FieldCompletion, Start: m[0], End: m[1],
				Excerpt: truncate(out[m[0]:m[1]], 120),
			}}
			f.Meta = map[string]string{"url": truncate(raw, 200)}
			res.Findings = append(res.Findings, f)
			res.Mutations = append(res.Mutations, core.Mutation{
				Guard: g.Name(), Field: core.FieldCompletion,
				Start: m[0], End: m[1],
				Replacement: "[image removed by policy]",
				Reason:      "format.image_exfiltration",
			})
		}
	}

	for _, m := range reMdLink.FindAllStringSubmatchIndex(out, 32) {
		raw := out[m[2]:m[3]]
		if reJSURL.MatchString(raw) {
			f := core.NewFinding(g.Name(), "script_url", "format.script_url",
				core.SeverityHigh, 0.95, "completion contains a script-scheme link")
			f.Spans = []core.Span{{Field: core.FieldCompletion, Start: m[0], End: m[1]}}
			res.Findings = append(res.Findings, f)
			continue
		}
		if len(g.allowedHosts) > 0 {
			if reason, bad := g.badURL(raw); bad {
				f := core.NewFinding(g.Name(), "untrusted_link", "format.untrusted_link",
					core.SeverityMedium, 0.7,
					"completion links to a host outside the allowlist: "+reason)
				f.Spans = []core.Span{{Field: core.FieldCompletion, Start: m[0], End: m[1]}}
				f.Meta = map[string]string{"url": truncate(raw, 200)}
				res.Findings = append(res.Findings, f)
			}
		}
	}

	if loc := reAutoFetch.FindStringIndex(out); loc != nil {
		f := core.NewFinding(g.Name(), "raw_html", "format.raw_html",
			core.SeverityMedium, 0.8,
			"completion contains raw HTML that a renderer would auto-fetch or execute")
		f.Spans = []core.Span{{
			Field: core.FieldCompletion, Start: loc[0], End: loc[1],
			Excerpt: truncate(out[loc[0]:loc[1]], 120),
		}}
		res.Findings = append(res.Findings, f)
	}

	for _, phrase := range g.bannedPhrases {
		if phrase == "" {
			continue
		}
		if i := strings.Index(strings.ToLower(out), strings.ToLower(phrase)); i >= 0 {
			f := core.NewFinding(g.Name(), "banned_phrase", "format.banned_phrase",
				core.SeverityMedium, 1.0,
				fmt.Sprintf("completion contains banned phrase %q", phrase))
			f.Spans = []core.Span{{Field: core.FieldCompletion, Start: i, End: i + len(phrase)}}
			res.Findings = append(res.Findings, f)
			res.Mutations = append(res.Mutations, core.Mutation{
				Guard: g.Name(), Field: core.FieldCompletion,
				Start: i, End: i + len(phrase),
				Replacement: "[removed]", Reason: "format.banned_phrase",
			})
		}
	}

	return res, nil
}

// badURL reports whether a URL should not be auto-fetched by a renderer.
func (g *Format) badURL(raw string) (string, bool) {
	if g.blockDataURLs && strings.HasPrefix(strings.ToLower(raw), "data:") {
		return "data: URL", true
	}
	if reJSURL.MatchString(raw) {
		return "script scheme", true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "unparseable URL", true
	}
	if u.Scheme == "" && !strings.HasPrefix(raw, "/") {
		return "", false // relative reference, harmless
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if len(g.allowedHosts) > 0 && !g.allowedHosts[host] && !hasAllowedSuffix(host, g.allowedHosts) {
		return "host " + host + " not allowlisted", true
	}
	// With no allowlist configured, a query string on an image URL is the
	// signal worth acting on: that is where exfiltrated data rides.
	if len(g.allowedHosts) == 0 && u.RawQuery != "" && len(u.RawQuery) > 24 {
		if detect.ShannonEntropy(u.RawQuery) > 3.5 {
			return "high-entropy query string on remote image", true
		}
	}
	return "", false
}

func hasAllowedSuffix(host string, allowed map[string]bool) bool {
	for a := range allowed {
		if strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}
