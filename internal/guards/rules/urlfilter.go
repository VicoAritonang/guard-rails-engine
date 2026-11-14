package rules

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// URLFilter allow-lists the links in a payload.
//
// Inbound it keeps users from steering the model at arbitrary pages; outbound
// it keeps the model from handing users a link nobody vetted, which is the
// last step of most phishing-through-a-chatbot attacks. The checks that need
// no allow list at all -- credentials in the URL ("https://bank.com@evil.io"),
// raw IP hosts, private addresses, non-https schemes -- are on by default
// once the guard is enabled.
type URLFilter struct {
	name           string
	stage          core.Stage
	allow, deny    []string
	schemes        map[string]bool
	subdomains     bool
	blockUserinfo  bool
	blockIPLiteral bool
	blockPrivate   bool
	severity       core.Severity
}

var urlRe = regexp.MustCompile(`(?i)\b(?:[a-z][a-z0-9+.-]{1,15}://|www\.|mailto:|javascript:|data:)[^\s<>"'\x60\]\[{}|\\^]+`)

// NewURLFilter builds the URL filter for one stage.
func NewURLFilter(name string, stage core.Stage, cfg *config.GuardConfig) (*URLFilter, error) {
	sev, err := core.ParseSeverity(cfg.String("severity", "medium"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	g := &URLFilter{
		name: name, stage: stage,
		allow:          lower(cfg.Strings("allow")),
		deny:           lower(cfg.Strings("deny")),
		schemes:        map[string]bool{},
		subdomains:     cfg.Bool("allow_subdomains", true),
		blockUserinfo:  cfg.Bool("block_userinfo", true),
		blockIPLiteral: cfg.Bool("block_ip_literals", true),
		blockPrivate:   cfg.Bool("block_private", true),
		severity:       sev,
	}
	schemes := cfg.Strings("allowed_schemes")
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	for _, s := range schemes {
		g.schemes[strings.ToLower(strings.TrimSuffix(s, ":"))] = true
	}
	return g, nil
}

func lower(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (g *URLFilter) Name() string      { return g.name }
func (g *URLFilter) Stage() core.Stage { return g.stage }

func (g *URLFilter) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	fields := tx.UserFields()
	if g.stage == core.StageOutbound {
		fields = tx.ScanFields()
	}
	for _, f := range fields {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		for _, loc := range urlRe.FindAllStringIndex(f.Text, 200) {
			raw := strings.TrimRight(f.Text[loc[0]:loc[1]], ".,;:!?)")
			end := loc[0] + len(raw)
			rule, cat, sev, why := g.judge(raw)
			if rule == "" {
				continue
			}
			fd := core.NewFinding(g.name, rule, cat, sev, 1.0, why)
			fd.Spans = []core.Span{{Field: f.Field, Start: loc[0], End: end, Excerpt: truncateURL(raw)}}
			fd.Meta = map[string]string{"url": truncateURL(raw)}
			res.Findings = append(res.Findings, fd)
			res.Mutations = append(res.Mutations, core.Mutation{Guard: g.name, Field: f.Field,
				Start: loc[0], End: end, Replacement: "[link removed]", Reason: cat})
		}
	}
	return res, nil
}

// judge returns the first rule a URL breaks, or "" when it passes.
func (g *URLFilter) judge(raw string) (rule, category string, sev core.Severity, why string) {
	s := raw
	if strings.HasPrefix(strings.ToLower(s), "www.") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "unparseable", "url.malformed", core.SeverityLow, "a URL could not be parsed"
	}
	scheme := strings.ToLower(u.Scheme)
	if !g.schemes[scheme] {
		sv := g.severity
		if scheme == "javascript" || scheme == "data" || scheme == "file" {
			sv = core.SeverityHigh
		}
		return "scheme", "url.scheme", sv, fmt.Sprintf("URL scheme %q is not allowed", scheme)
	}
	if scheme == "mailto" {
		return "", "", 0, ""
	}
	if g.blockUserinfo && u.User != nil {
		return "userinfo", "url.userinfo", core.SeverityHigh,
			"URL carries credentials or a decoy host before '@' (" + u.User.Username() + "@" + u.Hostname() + ")"
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", 0, ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if g.blockPrivate && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return "private_address", "url.private_address", core.SeverityHigh, "URL points at a private or loopback address " + host
		}
		if g.blockIPLiteral {
			return "ip_literal", "url.ip_literal", g.severity, "URL uses a raw IP address instead of a hostname"
		}
	}
	if g.blockPrivate && (host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".local") || host == "metadata.google.internal") {
		return "private_address", "url.private_address", core.SeverityHigh, "URL points at an internal hostname " + host
	}
	if matchHost(host, g.deny, true) {
		return "denied", "url.denied", core.SeverityHigh, "URL host " + host + " is on the deny list"
	}
	if len(g.allow) > 0 && !matchHost(host, g.allow, g.subdomains) {
		return "not_allowed", "url.not_allowed", g.severity, "URL host " + host + " is not on the allow list"
	}
	return "", "", 0, ""
}

func matchHost(host string, list []string, subdomains bool) bool {
	for _, h := range list {
		h = strings.TrimPrefix(h, "*.")
		if host == h || (subdomains && strings.HasSuffix(host, "."+h)) {
			return true
		}
	}
	return false
}

func truncateURL(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
