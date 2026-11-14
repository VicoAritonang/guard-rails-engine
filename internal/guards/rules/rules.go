// Package rules holds the operator-defined guards: keyword and regular
// expression rules written in the policy file, and the URL filter.
//
// Every built-in detector encodes somebody's idea of a threat. These two
// encode the operator's: a competitor's name the support bot must not
// mention, an internal project codename, a ticket-number format that is
// confidential, the three domains the assistant may link to. They exist so
// that changing what the gateway enforces is a policy edit, not a pull
// request.
package rules

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/core/normalize"
)

// Rule is one entry of params.rules.
type Rule struct {
	ID          string
	Category    string
	Severity    core.Severity
	Message     string
	Replacement string
	Roles       map[core.Role]bool
	keywords    *regexp.Regexp // over normalised text
	patterns    []*regexp.Regexp
}

// Guard evaluates a rule list on one stage.
type Guard struct {
	name  string
	stage core.Stage
	rules []Rule
}

// New builds the custom-rules guard registered under name.
//
// A rule's optional "action" is written into the guard's category overrides
// unless the operator already set one there, so the rule list stays the one
// place a rule is defined while the pipeline keeps resolving actions in the
// one place it always does.
func New(name string, stage core.Stage, cfg *config.GuardConfig) (*Guard, error) {
	g := &Guard{name: name, stage: stage}
	raw, _ := cfg.Params["rules"].([]any)
	seen := map[string]bool{}
	for i, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: rules[%d] must be a mapping", name, i)
		}
		r, action, err := parseRule(m)
		if err != nil {
			return nil, fmt.Errorf("%s: rules[%d]: %w", name, i, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("%s: duplicate rule id %q", name, r.ID)
		}
		seen[r.ID] = true
		if action != "" {
			if _, err := core.ParseAction(action); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", name, r.ID, err)
			}
			if cfg.Categories == nil {
				cfg.Categories = map[string]config.CategoryOverride{}
			}
			ov := cfg.Categories[r.Category]
			if ov.Action == "" {
				ov.Action = action
				cfg.Categories[r.Category] = ov
			}
		}
		g.rules = append(g.rules, r)
	}
	if cfg.Enabled && len(g.rules) == 0 {
		return nil, fmt.Errorf("%s is enabled but params.rules is empty", name)
	}
	return g, nil
}

func parseRule(m map[string]any) (Rule, string, error) {
	str := func(k string) string { s, _ := m[k].(string); return strings.TrimSpace(s) }
	list := func(k string) []string {
		var out []string
		switch v := m[k].(type) {
		case []any:
			for _, x := range v {
				if s := strings.TrimSpace(fmt.Sprint(x)); s != "" {
					out = append(out, s)
				}
			}
		case string:
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	r := Rule{ID: str("id"), Category: str("category"), Message: str("message"), Replacement: str("replacement")}
	if r.ID == "" {
		return r, "", errors.New("id is required")
	}
	if r.Category == "" {
		r.Category = "custom." + r.ID
	}
	sev := str("severity")
	if sev == "" {
		sev = "medium"
	}
	s, err := core.ParseSeverity(sev)
	if err != nil {
		return r, "", err
	}
	r.Severity = s
	if r.Replacement == "" {
		r.Replacement = "[" + strings.ToUpper(strings.ReplaceAll(r.ID, "-", "_")) + "]"
	}
	if roles := list("roles"); len(roles) > 0 {
		r.Roles = map[core.Role]bool{}
		for _, x := range roles {
			r.Roles[core.Role(strings.ToLower(x))] = true
		}
	}

	if kws := list("keywords"); len(kws) > 0 {
		// Keywords match on folded text, so "Ac­me", "ACME" and "Аcme" (with
		// a Cyrillic A) are one keyword, exactly as the injection detector
		// treats its phrases.
		alts := make([]string, 0, len(kws))
		for _, k := range kws {
			folded := normalize.Normalize(k, normalize.ForTopic).Value
			if folded == "" {
				continue
			}
			alts = append(alts, regexp.QuoteMeta(folded))
		}
		sort.Slice(alts, func(i, j int) bool { return len(alts[i]) > len(alts[j]) })
		re, err := regexp.Compile(`(?i)(?:^|\b)(?:` + strings.Join(alts, "|") + `)(?:\b|$)`)
		if err != nil {
			return r, "", err
		}
		r.keywords = re
	}
	for _, p := range list("patterns") {
		re, err := regexp.Compile(p)
		if err != nil {
			return r, "", fmt.Errorf("pattern %q: %w", p, err)
		}
		r.patterns = append(r.patterns, re)
	}
	if r.keywords == nil && len(r.patterns) == 0 {
		return r, "", errors.New("a rule needs keywords or patterns")
	}
	if r.Message == "" {
		r.Message = "matched custom rule " + r.ID
	}
	return r, str("action"), nil
}

func (g *Guard) Name() string      { return g.name }
func (g *Guard) Stage() core.Stage { return g.stage }

func (g *Guard) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	fields := tx.UserFields()
	if g.stage == core.StageOutbound {
		fields = tx.ScanFields()
	}
	for _, f := range fields {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var norm *normalize.Text
		for _, r := range g.rules {
			if r.Roles != nil && !r.Roles[f.Role] {
				continue
			}
			var spans [][2]int
			if r.keywords != nil {
				if norm == nil {
					t := normalize.Normalize(f.Text, normalize.ForTopic)
					norm = &t
				}
				for _, loc := range r.keywords.FindAllStringIndex(norm.Value, 50) {
					s, e := norm.Origin(loc[0], loc[1])
					spans = append(spans, [2]int{s, e})
				}
			}
			for _, re := range r.patterns {
				for _, loc := range re.FindAllStringIndex(f.Text, 50) {
					spans = append(spans, [2]int{loc[0], loc[1]})
				}
			}
			if len(spans) == 0 {
				continue
			}
			fd := core.NewFinding(g.name, r.ID, r.Category, r.Severity, 1.0, r.Message)
			fd.Meta = map[string]string{"rule": r.ID, "matches": fmt.Sprint(len(spans))}
			for _, sp := range dedupe(spans) {
				fd.Spans = append(fd.Spans, core.Span{Field: f.Field, Start: sp[0], End: sp[1],
					Excerpt: excerpt(f.Text, sp[0], sp[1])})
				res.Mutations = append(res.Mutations, core.Mutation{Guard: g.name, Field: f.Field,
					Start: sp[0], End: sp[1], Replacement: r.Replacement, Reason: r.Category})
			}
			res.Findings = append(res.Findings, fd)
		}
	}
	return res, nil
}

func dedupe(in [][2]int) [][2]int {
	sort.Slice(in, func(i, j int) bool { return in[i][0] < in[j][0] || (in[i][0] == in[j][0] && in[i][1] > in[j][1]) })
	var out [][2]int
	last := -1
	for _, s := range in {
		if s[0] < last || s[1] <= s[0] {
			continue
		}
		out = append(out, s)
		last = s[1]
	}
	return out
}

// excerpt masks the middle of a match so the audit log shows where a rule
// fired without storing what it matched.
func excerpt(s string, start, end int) string {
	if start < 0 || end > len(s) || end <= start {
		return ""
	}
	m := s[start:end]
	r := []rune(m)
	if len(r) <= 4 {
		return strings.Repeat("•", len(r))
	}
	return string(r[:2]) + strings.Repeat("•", min(len(r)-4, 12)) + string(r[len(r)-2:])
}
