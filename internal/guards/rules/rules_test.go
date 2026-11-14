package rules

import (
	"context"
	"testing"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

func TestKeywordSurvivesHomoglyphsAndPatternMatches(t *testing.T) {
	cfg := &config.GuardConfig{Enabled: true, Params: map[string]any{"rules": []any{
		map[string]any{"id": "competitor", "keywords": []any{"globex"}, "action": "redact"},
		map[string]any{"id": "codename", "patterns": []any{`(?i)project\s+bluebird`}, "severity": "high"},
	}}}
	g, err := New(config.GuardCustomRules, core.StageInbound, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Categories["custom.competitor"].Action != "redact" {
		t.Errorf("rule action not written into categories: %+v", cfg.Categories)
	}
	tx := &core.Transaction{Stage: core.StageInbound, Messages: []core.Message{
		{Role: core.RoleUser, Content: "Is Glоbex cheaper? Ask about Project Bluebird."}, // Cyrillic о
	}}
	res, err := g.Check(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	if !got["competitor"] || !got["codename"] {
		t.Fatalf("rules did not fire: %+v", res.Findings)
	}
}

func TestURLFilter(t *testing.T) {
	cfg := &config.GuardConfig{Enabled: true, Params: map[string]any{"allow": []any{"example.com"}}}
	g, err := NewURLFilter(config.GuardURLFilterOutbound, core.StageOutbound, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"https://docs.example.com/a":        "",
		"https://evil.io/x":                 "url.not_allowed",
		"https://example.com@evil.io/login": "url.userinfo",
		"http://example.com/":               "url.scheme",
		"https://169.254.169.254/latest":    "url.private_address",
	}
	for url, want := range cases {
		tx := &core.Transaction{Stage: core.StageOutbound, Completion: "see " + url}
		res, _ := g.Check(context.Background(), tx)
		got := ""
		if len(res.Findings) > 0 {
			got = res.Findings[0].Category
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", url, got, want)
		}
	}
}
