package inbound

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/core/normalize"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards/detect"
)

// secretRule detects a credential.
//
// Unlike PII, a secret in a prompt is almost never intentional -- it is a
// developer pasting a config file to ask why it does not work. The cost of
// missing one is a live credential in a third party's request logs, which is
// why this guard defaults to fail-closed and to blocking rather than masking:
// once the key has left the building, redacting it after the fact is theatre.
type secretRule struct {
	ID       string
	Category string
	Severity core.Severity
	Pattern  *regexp.Regexp
	// MinEntropy rejects a match whose captured secret is too structured to be
	// a real key. Zero disables the check for rules whose prefix is already
	// decisive.
	MinEntropy float64
	Base       float64

	// Pre is the cheap necessary condition tested before the regex runs. Every
	// vendor credential format carries a literal prefix, which makes these
	// filters both exact and almost free.
	Pre prefilter
}

var secretRules = []secretRule{
	{
		ID: "anthropic_key", Category: "secret.api_key", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9_\-]{20,}`), Base: 0.99,
		Pre: prefilter{AnyLiteralFold: []string{"sk-ant-"}},
	},
	{
		ID: "openai_key", Category: "secret.api_key", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\bsk-(?:proj-)?[a-zA-Z0-9_\-]{20,}`), Base: 0.97,
		Pre: prefilter{AnyLiteralFold: []string{"sk-"}},
	},
	{
		ID: "aws_access_key", Category: "secret.cloud_credential", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`), Base: 0.98,
		Pre: prefilter{AnyLiteral: []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA"}},
	},
	{
		ID: "aws_secret_key", Category: "secret.cloud_credential", Severity: core.SeverityCritical,
		Pattern:    regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+([A-Za-z0-9/+=]{40})`),
		MinEntropy: 4.2, Base: 0.95,
		Pre: prefilter{AnyLiteralFold: []string{"aws_secret"}},
	},
	{
		ID: "github_token", Category: "secret.vcs_token", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`), Base: 0.98,
		Pre: prefilter{AnyLiteralFold: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat"}},
	},
	{
		ID: "gcp_key", Category: "secret.cloud_credential", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), Base: 0.97,
		Pre: prefilter{AnyLiteral: []string{"AIza"}},
	},
	{
		ID: "slack_token", Category: "secret.api_key", Severity: core.SeverityHigh,
		Pattern: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}`), Base: 0.96,
		Pre: prefilter{AnyLiteralFold: []string{"xox"}},
	},
	{
		ID: "stripe_key", Category: "secret.api_key", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}`), Base: 0.98,
		Pre: prefilter{AnyLiteralFold: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}},
	},
	{
		ID: "private_key_block", Category: "secret.private_key", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		Base:    0.99,
		Pre:     prefilter{AnyLiteralFold: []string{"private key"}},
	},
	{
		ID: "jwt", Category: "secret.token", Severity: core.SeverityHigh,
		Pattern:    regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}`),
		MinEntropy: 3.5, Base: 0.90,
		Pre: prefilter{AnyLiteral: []string{"eyJ"}},
	},
	{
		ID: "postgres_url", Category: "secret.connection_string", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+`),
		Base:    0.95,
		Pre:     prefilter{AnyLiteralFold: []string{"://"}, NeedBytes: "@"},
	},
	{
		// The generic rule. Requires an assignment-shaped context AND high
		// entropy, because "password = hunter2" is a joke and
		// "api_key: your-key-here" is documentation -- neither is a leak.
		ID: "generic_assignment", Category: "secret.generic", Severity: core.SeverityHigh,
		Pattern: regexp.MustCompile(
			`(?i)\b(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|password|passwd)\b["'\s]*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,})["']?`),
		MinEntropy: 3.6, Base: 0.72,
		Pre: prefilter{AnyLiteralFold: []string{
			"api", "secret", "token", "password", "passwd", "client"}},
	},
}

// placeholderSecrets are the values that appear in every README on earth.
//
// Every entry has to be unambiguous, because this list can only ever cause
// false negatives -- it is the one place in the guard that says "this
// key-shaped thing is not a key". Generic words were tried here and removed:
// "abcdef" as a substring rejects real hex-adjacent keys, and "test" rejects
// any credential belonging to a test environment, which is still a credential.
// Ambiguous cases are left to the entropy check instead.
var placeholderSecrets = []string{
	"your-api-key", "your_api_key", "yourapikey", "your-key-here",
	"api-key-here", "api_key_here", "insert-your", "replace-with",
	"changeme", "change_me", "placeholder", "redacted", "<your", "your-token",
	"xxxxxxxx", "aaaaaaaa", "notarealkey", "not-a-real",
}

// minPrefixedEntropy applies to rules whose prefix already proves the vendor.
// Their remaining job is to separate a real key from a documentation example
// with the same prefix, and entropy does that far more robustly than a word
// list: "sk-ant-api03-EXAMPLEEXAMPLEEXAMPLE" scores ~2.6, a real key ~4.9.
const minPrefixedEntropy = 3.0

// Secrets blocks credentials from crossing the perimeter.
type Secrets struct {
	cfg         *config.GuardConfig
	scanEncoded bool
	maxDepth    int
}

func NewSecrets(cfg *config.GuardConfig) (*Secrets, error) {
	return &Secrets{
		cfg:         cfg,
		scanEncoded: cfg.Bool("scan_encoded_layers", true),
		maxDepth:    max(cfg.Int("max_decode_depth", 2), 1),
	}, nil
}

func (g *Secrets) Name() string      { return config.GuardSecrets }
func (g *Secrets) Stage() core.Stage { return core.StageInbound }

func (g *Secrets) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	// Secrets are scanned in every field including the system prompt: an
	// operator hard-coding a key into their own system prompt is one of the
	// most common ways credentials reach a provider.
	for _, field := range tx.ScanFields() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		g.scanView(field.Field, field.Text, nil, &res)

		// A base64-wrapped credential still reaches the provider intact.
		if g.scanEncoded {
			for _, layer := range normalize.DecodeLayers(field.Text, g.maxDepth) {
				if !valueSafeLayer(layer) {
					continue
				}
				l := layer
				g.scanView(field.Field, l.Text, &l, &res)
			}
		}
	}
	return res, nil
}

// scanView applies the rule table to one view of a field. A non-nil layer means
// text is decoded plaintext; findings are then attributed to the encoded region.
func (g *Secrets) scanView(field, text string, layer *normalize.Layer, res *core.Result) {
	stats := computeStats(text)
	for _, rule := range secretRules {
		if !rule.Pre.pass(stats) {
			continue
		}
		for _, loc := range rule.Pattern.FindAllStringSubmatchIndex(text, 32) {
			// Score the captured group when the rule has one, since that is
			// the actual secret; the surrounding "api_key=" is low-entropy by
			// construction and would drag the average down.
			candidate := text[loc[0]:loc[1]]
			if len(loc) >= 4 && loc[2] >= 0 {
				candidate = text[loc[2]:loc[3]]
			}
			if isPlaceholder(candidate) {
				continue
			}
			minEntropy := rule.MinEntropy
			if minEntropy == 0 && rule.ID != "private_key_block" {
				// A PEM header carries no entropy and needs none; every other
				// rule benefits from the documentation-example check.
				minEntropy = minPrefixedEntropy
			}
			if minEntropy > 0 && detect.ShannonEntropy(candidate) < minEntropy {
				continue
			}

			start, end := loc[0], loc[1]
			msg := fmt.Sprintf("credential (%s) detected in %s", rule.ID, field)
			if layer != nil {
				start, end = layer.SrcStart, layer.SrcEnd
				msg = fmt.Sprintf("credential (%s) detected in %s inside a %s-encoded payload",
					rule.ID, field, layer.Kind)
			}

			f := core.NewFinding(g.Name(), rule.ID, rule.Category, rule.Severity, rule.Base, msg)
			f.Spans = []core.Span{{
				Field: field, Start: start, End: end,
				Excerpt: core.Preview(candidate),
			}}
			f.Meta = map[string]string{
				"entropy": fmt.Sprintf("%.2f", detect.ShannonEntropy(candidate)),
				"length":  fmt.Sprint(len(candidate)),
			}
			if layer != nil {
				f.Meta["surface"] = layer.Kind
			}
			res.Findings = append(res.Findings, f)

			// A mutation is offered so that a policy which downgrades this
			// guard to "redact" still has something to apply. Under the
			// default policy the action is block and the pipeline discards
			// these unused mutations.
			res.Mutations = append(res.Mutations, core.Mutation{
				Guard: g.Name(), Field: field,
				Start: start, End: end,
				Replacement: "[REDACTED_CREDENTIAL]",
				Reason:      rule.Category,
			})
		}
	}
}

func isPlaceholder(s string) bool {
	low := strings.ToLower(s)
	for _, p := range placeholderSecrets {
		if strings.Contains(low, p) {
			return true
		}
	}
	// A value that is one repeated character is never a key.
	if len(low) > 0 {
		same := true
		for i := 1; i < len(low); i++ {
			if low[i] != low[0] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}
