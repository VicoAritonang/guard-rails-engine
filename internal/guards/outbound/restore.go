package outbound

import (
	"context"
	"regexp"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards/detect"
)

// Restore substitutes vaulted values back into the completion.
//
// This is the second half of the redaction round-trip and the reason inbound
// masking is usable at all. The user asked "does this card ending 4242 have a
// dispute", the model reasoned over [[PII:CARD:a1b2c3d4]], and the answer
// should mention the card the user actually asked about -- not a placeholder.
//
// It restores only tokens this request's vault issued. A model that invents a
// plausible-looking placeholder gets nothing back, which means this guard can
// never be turned into an oracle for data the model was not shown.
//
// Operators with a strict posture disable it (see StrictPolicy): in that
// configuration the masked value never comes back, and the caller is expected
// to rehydrate on their own side of the trust boundary.
type Restore struct {
	cfg *config.GuardConfig
}

func NewRestore(cfg *config.GuardConfig) (*Restore, error) { return &Restore{cfg: cfg}, nil }

func (g *Restore) Name() string      { return config.GuardRestore }
func (g *Restore) Stage() core.Stage { return core.StageOutbound }

func (g *Restore) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	if tx.Completion == "" || tx.Vault == nil || tx.Vault.Len() == 0 {
		return res, nil
	}
	_ = ctx

	restored, n := tx.Vault.Restore(tx.Completion)
	if n == 0 {
		return res, nil
	}

	f := core.NewFinding(g.Name(), "vault_restore", "privacy.restore",
		core.SeverityInfo, 1.0,
		"restored masked values in the completion")
	f.Meta = map[string]string{"count": itoa(n)}
	res.Findings = append(res.Findings, f)

	res.Mutations = append(res.Mutations, core.Mutation{
		Guard: g.Name(), Field: core.FieldCompletion,
		Start: 0, End: len(tx.Completion),
		Replacement: restored, Reason: "privacy.restore",
	})
	res.Metrics = map[string]float64{"restore.count": float64(n)}
	return res, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// completionSecretRules mirror the inbound secret patterns but are scoped to
// the credentials that realistically appear in a model's output: keys echoed
// from a system prompt or returned in a tool result.
var completionSecretRules = []struct {
	id         string
	category   string
	severity   core.Severity
	pattern    *regexp.Regexp
	minEntropy float64
}{
	{"anthropic_key", "leak.api_key", core.SeverityCritical,
		regexp.MustCompile(`sk-ant-[a-zA-Z0-9_\-]{20,}`), 0},
	{"openai_key", "leak.api_key", core.SeverityCritical,
		regexp.MustCompile(`\bsk-(?:proj-)?[a-zA-Z0-9_\-]{20,}`), 0},
	{"aws_access_key", "leak.cloud_credential", core.SeverityCritical,
		regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github_token", "leak.vcs_token", core.SeverityCritical,
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`), 0},
	{"private_key_block", "leak.private_key", core.SeverityCritical,
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`), 0},
	{"jwt", "leak.token", core.SeverityHigh,
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}`), 3.5},
	{"connection_string", "leak.connection_string", core.SeverityCritical,
		regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s:@/]+@[^\s/]+`), 0},
}

// scanCompletionSecrets finds credentials in model output.
func scanCompletionSecrets(completion string) []core.Finding {
	var out []core.Finding
	for _, rule := range completionSecretRules {
		for _, loc := range rule.pattern.FindAllStringIndex(completion, 16) {
			match := completion[loc[0]:loc[1]]
			if rule.minEntropy > 0 && detect.ShannonEntropy(match) < rule.minEntropy {
				continue
			}
			if strings.Contains(strings.ToLower(match), "example") {
				continue
			}
			f := core.NewFinding("", rule.id, rule.category, rule.severity, 0.95,
				"completion contains a credential ("+rule.id+")")
			f.Spans = []core.Span{{
				Field: core.FieldCompletion, Start: loc[0], End: loc[1],
				Excerpt: core.Preview(match),
			}}
			out = append(out, f)
		}
	}
	return out
}
