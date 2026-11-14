package outbound

import (
	"context"
	"fmt"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/core/normalize"
)

// Leak detects the operator's own secrets coming back out in the completion.
//
// Inbound guards stop data going to the provider. This stops data coming back
// to the user, and the two are not symmetric: the most valuable thing to
// exfiltrate through a chat product is usually the system prompt itself, which
// no inbound guard would ever see as suspicious because the operator put it
// there.
//
// Detection is n-gram overlap against the actual system prompt rather than
// keyword matching. That matters because a successful extraction rarely quotes
// the prompt verbatim -- the model paraphrases, reformats as bullets, or
// translates it. Shingling catches the paraphrase; a "did they say 'system
// prompt'" check does not.
type Leak struct {
	cfg *config.GuardConfig

	ngram     int
	threshold float64
	canary    bool
}

func NewLeak(cfg *config.GuardConfig) (*Leak, error) {
	g := &Leak{
		cfg:       cfg,
		ngram:     cfg.Int("system_prompt_ngram", 8),
		threshold: cfg.Float("system_prompt_threshold", 0.35),
		canary:    cfg.Bool("canary", true),
	}
	if g.ngram < 3 {
		return nil, fmt.Errorf("leak: system_prompt_ngram must be at least 3")
	}
	if g.threshold <= 0 || g.threshold > 1 {
		return nil, fmt.Errorf("leak: system_prompt_threshold must be in (0,1]")
	}
	return g, nil
}

func (g *Leak) Name() string      { return config.GuardLeak }
func (g *Leak) Stage() core.Stage { return core.StageOutbound }

// MetaCanaryKey carries a token the operator embedded in the system prompt.
//
// A canary is the only leak check with no false positives: the token is random,
// it appears nowhere in the world except that system prompt, so a completion
// containing it is proof of extraction rather than evidence of it. Every
// operator running a prompt-based product should be using one.
const MetaCanaryKey = "canary_token"

func (g *Leak) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	if tx.Completion == "" {
		return res, nil
	}
	res.Metrics = map[string]float64{}

	if g.canary {
		if token, _ := tx.Meta[MetaCanaryKey].(string); token != "" {
			if idx := strings.Index(tx.Completion, token); idx >= 0 {
				f := core.NewFinding(g.Name(), "canary_token", "leak.canary",
					core.SeverityCritical, 1.0,
					"completion contains the system-prompt canary token")
				f.Spans = []core.Span{{
					Field: core.FieldCompletion, Start: idx, End: idx + len(token),
					Excerpt: core.Preview(token),
				}}
				res.Findings = append(res.Findings, f)
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	if tx.System != "" {
		overlap, sample := shingleOverlap(tx.System, tx.Completion, g.ngram)
		res.Metrics["leak.system_prompt_overlap"] = overlap
		if overlap >= g.threshold {
			sev := core.SeverityHigh
			if overlap >= 0.70 {
				sev = core.SeverityCritical
			}
			f := core.NewFinding(g.Name(), "system_prompt_overlap", "leak.system_prompt",
				sev, overlap,
				fmt.Sprintf("completion reproduces %.0f%% of the system prompt", overlap*100))
			f.Meta = map[string]string{
				"overlap": fmt.Sprintf("%.3f", overlap),
				"ngram":   fmt.Sprint(g.ngram),
				"sample":  truncate(sample, 80),
			}
			f.Spans = []core.Span{{Field: core.FieldCompletion}}
			res.Findings = append(res.Findings, f)
		}
	}

	// Credentials in a completion are almost always the operator's own,
	// echoed back from the system prompt or a tool result.
	for _, f := range scanCompletionSecrets(tx.Completion) {
		f.Guard = g.Name()
		res.Findings = append(res.Findings, f)
	}

	return res, nil
}

// shingleOverlap returns the fraction of the source's word n-grams that appear
// in the candidate, plus one matching n-gram as evidence.
//
// Direction matters: this asks "how much of the system prompt is in the
// output", not "how similar are these two texts". A short leak inside a long
// answer would score near zero under a symmetric measure like Jaccard, which
// is exactly the case that must be caught.
func shingleOverlap(source, candidate string, n int) (float64, string) {
	src := words(source)
	cand := words(candidate)
	if len(src) < n || len(cand) < n {
		return 0, ""
	}

	candSet := make(map[string]struct{}, len(cand))
	for i := 0; i+n <= len(cand); i++ {
		candSet[strings.Join(cand[i:i+n], " ")] = struct{}{}
	}

	seen := make(map[string]struct{}, len(src))
	matched, total := 0, 0
	sample := ""
	for i := 0; i+n <= len(src); i++ {
		g := strings.Join(src[i:i+n], " ")
		if _, dup := seen[g]; dup {
			continue // count each distinct shingle once
		}
		seen[g] = struct{}{}
		total++
		if _, ok := candSet[g]; ok {
			matched++
			if sample == "" {
				sample = g
			}
		}
	}
	if total == 0 {
		return 0, ""
	}
	return float64(matched) / float64(total), sample
}

// words tokenizes for shingling: lowercase, punctuation-free, so that
// reformatting the prompt as a bullet list does not defeat the comparison.
func words(s string) []string {
	norm := normalize.Normalize(s, normalize.ForTopic)
	return strings.FieldsFunc(norm.Value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
