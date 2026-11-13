package outbound

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// Grounding flags sentences in a RAG answer that the retrieved context does
// not support.
//
// The honest framing matters more here than anywhere else in this engine.
// Lexical overlap is not entailment. This guard cannot tell you an answer is
// true; it tells you which sentences share no vocabulary with the documents
// the model was given, which is a strong signal that the model is drawing on
// parametric memory rather than the provided sources. That is a genuinely
// useful thing to surface to a reviewer and a genuinely bad thing to enforce
// with a block, which is why it defaults to disabled and to "flag".
//
// For a real entailment check, route flagged sentences to an LLM judge. This
// guard's job is to make that affordable by cutting the candidate set from
// every sentence to the handful worth paying for.
type Grounding struct {
	cfg       *config.GuardConfig
	threshold float64
	minWords  int
}

func NewGrounding(cfg *config.GuardConfig) (*Grounding, error) {
	g := &Grounding{
		cfg:       cfg,
		threshold: cfg.Threshold,
		minWords:  cfg.Int("min_sentence_words", 6),
	}
	if g.threshold <= 0 {
		g.threshold = 0.30
	}
	return g, nil
}

func (g *Grounding) Name() string      { return config.GuardGrounding }
func (g *Grounding) Stage() core.Stage { return core.StageOutbound }

func (g *Grounding) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	if tx.Completion == "" || len(tx.Context) == 0 {
		return res, nil // no retrieved context: nothing to be grounded against
	}

	// Build the context vocabulary once. Content words only: matching on
	// "the" and "is" would make every sentence look supported.
	vocab := map[string]struct{}{}
	for _, doc := range tx.Context {
		for _, w := range words(doc) {
			if !isStopword(w) && len(w) > 2 {
				vocab[w] = struct{}{}
			}
		}
	}
	if len(vocab) == 0 {
		return res, nil
	}

	sentences := splitSentences(tx.Completion)
	var unsupported, scored int
	var worst float64 = 1

	for _, s := range sentences {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		content := contentWords(s.text)
		if len(content) < g.minWords {
			continue // too short to score meaningfully
		}
		scored++

		hits := 0
		for _, w := range content {
			if _, ok := vocab[w]; ok {
				hits++
			}
		}
		support := float64(hits) / float64(len(content))
		if support >= g.threshold {
			continue
		}
		unsupported++
		if support < worst {
			worst = support
		}

		f := core.NewFinding(g.Name(), "unsupported_sentence", "grounding.unsupported",
			core.SeverityMedium, 1-support,
			fmt.Sprintf("sentence shares only %.0f%% of its content words with the retrieved context", support*100))
		f.Spans = []core.Span{{
			Field: core.FieldCompletion, Start: s.start, End: s.end,
			Excerpt: truncate(s.text, 160),
		}}
		f.Meta = map[string]string{"support": fmt.Sprintf("%.3f", support)}
		res.Findings = append(res.Findings, f)
	}

	res.Metrics = map[string]float64{
		"grounding.sentences_scored": float64(scored),
		"grounding.unsupported":      float64(unsupported),
	}
	if scored > 0 {
		res.Metrics["grounding.unsupported_ratio"] = float64(unsupported) / float64(scored)
	}
	return res, nil
}

type sentence struct {
	text  string
	start int
	end   int
}

var reSentenceEnd = regexp.MustCompile(`[.!?\n]+\s*`)

// splitSentences segments while preserving byte offsets, so a flagged sentence
// can be pointed at precisely in the original completion.
func splitSentences(s string) []sentence {
	var out []sentence
	start := 0
	for _, loc := range reSentenceEnd.FindAllStringIndex(s, -1) {
		end := loc[1]
		text := strings.TrimSpace(s[start:end])
		if text != "" {
			out = append(out, sentence{text: text, start: start, end: end})
		}
		start = end
	}
	if start < len(s) {
		if text := strings.TrimSpace(s[start:]); text != "" {
			out = append(out, sentence{text: text, start: start, end: len(s)})
		}
	}
	return out
}

func contentWords(s string) []string {
	var out []string
	for _, w := range words(s) {
		if len(w) > 2 && !isStopword(w) {
			out = append(out, w)
		}
	}
	return out
}

// stopwords covers English and Indonesian, since a bilingual product is the
// realistic case for this codebase.
var stopwords = map[string]struct{}{}

func init() {
	list := strings.Fields(`
		the and for are but not you all any can had her was one our out day get has him his how
		its may new now old see two who did yes his been have this that with from they will
		would there their what about which when make like time just know take into your some
		could them than then only other more some such these those very were
		yang dan di ke dari untuk pada dengan adalah ini itu tidak akan bisa sudah juga
		atau karena oleh dalam saya kami kita mereka anda dia ada agar bagi sebagai
	`)
	for _, w := range list {
		stopwords[w] = struct{}{}
	}
}

func isStopword(w string) bool {
	_, ok := stopwords[w]
	return ok
}
