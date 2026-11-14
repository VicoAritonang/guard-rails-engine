package inbound

import (
	"context"
	"fmt"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/core/normalize"
)

// topicRule flags a content category the operator has chosen not to serve.
//
// A word list is a weak classifier and this one does not pretend otherwise.
// What makes it usable is the intent qualifier: "how do I make a bomb" and
// "the bomb squad defused it" share a keyword and differ entirely in shape.
// Requiring a first-person instructional frame alongside the topic keyword
// removes the large majority of false positives that make naive denylists
// unusable in production.
//
// For workloads where the cost of a miss is high, this guard should be treated
// as a cheap pre-filter in front of a real classifier, not as the classifier.
// That is a deliberate boundary: shipping a bag-of-words model and calling it
// content safety would be worse than shipping nothing, because it invites
// misplaced trust.
type topicRule struct {
	ID       string
	Category string
	Severity core.Severity
	Weight   float64
	Terms    []string
	// RequireIntent gates the rule behind an instructional frame.
	RequireIntent bool
}

// intentFrames are the phrasings that turn a topic mention into a request for
// operational help.
var intentFrames = []string{
	"how do i", "how to", "how can i", "steps to", "instructions for",
	"give me a guide", "walk me through", "teach me to", "show me how",
	"what do i need to", "recipe for", "tutorial", "step by step",
	"bagaimana cara", "cara membuat", "cara bikin", "langkah untuk", "tutorial cara",
}

var topicRules = []topicRule{
	{
		ID: "weapons", Category: "content.weapons", Severity: core.SeverityHigh, Weight: 0.75,
		RequireIntent: true,
		Terms: []string{
			"explosive device", "pipe bomb", "improvised explosive", "detonator",
			"nerve agent", "chemical weapon", "bioweapon", "untraceable firearm",
			"bahan peledak", "senjata kimia",
		},
	},
	{
		ID: "malware", Category: "content.malware", Severity: core.SeverityHigh, Weight: 0.70,
		RequireIntent: true,
		Terms: []string{
			"ransomware", "keylogger", "rootkit", "botnet", "credential stealer",
			"undetectable malware", "bypass antivirus", "privilege escalation exploit",
		},
	},
	{
		ID: "self_harm", Category: "content.self_harm", Severity: core.SeverityCritical, Weight: 0.85,
		Terms: []string{
			"kill myself", "end my life", "commit suicide", "how to overdose",
			"bunuh diri", "mengakhiri hidup",
		},
	},
	{
		ID: "csam", Category: "content.csam", Severity: core.SeverityCritical, Weight: 0.95,
		Terms: []string{"child sexual", "minor sexual", "underage sexual", "cp trade"},
	},
	{
		ID: "fraud", Category: "content.fraud", Severity: core.SeverityMedium, Weight: 0.60,
		RequireIntent: true,
		Terms: []string{
			"steal credit card", "carding", "phishing page", "fake identity documents",
			"launder money", "money laundering", "cuci uang", "pencurian identitas",
		},
	},
	{
		ID: "drugs", Category: "content.drugs", Severity: core.SeverityMedium, Weight: 0.55,
		RequireIntent: true,
		Terms: []string{
			"synthesize methamphetamine", "make meth", "cook meth", "produce fentanyl",
			"grow psilocybin", "membuat sabu",
		},
	},
}

type compiledTopic struct {
	topicRule
	folded []string
}

var compiledTopics = func() []compiledTopic {
	out := make([]compiledTopic, 0, len(topicRules))
	for _, r := range topicRules {
		ct := compiledTopic{topicRule: r, folded: make([]string, 0, len(r.Terms))}
		for _, t := range r.Terms {
			ct.folded = append(ct.folded, normalize.FoldPhrase(t))
		}
		out = append(out, ct)
	}
	return out
}()

var foldedIntentFrames = func() []string {
	out := make([]string, 0, len(intentFrames))
	for _, f := range intentFrames {
		out = append(out, normalize.FoldPhrase(f))
	}
	return out
}()

// Topic screens prompts against the operator's content policy.
type Topic struct {
	cfg *config.GuardConfig
}

func NewTopic(cfg *config.GuardConfig) (*Topic, error) { return &Topic{cfg: cfg}, nil }

func (g *Topic) Name() string      { return config.GuardTopic }
func (g *Topic) Stage() core.Stage { return core.StageInbound }

func (g *Topic) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	for _, field := range tx.UserFields() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		norm := normalize.Normalize(field.Text, normalize.ForInjection)
		if norm.Empty() {
			continue
		}
		hay := norm.Value
		hasIntent := containsAny(hay, foldedIntentFrames)

		for _, rule := range compiledTopics {
			idx, term := indexAny(hay, rule.folded)
			if idx < 0 {
				continue
			}
			score := rule.Weight
			switch {
			case rule.RequireIntent && !hasIntent:
				// Topic present but framed as discussion, not instruction.
				// Report it at reduced confidence so the policy threshold can
				// decide, rather than dropping the signal entirely.
				score *= 0.45
			case hasIntent:
				score = score + (1-score)*0.5
			}

			start, end := norm.Origin(idx, idx+len(term))
			f := core.NewFinding(g.Name(), rule.ID, rule.Category, rule.Severity, score,
				fmt.Sprintf("restricted topic %q in %s", rule.ID, field.Field))
			f.Spans = []core.Span{{
				Field: field.Field, Start: start, End: end,
				Excerpt: truncate(safeSlice(field.Text, start, end), 80),
			}}
			f.Meta = map[string]string{"intent_frame": fmt.Sprint(hasIntent)}
			res.Findings = append(res.Findings, f)
		}
	}
	return res, nil
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func indexAny(hay string, needles []string) (int, string) {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if i := strings.Index(hay, n); i >= 0 {
			return i, n
		}
	}
	return -1, ""
}
