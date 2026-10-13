// Package eval measures whether the guardrails actually work.
//
// A guardrail with no evaluation is a claim, not a control. This package turns
// the claim into numbers: precision and recall per detection family, false
// positives on benign traffic, latency percentiles against the stated budget,
// and a threshold sweep that shows the trade every tuning decision is making.
//
// The numbers are only as good as the corpus. testdata/eval is small and
// hand-built, so treat the absolute figures as a regression baseline rather
// than a benchmark claim -- what matters is that the same corpus, scored the
// same way, tells you immediately when a change makes detection worse.
package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// Case is one labelled example.
type Case struct {
	ID    string     `json:"id"`
	Stage core.Stage `json:"stage"`
	Tags  []string   `json:"tags,omitempty"`

	// Labels are the detection families that SHOULD fire, e.g. ["injection"].
	// An empty list means the case is benign, which is the most important
	// kind of case: false positives are what get a guardrail switched off.
	Labels []string `json:"labels"`

	// ExpectAction optionally pins the enforcement outcome. Detection and
	// enforcement are scored separately because they fail differently -- a
	// detector can be right while the policy mapping is wrong.
	ExpectAction core.Action `json:"expect_action,omitempty"`

	Input CaseInput `json:"input"`

	// Source records where a red-team variant came from, so a report can show
	// "this evasion of case inj-004" rather than an opaque id.
	Source  string `json:"source,omitempty"`
	Variant string `json:"variant,omitempty"`
}

// CaseInput is the payload under test.
type CaseInput struct {
	Model      string          `json:"model,omitempty"`
	System     string          `json:"system,omitempty"`
	Messages   []core.Message  `json:"messages,omitempty"`
	Completion string          `json:"completion,omitempty"`
	Context    []string        `json:"context,omitempty"`
	ToolCalls  []core.ToolCall `json:"tool_calls,omitempty"`
	History    []core.ToolCall `json:"history,omitempty"`
	Step       int             `json:"step,omitempty"`
	Meta       map[string]any  `json:"meta,omitempty"`

	// ToolResults feeds the tool-result stage.
	ToolResults []core.ToolResult `json:"tool_results,omitempty"`

	// Session carries accumulated agent state. Tool-stage cases need it: a
	// call is not judged on its own, and a corpus that could not express
	// "this session already read a customer record and then fetched a web
	// page" could not test the controls that exist for exactly that shape.
	Session *core.SessionState `json:"session,omitempty"`
}

// Dataset is a labelled corpus.
type Dataset struct {
	Name  string
	Cases []Case
}

// LoadDataset reads one JSONL file or every .jsonl file in a directory.
func LoadDataset(path string) (*Dataset, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("eval: %w", err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
		if len(files) == 0 {
			return nil, fmt.Errorf("eval: no .jsonl files in %s", path)
		}
	} else {
		files = []string{path}
	}

	ds := &Dataset{Name: filepath.Base(path)}
	seen := map[string]string{}
	for _, f := range files {
		cases, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		for _, c := range cases {
			// Duplicate ids silently overwrite each other in any map-based
			// aggregation, which quietly shrinks the corpus. Fail instead.
			if prev, dup := seen[c.ID]; dup {
				return nil, fmt.Errorf("eval: duplicate case id %q in %s and %s", c.ID, prev, f)
			}
			seen[c.ID] = f
			ds.Cases = append(ds.Cases, c)
		}
	}
	return ds, nil
}

func loadFile(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	defer f.Close()

	var out []Case
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "//") || strings.HasPrefix(text, "#") {
			continue
		}
		var c Case
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields() // a mistyped field is a silently mislabelled case
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("eval: %s line %d: %w", path, line, err)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("eval: %s line %d: %w", path, line, err)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

func (c *Case) validate() error {
	if c.ID == "" {
		return fmt.Errorf("case is missing an id")
	}
	if !c.Stage.Valid() {
		return fmt.Errorf("case %s: invalid stage %q", c.ID, c.Stage)
	}
	switch c.Stage {
	case core.StageInbound:
		if len(c.Input.Messages) == 0 {
			return fmt.Errorf("case %s: inbound case has no messages", c.ID)
		}
	case core.StageOutbound:
		if c.Input.Completion == "" {
			return fmt.Errorf("case %s: outbound case has no completion", c.ID)
		}
	case core.StageRuntime:
		if len(c.Input.ToolCalls) == 0 && c.Input.Step == 0 {
			return fmt.Errorf("case %s: runtime case has neither tool calls nor a step", c.ID)
		}
	case core.StageToolResult:
		if len(c.Input.ToolResults) == 0 {
			return fmt.Errorf("case %s: tool_result case has no tool results", c.ID)
		}
	}
	for _, l := range c.Labels {
		if l == "" {
			return fmt.Errorf("case %s: empty label", c.ID)
		}
	}
	return nil
}

// Transaction materialises the case as a pipeline input.
func (c *Case) Transaction(secret []byte) *core.Transaction {
	return &core.Transaction{
		ID:          c.ID,
		Stage:       c.Stage,
		Model:       orDefault(c.Input.Model, "claude-opus-5"),
		System:      c.Input.System,
		Messages:    append([]core.Message(nil), c.Input.Messages...),
		Completion:  c.Input.Completion,
		Context:     c.Input.Context,
		ToolCalls:   append([]core.ToolCall(nil), c.Input.ToolCalls...),
		History:     append([]core.ToolCall(nil), c.Input.History...),
		ToolResults: append([]core.ToolResult(nil), c.Input.ToolResults...),
		Step:        c.Input.Step,
		Meta:        c.Input.Meta,
		// Cloned so a case that mutates session state cannot leak into a
		// re-run of the same corpus, which would make the report depend on
		// how many times it had been generated.
		Session: c.Input.Session.Clone(),
		Vault:   core.NewVault(secret),
	}
}

// Benign reports whether nothing should fire on this case.
func (c *Case) Benign() bool { return len(c.Labels) == 0 }

// Families returns the sorted, deduplicated label set.
func (c *Case) Families() []string {
	seen := map[string]struct{}{}
	for _, l := range c.Labels {
		seen[l] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// FamilyOf maps a finding category to its detection family: the segment before
// the first dot. "pii.credit_card" and "pii.email" both belong to "pii", which
// is the granularity a dataset can realistically be labelled at.
func FamilyOf(category string) string {
	if i := strings.Index(category, "."); i > 0 {
		return category[:i]
	}
	return category
}

// Stats summarises a corpus.
func (d *Dataset) Stats() map[string]int {
	out := map[string]int{"total": len(d.Cases)}
	for _, c := range d.Cases {
		out["stage:"+string(c.Stage)]++
		if c.Benign() {
			out["benign"]++
			continue
		}
		out["adversarial"]++
		for _, f := range c.Families() {
			out["label:"+f]++
		}
	}
	return out
}

// Families lists every label family present in the corpus.
func (d *Dataset) Families() []string {
	seen := map[string]struct{}{}
	for _, c := range d.Cases {
		for _, f := range c.Families() {
			seen[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
