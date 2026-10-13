// Package outbound implements the post-model interception layer: what must be
// true about a completion before it reaches the caller.
package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// Schema enforces that a completion is the JSON document the caller asked for.
//
// Structured outputs on the provider side already constrain generation, and
// where they are available they are strictly better than validating after the
// fact. This guard exists for the cases they do not cover: a provider without
// them, a model behind a proxy the caller does not control, or a schema the
// provider's constrained decoding rejects. In those cases the realistic failure
// is not "the model produced invalid JSON" -- it is "the model produced valid
// JSON wrapped in a markdown fence and a sentence of preamble", which is why
// repair runs before validation.
type Schema struct {
	cfg    *config.GuardConfig
	repair bool
}

func NewSchema(cfg *config.GuardConfig) (*Schema, error) {
	return &Schema{cfg: cfg, repair: cfg.Bool("repair", true)}, nil
}

func (g *Schema) Name() string      { return config.GuardSchema }
func (g *Schema) Stage() core.Stage { return core.StageOutbound }

// MetaSchemaKey is the transaction metadata key carrying the expected schema.
// The caller supplies it per request, because a schema is a property of the
// call site, not of the deployment.
const MetaSchemaKey = "response_schema"

func (g *Schema) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	raw, ok := tx.Meta[MetaSchemaKey]
	if !ok || tx.Completion == "" {
		return res, nil // nothing declared: not this guard's business
	}
	schema, err := toSchema(raw)
	if err != nil {
		// A malformed schema is the caller's bug, and reporting it as a finding
		// (rather than a guard error) puts it in front of the person who can
		// fix it instead of burying it in the gateway's own logs.
		f := core.NewFinding(g.Name(), "invalid_schema", "schema.invalid_declaration",
			core.SeverityMedium, 1.0, "declared response_schema is not valid: "+err.Error())
		res.Findings = append(res.Findings, f)
		return res, nil
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	body := tx.Completion
	repaired := false
	if g.repair {
		if fixed, changed := RepairJSON(body); changed {
			body, repaired = fixed, true
		}
	}

	var doc any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		f := core.NewFinding(g.Name(), "unparseable", "schema.parse_error",
			core.SeverityHigh, 1.0, "completion is not valid JSON: "+err.Error())
		f.Spans = []core.Span{{Field: core.FieldCompletion, Start: 0, End: min(len(tx.Completion), 200)}}
		f.Meta = map[string]string{"repair_attempted": fmt.Sprint(g.repair)}
		res.Findings = append(res.Findings, f)
		return res, nil
	}

	if violations := schema.Validate(doc, "$"); len(violations) > 0 {
		sort.Strings(violations)
		if len(violations) > 8 {
			violations = append(violations[:8], fmt.Sprintf("(+%d more)", len(violations)-8))
		}
		f := core.NewFinding(g.Name(), "schema_violation", "schema.violation",
			core.SeverityHigh, 1.0,
			"completion does not satisfy the declared schema: "+strings.Join(violations, "; "))
		f.Spans = []core.Span{{Field: core.FieldCompletion}}
		res.Findings = append(res.Findings, f)
		return res, nil
	}

	if repaired {
		// The document is valid but only after repair. Rewriting the completion
		// is the point -- the caller asked for JSON and should receive JSON --
		// but it is reported so that a persistently-fenced model shows up in
		// telemetry rather than being silently patched forever.
		f := core.NewFinding(g.Name(), "repaired", "schema.repaired",
			core.SeverityLow, 1.0, "completion required repair before it parsed as JSON")
		res.Findings = append(res.Findings, f)
		res.Mutations = append(res.Mutations, core.Mutation{
			Guard: g.Name(), Field: core.FieldCompletion,
			Start: 0, End: len(tx.Completion),
			Replacement: body, Reason: "schema.repaired",
		})
	}
	return res, nil
}

var (
	reFence      = regexp.MustCompile("(?s)```(?:json|JSON)?\\s*(.*?)\\s*```")
	reTrailingCm = regexp.MustCompile(`,(\s*[}\]])`)
)

// RepairJSON applies the small, safe fixes that turn a model's prose-wrapped
// answer into a parseable document. It never invents structure: if none of the
// repairs yield valid JSON, the original string is returned unchanged so the
// caller sees the model's real output in the error.
func RepairJSON(s string) (string, bool) {
	original := s
	candidate := strings.TrimSpace(s)

	if json.Valid([]byte(candidate)) {
		return original, false
	}

	// 1. Unwrap a markdown fence.
	if m := reFence.FindStringSubmatch(candidate); m != nil {
		candidate = strings.TrimSpace(m[1])
		if json.Valid([]byte(candidate)) {
			return candidate, true
		}
	}

	// 2. Extract the outermost balanced object or array, discarding preamble
	//    like "Here is the JSON you asked for:".
	if extracted, ok := extractBalanced(candidate); ok {
		if json.Valid([]byte(extracted)) {
			return extracted, true
		}
		candidate = extracted
	}

	// 3. Drop trailing commas, the single most common syntax error in
	//    model-generated JSON.
	if fixed := reTrailingCm.ReplaceAllString(candidate, "$1"); fixed != candidate {
		if json.Valid([]byte(fixed)) {
			return fixed, true
		}
	}

	return original, false
}

// extractBalanced finds the first {...} or [...] region with balanced
// delimiters, respecting string literals and escapes so that a brace inside a
// string does not throw off the count.
func extractBalanced(s string) (string, bool) {
	start := -1
	var open, close byte
	for i := 0; i < len(s); i++ {
		if s[i] == '{' {
			start, open, close = i, '{', '}'
			break
		}
		if s[i] == '[' {
			start, open, close = i, '[', ']'
			break
		}
	}
	if start < 0 {
		return "", false
	}

	depth := 0
	inString, escaped := false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// delimiters inside strings do not count
		case c == open:
			depth++
		case c == close:
			depth--
			if depth == 0 {
				return s[start : i+1], true
			}
		}
	}
	return "", false
}
