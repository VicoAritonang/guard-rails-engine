package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// Pin is the hash of everything in a tool definition the model will read.
//
// The name, the description and the full input schema (property descriptions
// included) are hashed, because each of them is text that reaches the model,
// and the published rug-pull attacks hide their payload in whichever one the
// client does not show the user.
func Pin(t Tool) string {
	schema := canonicalJSON(t.InputSchema)
	sum := sha256.Sum256([]byte(t.Name + "\x00" + t.Description + "\x00" + schema))
	return hex.EncodeToString(sum[:])
}

func canonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return string(b)
}

// ScanFinding is one problem with a tool definition.
type ScanFinding struct {
	Category string `json:"category"` // mcp.tool_poisoning | mcp.tool_shadowing | mcp.rug_pull | mcp.annotation_mismatch
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

// definitionText is every string in a tool definition the model will read.
func definitionText(t Tool) string {
	var b strings.Builder
	b.WriteString(t.Description)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if k == "description" || k == "title" || k == "default" {
					if s, ok := x[k].(string); ok {
						b.WriteString("\n")
						b.WriteString(s)
					}
				}
				walk(x[k])
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var schema any
	if json.Unmarshal(t.InputSchema, &schema) == nil {
		walk(schema)
	}
	return b.String()
}

var (
	// Wrappers that hide instructions from a human skimming a tool list while
	// remaining perfectly legible to the model.
	reHiddenBlock = regexp.MustCompile(`(?is)<\s*(important|system|instructions?|secret|hidden|admin|note)\s*>|<!--.*?-->|\[\s*(system|hidden)\s*\]`)
	// Instructions to read credentials or agent configuration: the canonical
	// tool-poisoning payload exfiltrates ~/.ssh/id_rsa or the MCP config itself.
	reSensitivePath = regexp.MustCompile(`(?i)(~?/\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|\.env\b|mcp\.json|claude_desktop_config|\.cursor/|/etc/passwd|/etc/shadow|private[_ ]key|api[_ ]keys?\b|\bpasswords?\b)`)
	// Secrecy: a benign tool never needs the model to hide what it is doing.
	reSecrecy = regexp.MustCompile(`(?i)(do not|don't|never|without)\s+(tell|mention|inform|reveal|show|notify|alert|let)\w*\s+(it\s+to\s+|this\s+to\s+)?(the\s+)?(user|human|anyone)|(the\s+)?user\s+(must|should)\s+not\s+(know|see|be told)`)
	// Imperatives addressed to the model, ahead of the tool's own purpose.
	reDirective = regexp.MustCompile(`(?i)\b(before|after|when(ever)?)\s+(using|calling|you\s+(use|call)|responding|answering)\b.{0,80}\b(you\s+must|always|first|also)\b|\b(ignore|disregard|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|other|system)\b|\bas\s+an?\s+(ai|assistant|model)\b.{0,40}\b(must|should)\b`)
)

// ScanDefinition inspects one tool definition. others are the names of every
// other tool visible to the agent: a description that gives instructions
// about one of them is shadowing, the attack where a malicious server rewires
// how a TRUSTED server's tool is used without ever being called itself.
//
// rails, when set, runs the tool-result guard over the definition text as
// well. A description is attacker-authored text that the model reads as
// instructions -- structurally the same thing as a poisoned tool result -- so
// the same detector applies.
func ScanDefinition(ctx context.Context, t Tool, others []string, rails func(ctx context.Context, text string) []core.Finding) []ScanFinding {
	text := definitionText(t)
	var out []ScanFinding
	add := func(cat, sev, msg, ev string) {
		out = append(out, ScanFinding{Category: cat, Severity: sev, Message: msg, Evidence: clip(ev, 120)})
	}

	if m := reHiddenBlock.FindString(text); m != "" {
		add("mcp.tool_poisoning", "critical", "definition contains a hidden instruction block", m)
	}
	if m := reSensitivePath.FindString(text); m != "" {
		add("mcp.tool_poisoning", "critical", "definition references credentials or agent configuration", m)
	}
	if m := reSecrecy.FindString(text); m != "" {
		add("mcp.tool_poisoning", "critical", "definition tells the model to hide something from the user", m)
	}
	if m := reDirective.FindString(text); m != "" {
		add("mcp.tool_poisoning", "high", "definition gives the model behavioural instructions", m)
	}
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) || (r >= 0xE0000 && r <= 0xE007F) {
			add("mcp.tool_poisoning", "critical", "definition contains invisible format or tag characters", fmt.Sprintf("U+%04X", r))
			break
		}
	}
	low := strings.ToLower(text)
	for _, o := range others {
		if o == t.Name || len(o) < 4 {
			continue
		}
		if strings.Contains(low, strings.ToLower(o)) {
			add("mcp.tool_shadowing", "critical", fmt.Sprintf("definition gives instructions about another tool (%s)", o), o)
		}
	}
	if len(t.Description) > 2000 {
		add("mcp.tool_poisoning", "medium", fmt.Sprintf("description is unusually long (%d chars)", len(t.Description)), "")
	}
	if rails != nil {
		for _, f := range rails(ctx, text) {
			if f.Severity >= core.SeverityHigh {
				add("mcp.tool_poisoning", f.SeverityName, "tool-result rails: "+f.Message, f.Category)
			}
		}
	}
	return dedupe(out)
}

func dedupe(in []ScanFinding) []ScanFinding {
	seen := map[string]bool{}
	var out []ScanFinding
	for _, f := range in {
		k := f.Category + "|" + f.Message
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Blocking reports whether any finding is high or critical.
func Blocking(fs []ScanFinding) bool {
	for _, f := range fs {
		if f.Severity == "high" || f.Severity == "critical" {
			return true
		}
	}
	return false
}
