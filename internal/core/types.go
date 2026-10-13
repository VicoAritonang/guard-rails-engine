// Package core defines the contracts every guardrail implements and the
// pipeline that executes them. It is intentionally free of I/O so that the
// interception layers stay stateless and trivially unit-testable.
package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Stage identifies one of the three interception points in the request
// lifecycle. A guard declares exactly one stage; the pipeline never runs a
// guard outside the stage it was registered for.
type Stage string

const (
	// StageInbound runs before the prompt reaches the model provider.
	StageInbound Stage = "inbound"
	// StageRuntime runs between agent loop iterations, on a tool call that has
	// been proposed but not yet executed. This is the last point at which a
	// side effect can still be prevented.
	StageRuntime Stage = "runtime"
	// StageToolResult runs on what a tool returned, before that text is fed
	// back to the model.
	//
	// This stage exists because a tool result is untrusted input that the user
	// never wrote and never saw. A retrieved web page, an email body, a row
	// out of a shared database: each can carry instructions aimed at the model
	// rather than data aimed at the user. Treating tool output as trusted
	// because it came from "our" tool is the single most common way an agent
	// gets hijacked, and no inbound rail ever sees it.
	StageToolResult Stage = "tool_result"
	// StageOutbound runs on the model completion before it reaches the caller.
	StageOutbound Stage = "outbound"
)

func (s Stage) Valid() bool {
	switch s {
	case StageInbound, StageRuntime, StageToolResult, StageOutbound:
		return true
	}
	return false
}

// Stages lists every interception point in execution order.
func Stages() []Stage {
	return []Stage{StageInbound, StageRuntime, StageToolResult, StageOutbound}
}

// Action is the enforcement outcome. The zero value is ActionAllow so that a
// guard returning an empty Result is a no-op.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionFlag   Action = "flag"   // observe only: emit telemetry, do not alter traffic
	ActionRedact Action = "redact" // rewrite the payload in place, then continue
	ActionBlock  Action = "block"  // terminate the request with a policy error
)

// rank orders actions so that the pipeline can escalate monotonically: the
// final decision is the strongest action any guard asked for.
func (a Action) rank() int {
	switch a {
	case ActionFlag:
		return 1
	case ActionRedact:
		return 2
	case ActionBlock:
		return 3
	default:
		return 0
	}
}

// Escalate returns whichever of the two actions is more restrictive.
func (a Action) Escalate(b Action) Action {
	if b.rank() > a.rank() {
		return b
	}
	if a == "" {
		return ActionAllow
	}
	return a
}

func ParseAction(s string) (Action, error) {
	switch a := Action(strings.ToLower(strings.TrimSpace(s))); a {
	case ActionAllow, ActionFlag, ActionRedact, ActionBlock:
		return a, nil
	case "":
		return ActionAllow, nil
	default:
		return "", fmt.Errorf("unknown action %q (want allow|flag|redact|block)", s)
	}
}

// Severity grades a finding independently of the action taken on it. Policy
// maps severity to action, which is what lets one detector serve both a
// permissive consumer tenant and a strict enterprise tenant.
type Severity int

const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical", "crit":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q", s)
	}
}

// Span locates a detection inside a specific field of the transaction, using
// byte offsets into the *original* (pre-normalization) text. Guards that match
// against a normalized view are responsible for mapping offsets back; see
// internal/core/normalize.
type Span struct {
	Field   string `json:"field"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Excerpt string `json:"excerpt,omitempty"` // redacted preview, safe to log
}

// Finding is a single detection produced by a guard.
type Finding struct {
	Guard        string            `json:"guard"`
	Rule         string            `json:"rule"`
	Category     string            `json:"category"` // dotted taxonomy, e.g. "pii.credit_card"
	Severity     Severity          `json:"-"`
	SeverityName string            `json:"severity"`
	Score        float64           `json:"score"` // calibrated confidence in [0,1]
	Message      string            `json:"message"`
	Spans        []Span            `json:"spans,omitempty"`
	Meta         map[string]string `json:"meta,omitempty"`
}

// NewFinding builds a Finding with the JSON-facing severity name kept in sync.
func NewFinding(guard, rule, category string, sev Severity, score float64, msg string) Finding {
	return Finding{
		Guard:    guard,
		Rule:     rule,
		Category: category,
		Severity: sev, SeverityName: sev.String(),
		Score:   score,
		Message: msg,
	}
}

// Mutation is a *described* edit rather than an applied one. Detectors run
// concurrently and must not race on the transaction, so they return mutations
// and the pipeline applies them serially in a deterministic order.
type Mutation struct {
	Guard       string `json:"guard"`
	Field       string `json:"field"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
	Reason      string `json:"reason,omitempty"`
}

// Role mirrors the chat roles the engine understands.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// Message is one chat turn.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`

	// ToolCalls are the calls an assistant turn proposed, and ToolCallID ties a
	// tool turn back to the call it answers. Both exist so an agent transcript
	// can round-trip through the gateway: a function-calling API rejects a tool
	// result whose call it never saw.
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall is a tool invocation proposed by the model, inspected at the runtime
// stage before it is allowed to execute.
type ToolCall struct {
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Raw       string         `json:"raw,omitempty"` // verbatim JSON, scanned as text
}

// Origin records where a piece of content came from, which decides how much
// authority it is allowed to have over the agent.
//
// The distinction that matters is not "internal vs external" but "who could
// have written this". A row from our own database is external content the
// moment a customer can put text in it.
type Origin string

const (
	// OriginOperator is content authored by whoever configured the agent.
	// Only the system prompt qualifies.
	OriginOperator Origin = "operator"
	// OriginUser is content the human in the conversation typed. Trusted to
	// express intent, never trusted to grant privilege.
	OriginUser Origin = "user"
	// OriginTool is content a tool returned. Never trusted as instruction.
	OriginTool Origin = "tool"
	// OriginWeb is content fetched from the public internet: tool content with
	// the widest possible authorship.
	OriginWeb Origin = "web"
)

// Untrusted reports whether content of this origin is attacker-authorable on
// the strength of its origin alone.
//
// Only OriginWeb qualifies. OriginTool deliberately does not, and the
// distinction is the whole point: whether a tool's output is attacker-authorable
// is a property of that specific tool, declared once in the catalog, not
// something that can be inferred from "it came back from a tool". get_customer
// returns a row we wrote; read_email returns whatever a stranger sent; both are
// tool results. Treating every tool result as untrusted would mark the
// exfiltration trifecta complete on the first read of the session's own data,
// which is a critical finding on an agent that has done nothing -- and a
// control that fires on everything is a control that gets switched off.
func (o Origin) Untrusted() bool { return o == OriginWeb }

// ToolResult is what a tool returned, inspected at the tool-result stage before
// it is appended to the model's context.
type ToolResult struct {
	CallID  string `json:"call_id,omitempty"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`

	// Origin defaults to OriginTool when empty. A fetch tool should set
	// OriginWeb so that the result rails apply the stricter prior.
	Origin Origin `json:"origin,omitempty"`

	// Sensitive marks a result that carried private data out of a system of
	// record. It is what the trifecta guard counts as "read private data".
	Sensitive bool `json:"sensitive,omitempty"`
}

// Usage carries token accounting for cost attribution.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_input_tokens,omitempty"`
	CacheWriteTokens int `json:"cache_creation_input_tokens,omitempty"`
}

func (u Usage) Add(o Usage) Usage {
	return Usage{
		InputTokens:      u.InputTokens + o.InputTokens,
		OutputTokens:     u.OutputTokens + o.OutputTokens,
		CacheReadTokens:  u.CacheReadTokens + o.CacheReadTokens,
		CacheWriteTokens: u.CacheWriteTokens + o.CacheWriteTokens,
	}
}

// Transaction is the mutable unit of work flowing through a stage. One
// Transaction is owned by exactly one goroutine at a time: detectors read it
// concurrently, the pipeline writes it serially.
type Transaction struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant,omitempty"`
	Stage  Stage  `json:"stage"`
	Model  string `json:"model,omitempty"`

	System   string    `json:"system,omitempty"`
	Messages []Message `json:"messages,omitempty"`

	// Runtime-stage inputs.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	Step      int        `json:"step,omitempty"`
	History   []ToolCall `json:"history,omitempty"` // prior calls in this agent trace

	// Tool-result-stage inputs.
	ToolResults []ToolResult `json:"tool_results,omitempty"`

	// Session is the agent's accumulated state across the trace. It is carried
	// on the transaction rather than held by the engine so that the guards stay
	// stateless and the gateway stays horizontally scalable; the caller owns
	// the state and passes it back each step.
	Session *SessionState `json:"session,omitempty"`

	// Outbound-stage inputs.
	Completion string   `json:"completion,omitempty"`
	Context    []string `json:"context,omitempty"` // retrieved documents for groundedness

	Usage     Usage          `json:"usage,omitzero"`
	CostUSD   float64        `json:"cost_usd,omitempty"`
	StartedAt time.Time      `json:"started_at,omitzero"`
	Meta      map[string]any `json:"meta,omitempty"`

	// Vault survives across stages within one request so that values masked
	// inbound can be restored outbound.
	Vault *Vault `json:"-"`
}

// FieldValue is a named, scannable piece of text within a transaction.
type FieldValue struct {
	Field string
	Role  Role
	Text  string
}

const (
	FieldSystem     = "system"
	FieldCompletion = "completion"
)

func msgField(i int) string    { return fmt.Sprintf("messages[%d].content", i) }
func toolField(i int) string   { return fmt.Sprintf("tool_calls[%d].raw", i) }
func resultField(i int) string { return fmt.Sprintf("tool_results[%d].content", i) }

// ScanFields returns every text field a guard at this stage should inspect.
// Keeping this in one place means adding a new payload shape does not require
// touching every guard.
func (t *Transaction) ScanFields() []FieldValue {
	var out []FieldValue
	switch t.Stage {
	case StageInbound:
		if t.System != "" {
			out = append(out, FieldValue{Field: FieldSystem, Role: RoleSystem, Text: t.System})
		}
		for i, m := range t.Messages {
			out = append(out, FieldValue{Field: msgField(i), Role: m.Role, Text: m.Content})
		}
	case StageRuntime:
		for i, c := range t.ToolCalls {
			raw := c.Raw
			if raw == "" {
				raw = c.Name
			}
			out = append(out, FieldValue{Field: toolField(i), Role: RoleTool, Text: raw})
		}
	case StageToolResult:
		for i, r := range t.ToolResults {
			if r.Content == "" {
				continue
			}
			out = append(out, FieldValue{Field: resultField(i), Role: RoleTool, Text: r.Content})
		}
	case StageOutbound:
		if t.Completion != "" {
			out = append(out, FieldValue{Field: FieldCompletion, Role: RoleAssistant, Text: t.Completion})
		}
	}
	return out
}

// UserFields narrows ScanFields to attacker-controlled turns. System prompts
// are trusted by construction, so scanning them for prompt injection would be
// a guaranteed false positive.
func (t *Transaction) UserFields() []FieldValue {
	var out []FieldValue
	for _, f := range t.ScanFields() {
		if f.Role == RoleSystem {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Field reads a field by reference.
func (t *Transaction) Field(ref string) (string, bool) {
	switch ref {
	case FieldSystem:
		return t.System, true
	case FieldCompletion:
		return t.Completion, true
	}
	if i, ok := parseIndexed(ref, "messages[", "].content"); ok && i < len(t.Messages) {
		return t.Messages[i].Content, true
	}
	if i, ok := parseIndexed(ref, "tool_calls[", "].raw"); ok && i < len(t.ToolCalls) {
		return t.ToolCalls[i].Raw, true
	}
	if i, ok := parseIndexed(ref, "tool_results[", "].content"); ok && i < len(t.ToolResults) {
		return t.ToolResults[i].Content, true
	}
	return "", false
}

// SetField writes a field by reference.
func (t *Transaction) SetField(ref, val string) bool {
	switch ref {
	case FieldSystem:
		t.System = val
		return true
	case FieldCompletion:
		t.Completion = val
		return true
	}
	if i, ok := parseIndexed(ref, "messages[", "].content"); ok && i < len(t.Messages) {
		t.Messages[i].Content = val
		return true
	}
	if i, ok := parseIndexed(ref, "tool_calls[", "].raw"); ok && i < len(t.ToolCalls) {
		t.ToolCalls[i].Raw = val
		return true
	}
	if i, ok := parseIndexed(ref, "tool_results[", "].content"); ok && i < len(t.ToolResults) {
		t.ToolResults[i].Content = val
		return true
	}
	return false
}

func parseIndexed(ref, prefix, suffix string) (int, bool) {
	if !strings.HasPrefix(ref, prefix) || !strings.HasSuffix(ref, suffix) {
		return 0, false
	}
	body := ref[len(prefix) : len(ref)-len(suffix)]
	if body == "" {
		return 0, false
	}
	n := 0
	for _, r := range body {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// GuardRun records what happened to a single guard, including the failures the
// pipeline swallowed. Without this, a guard that silently times out on every
// request is indistinguishable from a guard that finds nothing.
type GuardRun struct {
	Guard    string        `json:"guard"`
	Duration time.Duration `json:"duration_ns"`
	Findings int           `json:"findings"`
	Action   Action        `json:"action"`
	Skipped  bool          `json:"skipped,omitempty"`
	TimedOut bool          `json:"timed_out,omitempty"`
	Error    string        `json:"error,omitempty"`
	FailMode string        `json:"fail_mode,omitempty"`
}

// Decision is the pipeline's verdict for one stage.
type Decision struct {
	TransactionID string        `json:"transaction_id"`
	Stage         Stage         `json:"stage"`
	Action        Action        `json:"action"`
	Findings      []Finding     `json:"findings,omitempty"`
	Mutations     []Mutation    `json:"mutations,omitempty"`
	Runs          []GuardRun    `json:"guard_runs,omitempty"`
	Duration      time.Duration `json:"duration_ns"`
	PolicyVersion string        `json:"policy_version,omitempty"`
	Degraded      bool          `json:"degraded,omitempty"` // a guard failed and was failed open

	// Metrics carries detector-internal numbers, including scores below the
	// policy threshold. A suppressed 0.4 injection score produces no finding,
	// and it is exactly the "suspicious but not proven" signal the semantic
	// tier's cascade mode escalates on.
	Metrics map[string]float64 `json:"metrics,omitempty"`
}

// Blocked reports whether the caller must stop.
func (d *Decision) Blocked() bool { return d.Action == ActionBlock }

// Categories returns the deduplicated, sorted set of categories detected. This
// is the label space the evaluation harness scores against.
func (d *Decision) Categories() []string {
	seen := map[string]struct{}{}
	for _, f := range d.Findings {
		seen[f.Category] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// TopFinding returns the highest-severity finding, breaking ties by score.
func (d *Decision) TopFinding() (Finding, bool) {
	var best Finding
	found := false
	for _, f := range d.Findings {
		if !found || f.Severity > best.Severity || (f.Severity == best.Severity && f.Score > best.Score) {
			best, found = f, true
		}
	}
	return best, found
}

// Reason renders a short, user-safe explanation for a block.
func (d *Decision) Reason() string {
	f, ok := d.TopFinding()
	if !ok {
		return "policy violation"
	}
	return fmt.Sprintf("%s (%s)", f.Message, f.Category)
}
