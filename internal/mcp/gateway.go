package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"go.vicoworks.com/guard-rails-engine/internal/agent"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Grade is the operator's risk grading of one upstream tool. It is the only
// source allowed to make a tool look safer than the default.
type Grade struct {
	Reversibility  string  `yaml:"reversibility" json:"reversibility,omitempty"`
	Radius         string  `yaml:"radius" json:"radius,omitempty"`
	Egress         bool    `yaml:"egress" json:"egress,omitempty"`
	Destination    string  `yaml:"destination" json:"destination,omitempty"`
	Amount         string  `yaml:"amount" json:"amount,omitempty"`
	AmountLimitUSD float64 `yaml:"amount_limit_usd" json:"amount_limit_usd,omitempty"`
	Private        bool    `yaml:"private" json:"private,omitempty"`
	MaxPerSession  int     `yaml:"max_per_session" json:"max_per_session,omitempty"`
}

// ServerConfig is one upstream MCP server.
type ServerConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Trust is "untrusted" (default) or "trusted". Results from an untrusted
	// server count as attacker-authorable content for taint and the trifecta.
	Trust string           `yaml:"trust"`
	Tools map[string]Grade `yaml:"tools"`
	// Headers are sent on every request to this server. Values may use
	// ${ENV_VAR}, so a token never has to be written in the file.
	Headers map[string]string `yaml:"headers"`
}

// Config is config/mcp.yaml.
type Config struct {
	Servers []ServerConfig `yaml:"servers"`
	// BuiltinTools exposes tools from the gateway's own catalog (simulated
	// executors) alongside the upstream ones.
	BuiltinTools []string `yaml:"builtin_tools"`
	// SessionCapabilities are granted to every MCP session; "*" grants every
	// capability in the catalog, leaving tiers, taint, the trifecta and
	// approvals as the controls that decide.
	SessionCapabilities []string `yaml:"session_capabilities"`
	// Default grade for an upstream tool the operator has not reviewed.
	Default Grade `yaml:"default_grade"`
}

// LoadConfig reads an MCP gateway config, rejecting unknown fields.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// ${NAME:-default} lets one file serve both a local run and docker
	// compose, where the demo server has a different hostname.
	expanded := envRef.ReplaceAllStringFunc(string(raw), func(m string) string {
		sub := envRef.FindStringSubmatch(m)
		if v := os.Getenv(sub[1]); v != "" {
			return v
		}
		return sub[2]
	})
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("mcp config %s: %w", path, err)
	}
	return &c, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Z0-9_]+)(?::-([^}]*))?\}`)

// Publisher receives gateway events (for the live console).
type Publisher interface {
	Publish(kind string, data any)
}

// Options wires the gateway to the engine.
type Options struct {
	Config *Config
	// Base is the engine's tool-safety evaluator. Its approver, egress
	// allowlist and tier ceiling are reused, so an approval minted by
	// /v1/agent/approve is valid here and a deployment-wide limit applies to
	// MCP tools too.
	Base *agent.Evaluator
	// ToolResult is the engine's tool-result pipeline.
	ToolResult *core.Pipeline
	// ArgPolicy inspects arguments (SSRF, destructive shell, path traversal);
	// the engine's tool_policy guard.
	ArgPolicy core.Guard
	Secret    []byte
	Events    Publisher
	Logger    *slog.Logger
}

type entry struct {
	server   string
	upstream string
	def      Tool
	tool     agent.Tool
	grade    Grade
	reviewed bool
	notes    []ScanFinding
}

// Quarantined is a tool withheld from the agent.
type Quarantined struct {
	Tool     string        `json:"tool"`
	Server   string        `json:"server"`
	Reason   string        `json:"reason"`
	Findings []ScanFinding `json:"findings"`
	At       time.Time     `json:"at"`
}

// Gateway is the guarded MCP server.
type Gateway struct {
	opts    Options
	sim     *agent.Simulator
	clients map[string]*Client
	trust   map[string]bool

	mu         sync.RWMutex
	entries    map[string]*entry
	pins       map[string]string
	quarantine map[string]Quarantined
	eval       *agent.Evaluator
	broker     *agent.Broker
	lastSync   time.Time

	sessMu   sync.Mutex
	sessions map[string]*session
}

type session struct {
	state *core.SessionState
	vault *core.Vault
	seen  time.Time
}

// NewGateway builds the gateway and performs the first discovery. An
// unreachable upstream is logged, not fatal: its tools are simply absent until
// the next sync finds it.
func NewGateway(ctx context.Context, opts Options) (*Gateway, error) {
	if opts.Base == nil {
		return nil, fmt.Errorf("mcp: the tool_safety guard must be enabled")
	}
	if opts.Config == nil {
		opts.Config = &Config{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	g := &Gateway{opts: opts, sim: agent.NewSimulator(nil), clients: map[string]*Client{}, trust: map[string]bool{},
		entries: map[string]*entry{}, pins: map[string]string{}, quarantine: map[string]Quarantined{},
		sessions: map[string]*session{}}
	for _, s := range opts.Config.Servers {
		c := NewClient(s.Name, s.URL, 20*time.Second)
		c.Headers = s.Headers
		g.clients[s.Name] = c
		g.trust[s.Name] = s.Trust == "trusted"
	}
	if err := g.Sync(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Gateway) publish(kind string, v any) {
	if g.opts.Events != nil {
		g.opts.Events.Publish(kind, v)
	}
}

// Sync re-lists every upstream, re-scans and re-pins. It runs on every
// tools/list (rate-limited), because a rug pull is a definition that changes
// between two lists, and only a gateway that keeps looking will see it.
func (g *Gateway) Sync(ctx context.Context) error {
	builtin := map[string]agent.Tool{}
	for _, name := range g.opts.Config.BuiltinTools {
		t, ok := g.opts.Base.Catalog().Lookup(name)
		if !ok {
			return fmt.Errorf("mcp: builtin tool %q is not in the catalog", name)
		}
		builtin[name] = *t
	}

	type listed struct {
		server string
		tools  []Tool
	}
	var all []listed
	for _, s := range g.opts.Config.Servers {
		tools, err := g.clients[s.Name].ListTools(ctx)
		if err != nil {
			g.opts.Logger.Warn("mcp upstream unavailable", "server", s.Name, "error", err)
			continue
		}
		all = append(all, listed{s.Name, tools})
	}

	// Every name the agent can see, for the shadowing check.
	var visible []string
	for n := range builtin {
		visible = append(visible, n)
	}
	for _, l := range all {
		for _, t := range l.tools {
			visible = append(visible, t.Name)
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	entries := map[string]*entry{}
	for _, l := range all {
		cfg := g.serverConfig(l.server)
		for _, t := range l.tools {
			name := exposedName(l.server, t.Name)
			pin := Pin(t)
			if old, ok := g.pins[name]; ok && old != pin {
				if _, already := g.quarantine[name]; !already {
					q := Quarantined{Tool: name, Server: l.server, Reason: "rug_pull", At: time.Now(),
						Findings: []ScanFinding{{Category: "mcp.rug_pull", Severity: "critical",
							Message:  "tool definition changed after it was pinned; re-review before re-enabling",
							Evidence: "pin " + old[:12] + " → " + pin[:12]}}}
					g.quarantine[name] = q
					g.opts.Logger.Warn("mcp rug pull detected", "tool", name, "old_pin", old[:12], "new_pin", pin[:12])
					g.publish("mcp.quarantine", q)
				}
				continue
			}
			if q, ok := g.quarantine[name]; ok && q.Reason == "rug_pull" {
				continue // stays quarantined until an operator re-pins it
			}
			findings := ScanDefinition(ctx, t, visible, g.railsScan)
			if Blocking(findings) {
				if _, already := g.quarantine[name]; !already {
					q := Quarantined{Tool: name, Server: l.server, Reason: "poisoned_definition", Findings: findings, At: time.Now()}
					g.quarantine[name] = q
					g.opts.Logger.Warn("mcp tool quarantined", "tool", name, "findings", len(findings))
					g.publish("mcp.quarantine", q)
				}
				continue
			}
			g.pins[name] = pin
			e, err := g.grade(l.server, cfg, t)
			if err != nil {
				g.quarantine[name] = Quarantined{Tool: name, Server: l.server, Reason: "invalid_grade", At: time.Now(),
					Findings: []ScanFinding{{Category: "mcp.config", Severity: "high", Message: err.Error()}}}
				continue
			}
			e.notes = append(e.notes, findings...)
			entries[name] = e
		}
	}

	tools := make([]agent.Tool, 0, len(builtin)+len(entries))
	for _, t := range builtin {
		tools = append(tools, t)
	}
	for _, e := range entries {
		tools = append(tools, e.tool)
	}
	cat, err := agent.NewCatalog(tools)
	if err != nil {
		return fmt.Errorf("mcp: catalog: %w", err)
	}
	base := g.opts.Base.Options()
	base.Catalog = cat
	ev, err := agent.NewEvaluator(base)
	if err != nil {
		return err
	}
	br, err := agent.NewBroker(ev, g, receiptSink{g})
	if err != nil {
		return err
	}
	g.entries, g.eval, g.broker, g.lastSync = entries, ev, br, time.Now()
	return nil
}

// Repin clears a quarantine after an operator has reviewed the definition.
func (g *Gateway) Repin(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.quarantine[name]; !ok {
		return false
	}
	delete(g.quarantine, name)
	delete(g.pins, name)
	g.lastSync = time.Time{}
	return true
}

func (g *Gateway) railsScan(ctx context.Context, text string) []core.Finding {
	if g.opts.ToolResult == nil {
		return nil
	}
	tx := &core.Transaction{ID: "mcp-scan", Stage: core.StageToolResult, StartedAt: time.Now(),
		Vault:       core.NewVault(g.opts.Secret),
		ToolResults: []core.ToolResult{{Name: "tool_definition", Content: text, Origin: core.OriginWeb}}}
	dec, _ := g.opts.ToolResult.Execute(ctx, tx)
	return dec.Findings
}

func (g *Gateway) serverConfig(name string) ServerConfig {
	for _, s := range g.opts.Config.Servers {
		if s.Name == name {
			return s
		}
	}
	return ServerConfig{Name: name}
}

func exposedName(server, tool string) string { return server + "__" + tool }

// grade turns an upstream definition into a catalog entry. The operator's
// grade wins outright; without one the default applies, and annotations may
// only raise the risk -- never lower it.
func (g *Gateway) grade(server string, cfg ServerConfig, t Tool) (*entry, error) {
	gr, reviewed := cfg.Tools[t.Name]
	if !reviewed {
		gr = g.opts.Config.Default
		if gr.Reversibility == "" {
			gr.Reversibility = "compensable"
		}
		if gr.Radius == "" {
			gr.Radius = "external"
		}
	}
	rev, err := agent.ParseReversibility(gr.Reversibility)
	if err != nil {
		return nil, err
	}
	rad, err := agent.ParseRadius(gr.Radius)
	if err != nil {
		return nil, err
	}
	var notes []ScanFinding
	if a := t.Annotations; a != nil {
		if !reviewed {
			if a.DestructiveHint != nil && *a.DestructiveHint {
				rev = agent.RevIrreversible
			}
			if a.OpenWorldHint != nil && *a.OpenWorldHint && rad < agent.RadiusExternal {
				rad = agent.RadiusExternal
			}
		}
		if a.ReadOnlyHint != nil && *a.ReadOnlyHint && rev != agent.RevNone {
			notes = append(notes, ScanFinding{Category: "mcp.annotation_mismatch", Severity: "medium",
				Message: fmt.Sprintf("server claims readOnlyHint=true; graded %s/%s and treated as such", rev, rad)})
		}
	}
	name := exposedName(server, t.Name)
	at := agent.Tool{
		Name: name, Description: t.Description, Domain: "mcp:" + server,
		Reversibility: rev, Radius: rad, Egress: gr.Egress,
		Capability: "mcp:" + server, MaxPerSession: gr.MaxPerSession, AmountLimitUSD: gr.AmountLimitUSD,
		Rationale: fmt.Sprintf("MCP tool from %s; %s", server, map[bool]string{true: "graded by the operator", false: "default grade, not reviewed"}[reviewed]),
	}
	if rev == agent.RevCompensable {
		at.Undo = "ask the operator of MCP server " + server + " to reverse it"
	}
	if !g.trust[server] {
		at.Exposure |= agent.ExposureUntrusted
	}
	if gr.Private {
		at.Exposure |= agent.ExposurePrivate
	}
	at.Params = paramsFromSchema(t.InputSchema, gr)
	return &entry{server: server, upstream: t.Name, def: t, tool: at, grade: gr, reviewed: reviewed, notes: notes}, nil
}

func paramsFromSchema(raw json.RawMessage, gr Grade) []agent.Param {
	var s struct {
		Properties map[string]struct {
			Type        any    `json:"type"`
			Description string `json:"description"`
			MaxLength   int    `json:"maxLength"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(raw, &s)
	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	var out []agent.Param
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := s.Properties[n]
		typ, _ := p.Type.(string)
		switch typ {
		case "string", "integer", "number", "boolean", "array":
		default:
			continue // objects and unions are passed through unvalidated
		}
		out = append(out, agent.Param{Name: n, Type: typ, Required: req[n], MaxLen: p.MaxLength, Desc: p.Description,
			Destination: n == gr.Destination, Amount: n == gr.Amount})
	}
	return out
}

// --- agent.Executor -------------------------------------------------------------

// Preview describes an upstream call without making it. The gateway cannot
// know what a third-party server will actually do, and the preview says so: a
// human approving the call should know they are approving an unverifiable
// effect.
func (g *Gateway) Preview(ctx context.Context, t *agent.Tool, args map[string]any) (string, error) {
	g.mu.RLock()
	e, upstream := g.entries[t.Name]
	g.mu.RUnlock()
	if !upstream {
		return g.sim.Preview(ctx, t, args)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s] on MCP server %q\n", e.upstream, t.Tier(), e.server)
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-12s %s\n", k+":", clip(fmt.Sprint(args[k]), 80))
	}
	if t.Reversibility == agent.RevIrreversible {
		b.WriteString("  undo:        NONE -- this cannot be taken back\n")
	}
	b.WriteString("  note:        the effect is performed by a third-party server and cannot be verified by the gateway")
	if strings.Contains(b.String(), "[[PII:") {
		b.WriteString("\n  masked:      [[PII:...]] values are restored inside the gateway at execution; this approval binds to them by HMAC")
	}
	return b.String(), nil
}

type vaultKey struct{}

// restoreArgs substitutes vault placeholders with real values. Controls,
// approvals and audit all ran on the masked form -- the approval signature
// binds to the HMAC placeholder, which is unique to the value -- so restoring
// here changes what the executor receives and nothing that was judged.
func restoreArgs(ctx context.Context, args map[string]any) map[string]any {
	v, _ := ctx.Value(vaultKey{}).(*core.Vault)
	if v == nil || v.Len() == 0 {
		return args
	}
	out := make(map[string]any, len(args))
	for k, a := range args {
		if s, ok := a.(string); ok {
			s, _ = v.Restore(s)
			out[k] = s
			continue
		}
		out[k] = a
	}
	return out
}

// Execute forwards the call upstream, or to the simulator for built-in tools.
func (g *Gateway) Execute(ctx context.Context, t *agent.Tool, args map[string]any) (core.ToolResult, error) {
	args = restoreArgs(ctx, args)
	g.mu.RLock()
	e, upstream := g.entries[t.Name]
	g.mu.RUnlock()
	if !upstream {
		return g.sim.Execute(ctx, t, args)
	}
	res, err := g.clients[e.server].CallTool(ctx, e.upstream, args)
	if err != nil {
		return core.ToolResult{}, err
	}
	origin := core.OriginTool
	if !g.trust[e.server] {
		origin = core.OriginWeb
	}
	out := core.ToolResult{Name: t.Name, Content: res.Text(), Origin: origin, Sensitive: e.grade.Private, Parts: res.Parts()}
	if res.IsError {
		out.Error = "upstream reported an error"
	}
	return out, nil
}

type receiptSink struct{ g *Gateway }

func (s receiptSink) Receipt(r *agent.Receipt) { s.g.publish("tool.receipt", r) }

// --- calls -------------------------------------------------------------------------

// CallMeta carries the controls a caller can satisfy.
type CallMeta struct {
	ApprovalToken  string
	IdempotencyKey string
	DryRun         bool
	// Vault restores masked values in the arguments just before execution.
	// The model only ever handled placeholders; the real IBAN or email is
	// substituted inside the gateway, after every control has passed, so it
	// never travels back through the model.
	Vault *core.Vault
}

// CallOutcome is everything the gateway decided about one call.
type CallOutcome struct {
	Tool         string              `json:"tool"`
	Trace        string              `json:"trace"`
	Server       string              `json:"server,omitempty"`
	Tier         string              `json:"tier,omitempty"`
	Status       string              `json:"status"` // executed | refused | approval_required | quarantined | result_blocked | unknown_tool | error
	Controls     []string            `json:"controls,omitempty"`
	Findings     []core.Finding      `json:"findings,omitempty"`
	Requirements []agent.Requirement `json:"requirements,omitempty"`
	Preview      string              `json:"preview,omitempty"`
	Signature    string              `json:"signature,omitempty"`
	ResultAction core.Action         `json:"result_action,omitempty"`
	Receipt      string              `json:"receipt,omitempty"`
	Result       string              `json:"-"`
	DurationMS   int64               `json:"duration_ms"`
}

// Call runs one tool call through every control. It is the single path for
// both MCP clients and the gateway's own LLM agent loop.
func (g *Gateway) Call(ctx context.Context, state *core.SessionState, name string, args map[string]any, meta CallMeta) *CallOutcome {
	start := time.Now()
	out := &CallOutcome{Tool: name, Trace: state.TraceID}
	defer func() {
		out.DurationMS = time.Since(start).Milliseconds()
		g.publish("tool.call", out)
	}()

	g.mu.RLock()
	q, quarantined := g.quarantine[name]
	e := g.entries[name]
	broker, ev := g.broker, g.eval
	g.mu.RUnlock()
	if e != nil {
		out.Server = e.server
	}
	if quarantined {
		out.Status = "quarantined"
		out.Server = q.Server
		out.Result = fmt.Sprintf("tool %s is quarantined (%s)", name, q.Reason)
		return out
	}
	t, known := ev.Catalog().Lookup(name)
	if !known {
		out.Status = "unknown_tool"
		out.Result = "no such tool: " + name
		return out
	}
	out.Tier = t.Tier().String()

	raw, _ := json.Marshal(args)
	call := core.ToolCall{ID: "call_" + newID()[:12], Name: name, Arguments: args, Raw: string(raw)}

	// Argument inspection first: SSRF to metadata endpoints, destructive
	// shell, path traversal. These are properties of the argument text and
	// apply whatever the tool's grade.
	if g.opts.ArgPolicy != nil {
		tx := &core.Transaction{ID: call.ID, Stage: core.StageRuntime, ToolCalls: []core.ToolCall{call},
			Session: state, StartedAt: time.Now(), Vault: core.NewVault(g.opts.Secret)}
		res, _ := g.opts.ArgPolicy.Check(ctx, tx)
		for _, f := range res.Findings {
			if f.Severity >= core.SeverityHigh {
				out.Findings = append(out.Findings, f)
			}
		}
		if len(out.Findings) > 0 {
			out.Status = "refused"
			out.Result = "refused by argument policy: " + out.Findings[0].Message
			return out
		}
	}

	if g.opts.Config.grantAll() {
		state.Granted = ev.Catalog().Capabilities()
	} else {
		state.Granted = g.opts.Config.SessionCapabilities
	}

	req := agent.Request{Trace: state.TraceID, Call: call, Session: state,
		IdempotencyKey: meta.IdempotencyKey, ApprovalToken: meta.ApprovalToken, DryRun: meta.DryRun}
	// An agent that never heard of idempotency keys still gets the guarantee:
	// the same call in the same session is the same effect, and a retry is
	// answered from the ledger instead of performed twice.
	if req.IdempotencyKey == "" && t.Tier() >= agent.T3 {
		req.IdempotencyKey = "auto-" + state.TraceID + "-" + ev.Assess(agent.Request{Trace: state.TraceID, Call: call, Session: state.Clone()}).Signature
	}

	if meta.Vault != nil {
		ctx = context.WithValue(ctx, vaultKey{}, meta.Vault)
	}
	o := broker.Do(ctx, req)
	out.Controls, out.Findings, out.Signature = o.Assessment.Controls, o.Assessment.Findings, o.Assessment.Signature
	if o.Receipt != nil {
		out.Receipt = o.Receipt.ID
	}

	// A call whose only missing control is the dry run gets one, so the
	// person asked to approve it sees what it would do.
	if !o.Assessment.Allowed() && onlyMissing(o.Assessment, "dry_run", "approval") && hasRequirement(o.Assessment, "dry_run") {
		dry := req
		dry.DryRun = true
		d := broker.Do(ctx, dry)
		out.Preview = d.Preview
		o = broker.Do(ctx, req)
		out.Controls, out.Findings, out.Signature = o.Assessment.Controls, o.Assessment.Findings, o.Assessment.Signature
	}

	switch {
	case !o.Assessment.Allowed():
		out.Requirements = o.Assessment.Requirements
		if onlyMissing(o.Assessment, "approval") && len(highFindings(o.Assessment.Findings)) == 0 {
			out.Status = "approval_required"
			if out.Preview == "" {
				out.Preview, _ = g.Preview(ctx, t, args)
			}
			out.Result = fmt.Sprintf("APPROVAL REQUIRED for %s [%s]. A person must review this exact call and approve signature %s via POST /v1/agent/approve, then retry with _meta.approval_token.\n\n%s",
				name, out.Tier, out.Signature, out.Preview)
			return out
		}
		out.Status = "refused"
		var why []string
		for _, f := range highFindings(o.Assessment.Findings) {
			why = append(why, f.Message)
		}
		for _, r := range o.Assessment.Requirements {
			why = append(why, r.Control+": "+r.Message)
		}
		out.Result = "REFUSED: " + strings.Join(why, "; ")
		return out
	case o.DryRun:
		out.Status = "dry_run"
		out.Result = o.Preview
		return out
	case o.Error != "":
		out.Status = "error"
		out.Result = "tool error: " + o.Error
		return out
	case !o.Executed:
		out.Status = "replay"
		out.Result = "this exact call already ran in this session; not executing it twice"
		return out
	}

	// Result rails: what came back is untrusted until checked.
	res := *o.Result
	tx := &core.Transaction{ID: call.ID, Stage: core.StageToolResult, ToolResults: []core.ToolResult{res},
		Session: state, StartedAt: time.Now(), Vault: core.NewVault(g.opts.Secret)}
	dec, _ := g.opts.ToolResult.Execute(ctx, tx)
	out.ResultAction = dec.Action
	out.Findings = append(out.Findings, dec.Findings...)
	if dec.Blocked() {
		out.Status = "result_blocked"
		out.Result = "the tool ran, but its result was withheld from the model: " + dec.Reason()
		return out
	}
	out.Status = "executed"
	out.Result = tx.ToolResults[0].Content
	// Attachments reach the agent as the text the ingest step extracted and
	// the result rails passed (redactions included), never as raw bytes the
	// rails could not see into.
	for _, p := range tx.ToolResults[0].Parts {
		if t := p.AsText().Text; t != "" {
			if out.Result != "" {
				out.Result += "\n\n"
			}
			out.Result += t
		}
	}
	if meta.Vault != nil {
		out.Result, _ = meta.Vault.MaskKnown(out.Result)
	}
	if res.Error != "" {
		out.Result = "tool reported an error: " + out.Result
	}
	return out
}

func (c *Config) grantAll() bool {
	for _, s := range c.SessionCapabilities {
		if s == "*" {
			return true
		}
	}
	return len(c.SessionCapabilities) == 0
}

func hasRequirement(a agent.Assessment, control string) bool {
	for _, r := range a.Requirements {
		if r.Control == control {
			return true
		}
	}
	return false
}

func onlyMissing(a agent.Assessment, controls ...string) bool {
	ok := map[string]bool{}
	for _, c := range controls {
		ok[c] = true
	}
	for _, r := range a.Requirements {
		if !ok[r.Control] {
			return false
		}
	}
	return len(highFindings(a.Findings)) == 0
}

func highFindings(fs []core.Finding) []core.Finding {
	var out []core.Finding
	for _, f := range fs {
		if f.Severity >= core.SeverityHigh && f.Category != "tool.approval_required" && f.Category != "tool.dry_run_required" {
			out = append(out, f)
		}
	}
	return out
}

// --- introspection ----------------------------------------------------------------

// ToolInfo is one tool as the console and /v1/mcp/servers show it.
type ToolInfo struct {
	Name     string        `json:"name"`
	Server   string        `json:"server"`
	Tier     string        `json:"tier"`
	Reviewed bool          `json:"reviewed"`
	Exposure string        `json:"exposure"`
	Pin      string        `json:"pin,omitempty"`
	Notes    []ScanFinding `json:"notes,omitempty"`
}

// Inventory lists exposed and quarantined tools.
func (g *Gateway) Inventory() (exposed []ToolInfo, quarantined []Quarantined) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, t := range g.eval.Catalog().Tools() {
		info := ToolInfo{Name: t.Name, Server: "builtin", Tier: t.Tier().String(), Reviewed: true, Exposure: t.Exposure.String()}
		if e, ok := g.entries[t.Name]; ok {
			info.Server, info.Reviewed, info.Notes = e.server, e.reviewed, e.notes
			if p := g.pins[t.Name]; len(p) > 12 {
				info.Pin = p[:12]
			}
		}
		exposed = append(exposed, info)
	}
	for _, q := range g.quarantine {
		quarantined = append(quarantined, q)
	}
	sort.Slice(quarantined, func(i, j int) bool { return quarantined[i].Tool < quarantined[j].Tool })
	return exposed, quarantined
}

// FunctionTools renders the exposed tools as function-calling declarations.
func (g *Gateway) FunctionTools() []map[string]any {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.functionToolsLocked()
}

func (g *Gateway) functionToolsLocked() []map[string]any {
	var out []map[string]any
	for _, t := range g.eval.Catalog().Tools() {
		schema := map[string]any{"type": "object", "properties": map[string]any{}}
		if e, ok := g.entries[t.Name]; ok && len(e.def.InputSchema) > 0 {
			var s map[string]any
			if json.Unmarshal(e.def.InputSchema, &s) == nil {
				schema = s
			}
		} else {
			props := map[string]any{}
			var req []string
			for _, p := range t.Params {
				ps := map[string]any{"type": p.Type}
				if p.Type == "array" {
					ps["items"] = map[string]any{"type": "string"}
				}
				if p.Desc != "" {
					ps["description"] = p.Desc
				}
				props[p.Name] = ps
				if p.Required {
					req = append(req, p.Name)
				}
			}
			schema["properties"] = props
			if len(req) > 0 {
				schema["required"] = req
			}
		}
		out = append(out, map[string]any{"name": t.Name, "description": t.Description, "parameters": schema})
	}
	return out
}

// NewSession creates a session with fresh agent state.
func (g *Gateway) NewSession(prefix string) (string, *core.SessionState) {
	id := newID()
	st := &core.SessionState{TraceID: prefix + id[:16]}
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	// Sessions are the one piece of per-agent state the gateway holds: MCP is
	// a stateful protocol. They are bounded and expire.
	for k, s := range g.sessions {
		if time.Since(s.seen) > time.Hour {
			delete(g.sessions, k)
		}
	}
	if len(g.sessions) > 10_000 {
		g.sessions = map[string]*session{}
	}
	g.sessions[id] = &session{state: st, vault: core.NewVault(g.opts.Secret), seen: time.Now()}
	return id, st
}

// Vault returns a session's redaction vault: values masked on the way into
// the model, restored only at the execution boundary.
func (g *Gateway) Vault(id string) *core.Vault {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	if s, ok := g.sessions[id]; ok {
		return s.vault
	}
	return nil
}

// Session returns a live session's state.
func (g *Gateway) Session(id string) (*core.SessionState, bool) {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	s, ok := g.sessions[id]
	if !ok {
		return nil, false
	}
	s.seen = time.Now()
	return s.state, true
}

// EndSession drops a session.
func (g *Gateway) EndSession(id string) {
	g.sessMu.Lock()
	delete(g.sessions, id)
	g.sessMu.Unlock()
}

func (g *Gateway) maybeSync(ctx context.Context) {
	g.mu.RLock()
	stale := time.Since(g.lastSync) > 2*time.Second
	g.mu.RUnlock()
	if stale {
		if err := g.Sync(ctx); err != nil {
			g.opts.Logger.Warn("mcp sync failed", "error", err)
		}
	}
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
