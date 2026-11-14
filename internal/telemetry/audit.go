package telemetry

import (
	"context"
	"log/slog"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Auditor writes the compliance record of what the engine decided.
//
// The governing rule is that the audit log must never become the breach it was
// written to detect. It records categories, severities, offsets, fingerprints
// and guard names -- never the matched value. An auditor who needs to know
// whether the same card number appeared in forty requests can correlate on the
// HMAC fingerprint the PII guard attaches; nobody needs the digits to answer
// that question, and storing them would turn every log shipper, index and
// backup into regulated infrastructure.
type Auditor struct {
	log     *slog.Logger
	enabled bool
	// logAllowed controls whether clean requests are recorded. Compliance
	// regimes usually want them; cost-sensitive deployments usually do not.
	logAllowed bool
}

// AuditOptions configures the auditor.
type AuditOptions struct {
	Logger     *slog.Logger
	Enabled    bool
	LogAllowed bool
}

func NewAuditor(opts AuditOptions) *Auditor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Auditor{log: opts.Logger, enabled: opts.Enabled, logAllowed: opts.LogAllowed}
}

// Record writes one decision to the audit trail.
func (a *Auditor) Record(ctx context.Context, tx *core.Transaction, d *core.Decision) {
	if a == nil || !a.enabled || d == nil {
		return
	}
	if d.Action == core.ActionAllow && len(d.Findings) == 0 && !a.logAllowed {
		return
	}

	attrs := []any{
		"event", "guardrail.decision",
		"transaction_id", d.TransactionID,
		"stage", string(d.Stage),
		"action", string(d.Action),
		"policy_version", d.PolicyVersion,
		"duration_us", d.Duration.Microseconds(),
		"finding_count", len(d.Findings),
		"mutation_count", len(d.Mutations),
	}
	if tx != nil {
		if tx.Tenant != "" {
			attrs = append(attrs, "tenant", tx.Tenant)
		}
		if tx.Model != "" {
			attrs = append(attrs, "model", tx.Model)
		}
		if tx.Step > 0 {
			attrs = append(attrs, "step", tx.Step)
		}
	}
	if id := TraceID(ctx); id != "" {
		attrs = append(attrs, "trace_id", id)
	}
	if d.Degraded {
		attrs = append(attrs, "degraded", true)
	}
	if len(d.Findings) > 0 {
		attrs = append(attrs, "findings", auditFindings(d.Findings))
	}

	level := slog.LevelInfo
	switch d.Action {
	case core.ActionBlock:
		level = slog.LevelWarn
	case core.ActionRedact:
		level = slog.LevelInfo
	}
	a.log.Log(ctx, level, "guardrail decision", attrs...)
}

// auditRecord is the redacted projection of a finding.
type auditRecord struct {
	Guard       string  `json:"guard"`
	Rule        string  `json:"rule"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Field       string  `json:"field,omitempty"`
	Start       int     `json:"start,omitempty"`
	End         int     `json:"end,omitempty"`
	Fingerprint string  `json:"fingerprint,omitempty"`
}

func auditFindings(in []core.Finding) []auditRecord {
	out := make([]auditRecord, 0, len(in))
	for _, f := range in {
		r := auditRecord{
			Guard: f.Guard, Rule: f.Rule, Category: f.Category,
			Severity: f.SeverityName, Score: round3(f.Score),
			Fingerprint: f.Meta["fingerprint"],
		}
		if len(f.Spans) > 0 {
			// Offsets, not excerpts: an offset lets an operator locate the
			// match in the original request they already hold, without the
			// audit log carrying a copy of the sensitive value.
			r.Field, r.Start, r.End = f.Spans[0].Field, f.Spans[0].Start, f.Spans[0].End
		}
		out = append(out, r)
	}
	return out
}

func round3(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

// RecordUsage writes the cost record for a completed upstream call.
func (a *Auditor) RecordUsage(ctx context.Context, tx *core.Transaction, u core.Usage, costUSD float64, latency time.Duration) {
	if a == nil || !a.enabled {
		return
	}
	attrs := []any{
		"event", "guardrail.usage",
		"model", tx.Model,
		"input_tokens", u.InputTokens,
		"output_tokens", u.OutputTokens,
		"cost_usd", costUSD,
		"upstream_latency_ms", latency.Milliseconds(),
	}
	if tx.Tenant != "" {
		attrs = append(attrs, "tenant", tx.Tenant)
	}
	if u.CacheReadTokens > 0 {
		attrs = append(attrs, "cache_read_tokens", u.CacheReadTokens)
	}
	if id := TraceID(ctx); id != "" {
		attrs = append(attrs, "trace_id", id)
	}
	a.log.Log(ctx, slog.LevelInfo, "upstream usage", attrs...)
}

// RecordToolExecution writes an execution receipt to the audit trail.
//
// Receipts are logged even when the call was refused, and especially then. The
// question after an incident is never only "what did the agent do" -- it is
// "what did it try to do, and which control stopped it", and a trail that only
// contains successes cannot answer the second half.
//
// The receipt carries an argument digest rather than the arguments. Tool
// arguments routinely contain exactly the values the rest of this engine works
// to keep out of logs.
func (a *Auditor) RecordToolExecution(ctx context.Context, r ToolReceipt) {
	if a == nil || !a.enabled {
		return
	}
	if r.Allowed && len(r.DeniedBy) == 0 && !a.logAllowed {
		return
	}
	attrs := []any{
		"event", "guardrail.tool_execution",
		"receipt", r.ID,
		"trace", r.Trace,
		"tool", r.Tool,
		"tier", r.Tier,
		"signature", r.Signature,
		"allowed", r.Allowed,
		"args_digest", r.ArgsDigest,
		"chain", r.Hash,
	}
	if r.DryRun {
		attrs = append(attrs, "dry_run", true)
	}
	if r.Replay {
		attrs = append(attrs, "replay", true)
	}
	if len(r.Controls) > 0 {
		attrs = append(attrs, "controls", r.Controls)
	}
	if len(r.DeniedBy) > 0 {
		attrs = append(attrs, "denied_by", r.DeniedBy)
	}
	if r.Approver != "" {
		attrs = append(attrs, "approver", r.Approver)
	}
	if r.Error != "" {
		attrs = append(attrs, "error", r.Error)
	}
	a.log.LogAttrs(ctx, levelFor(r.Allowed), "tool execution", toAttrs(attrs)...)
}

// ToolReceipt is the audit projection of an execution receipt. It is declared
// here rather than imported from internal/agent so that telemetry keeps its
// one-way dependency on core alone.
type ToolReceipt struct {
	ID         string
	Trace      string
	Tool       string
	Tier       string
	Signature  string
	ArgsDigest string
	Hash       string
	Approver   string
	Error      string
	Controls   []string
	DeniedBy   []string
	Allowed    bool
	DryRun     bool
	Replay     bool
}

func levelFor(allowed bool) slog.Level {
	if allowed {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}

func toAttrs(kv []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		out = append(out, slog.Any(key, kv[i+1]))
	}
	return out
}
