package config

import (
	"fmt"
	"time"
)

// Guard name constants. Declaring them here rather than as string literals
// scattered across packages means the policy validator can reject a typo'd
// guard name at startup instead of silently ignoring the block.
const (
	GuardPII        = "pii"
	GuardSecrets    = "secrets"
	GuardInjection  = "injection"
	GuardTopic      = "topic"
	GuardQuota      = "quota"
	GuardLoop       = "loop_breaker"
	GuardToolPolicy = "tool_policy"
	GuardToolSafety = "tool_safety"
	GuardBudget     = "budget_breaker"
	GuardToolResult = "tool_result"
	GuardSchema     = "schema"
	GuardLeak       = "leak"
	GuardGrounding  = "grounding"
	GuardFormat     = "format"
	GuardRestore    = "restore"

	GuardMedia                 = "media"
	GuardMediaResult           = "media_result"
	GuardCustomRules           = "custom_rules"
	GuardCustomRulesOutbound   = "custom_rules_outbound"
	GuardCustomRulesToolResult = "custom_rules_tool_result"
	GuardURLFilter             = "url_filter"
	GuardURLFilterOutbound     = "url_filter_outbound"
)

// guardStages is the authoritative guard -> stage mapping, used by the policy
// validator and by the guard registry.
var guardStages = map[string]string{
	GuardPII:        "inbound",
	GuardSecrets:    "inbound",
	GuardInjection:  "inbound",
	GuardTopic:      "inbound",
	GuardQuota:      "inbound",
	GuardLoop:       "runtime",
	GuardToolPolicy: "runtime",
	GuardToolSafety: "runtime",
	GuardBudget:     "runtime",
	GuardToolResult: "tool_result",
	GuardSchema:     "outbound",
	GuardLeak:       "outbound",
	GuardGrounding:  "outbound",
	GuardFormat:     "outbound",
	GuardRestore:    "outbound",

	GuardMedia:                 "inbound",
	GuardMediaResult:           "tool_result",
	GuardCustomRules:           "inbound",
	GuardCustomRulesOutbound:   "outbound",
	GuardCustomRulesToolResult: "tool_result",
	GuardURLFilter:             "inbound",
	GuardURLFilterOutbound:     "outbound",
}

func guardStage(name string) string { return guardStages[name] }

// GuardStage exposes the mapping to other packages.
func GuardStage(name string) (string, bool) {
	s, ok := guardStages[name]
	return s, ok
}

// KnownGuards lists every guard the engine can construct.
func KnownGuards() []string {
	out := make([]string, 0, len(guardStages))
	for n := range guardStages {
		out = append(out, n)
	}
	return out
}

// DefaultPolicy is the built-in balanced ruleset: safe enough to put in front
// of production traffic, permissive enough not to break a normal product.
//
// Two deliberate choices are worth calling out.
//
// First, PII redacts rather than blocks. Blocking a user for pasting their own
// email address is a product failure disguised as a security control; masking
// it keeps the request useful and still stops the value from reaching the
// provider.
//
// Second, everything defaults to fail-open EXCEPT the guards whose failure has
// unbounded downside: a broken tool-policy or budget breaker can let an agent
// spend real money or touch real infrastructure, so those fail closed.
func DefaultPolicy() *Policy {
	sec := func(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

	return &Policy{
		Version:     "1.0.0",
		Name:        "balanced",
		Description: "Balanced default policy: mask PII, block high-confidence injection, cap agent spend.",

		DefaultActions: map[string]string{
			"info":     "flag",
			"low":      "flag",
			"medium":   "flag",
			"high":     "block",
			"critical": "block",
		},
		DefaultTimeout:  sec(10),
		DefaultFailMode: FailOpen,

		StageBudget: map[string]time.Duration{
			"inbound": sec(50),
			// The runtime stage is the one a human may be waiting on with a
			// finger over an approve button, and it does no text scanning, so
			// it gets the tightest budget of the four.
			"runtime":     sec(25),
			"tool_result": sec(50),
			"outbound":    sec(50),
		},

		Guards: map[string]*GuardConfig{
			GuardPII: {
				Enabled:  true,
				Timeout:  sec(15),
				FailMode: FailOpen,
				// Every PII hit redacts regardless of severity: the severity
				// grades how bad a leak would be, not whether to mask.
				Actions: map[string]string{
					"info": "redact", "low": "redact", "medium": "redact",
					"high": "redact", "critical": "redact",
				},
				Categories: map[string]CategoryOverride{
					// An IP address in a prompt is usually a log line being
					// debugged, not a privacy incident. Observe, do not mangle.
					"pii.ip_address": {Severity: "info", Action: "flag"},
				},
				Params: map[string]any{
					"mask_mode":         "vault", // vault | label | hash
					"restore_outbound":  true,
					"min_digits_phone":  9,
					"detect_indonesian": true,
				},
			},

			GuardSecrets: {
				Enabled:  true,
				Timeout:  sec(10),
				FailMode: FailClosed, // a credential reaching an upstream provider is unrecoverable
				Actions: map[string]string{
					"high": "block", "critical": "block", "medium": "redact",
				},
			},

			GuardInjection: {
				Enabled:   true,
				Threshold: 0.60,
				Timeout:   sec(15),
				FailMode:  FailOpen,
				Actions: map[string]string{
					"low": "flag", "medium": "flag", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					"scan_encoded_layers": true,
					"max_decode_depth":    2,
					"scan_tool_output":    true,
				},
			},

			GuardTopic: {
				Enabled:   true,
				Threshold: 0.55,
				Timeout:   sec(10),
				FailMode:  FailOpen,
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
			},

			GuardQuota: {
				Enabled:  true,
				Timeout:  sec(5),
				FailMode: FailClosed, // an unbounded prompt is an unbounded bill
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					"max_input_tokens":  200000,
					"max_messages":      200,
					"max_message_chars": 400000,
					"max_cost_usd":      2.50,
				},
			},

			GuardLoop: {
				Enabled:  true,
				Timeout:  sec(5),
				FailMode: FailClosed,
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					"max_steps":             25,
					"max_repeats":           3,
					"repeat_window":         6,
					"detect_oscillation":    true,
					"max_wallclock_seconds": 300,
				},
			},

			GuardToolPolicy: {
				Enabled:  true,
				Timeout:  sec(5),
				FailMode: FailClosed,
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					// Empty allowlist means "allow any tool not denied". Set an
					// explicit list in production to get default-deny.
					"allow":              []any{},
					"deny":               []any{},
					"block_private_urls": true,
					"scan_arguments":     true,
				},
			},

			// ToolSafety is the tool-level control plane: risk tiering,
			// least privilege, taint, approvals. It fails closed for the same
			// reason the budget breaker does -- the downside of an open tool
			// rail is an executed action, and there is no later stage that can
			// take one back.
			GuardToolSafety: {
				Enabled:  true,
				Timeout:  sec(10),
				FailMode: FailClosed,
				Actions: map[string]string{
					"info": "flag", "low": "flag", "medium": "flag",
					"high": "block", "critical": "block",
				},
				Categories: map[string]CategoryOverride{
					// A replay is the idempotency control working, not a
					// violation: the caller retried and must be handed the
					// first result instead of causing a second effect.
					"tool.replay": {Action: "flag"},
					// Reported per call at info severity; the actionable form
					// is `grctl policy lint`.
					"tool.egress_unrestricted": {Action: "flag"},
					"tool.amount_unconverted":  {Action: "flag"},
				},
				Params: map[string]any{
					// Empty means "no allowlist configured", which is reported
					// by `grctl policy lint` rather than enforced as deny-all.
					// Deny-all here would break every egress tool on day one,
					// and a control that has to be switched off to ship is a
					// control that stays off.
					"egress_allowlist": []any{},
					// The deployment-wide ceiling. Lower it to T3 and this
					// gateway can never move money, whatever a session was
					// granted.
					"max_tier":             "T4",
					"disabled_controls":    []any{},
					"approval_ttl_seconds": 600,
					"catalog_file":         "",
				},
			},

			GuardBudget: {
				Enabled:  true,
				Timeout:  sec(5),
				FailMode: FailClosed,
				Actions: map[string]string{
					"high": "block", "critical": "block", "medium": "flag",
				},
				Params: map[string]any{
					"max_trace_cost_usd": 5.00,
					"max_trace_tokens":   1000000,
				},
			},

			// ToolResult is the fourth rail: what a tool returned, before it
			// is appended to the model's context. It fails closed because an
			// injected instruction that slips through here does not produce a
			// bad answer -- it produces the next tool call.
			GuardToolResult: {
				Enabled:   true,
				Threshold: 0.55,
				Timeout:   sec(20),
				FailMode:  FailClosed,
				Actions: map[string]string{
					"info": "flag", "low": "flag", "medium": "flag",
					"high": "block", "critical": "block",
				},
				Categories: map[string]CategoryOverride{
					// Oversized results are truncated, not refused: a long
					// document is usually a long document.
					"tool_result.oversized": {Action: "redact"},
				},
				Params: map[string]any{
					"max_result_bytes": 200000,
					"scan_injection":   true,
					// The same signal, graded one step higher than it would be
					// inbound. A user typing "ignore your instructions" is
					// usually testing the product; a web page saying it has no
					// benign reading at all.
					"escalate_injection": true,
				},
			},

			GuardSchema: {
				Enabled:  false, // opt-in: only meaningful when the caller declares a schema
				Timeout:  sec(15),
				FailMode: FailOpen,
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
				Categories: map[string]CategoryOverride{
					// A successful repair must map to "redact", not "flag":
					// the repaired document is delivered by applying the
					// mutation, and the pipeline discards mutations from a
					// guard whose action is merely observational.
					"schema.repaired": {Action: "redact"},
				},
				Params: map[string]any{
					"repair": true, // strip fences / trailing commas before failing
				},
			},

			GuardLeak: {
				Enabled:  true,
				Timeout:  sec(15),
				FailMode: FailClosed, // system-prompt exfiltration must not fail open
				Actions: map[string]string{
					"medium": "flag", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					"system_prompt_ngram":     8,
					"system_prompt_threshold": 0.35,
					"canary":                  true,
				},
			},

			GuardGrounding: {
				Enabled:   false, // opt-in: requires retrieved context to score against
				Threshold: 0.30,
				Timeout:   sec(20),
				FailMode:  FailOpen,
				Actions: map[string]string{
					"low": "flag", "medium": "flag", "high": "flag",
				},
			},

			GuardFormat: {
				Enabled:  true,
				Timeout:  sec(10),
				FailMode: FailOpen,
				Actions: map[string]string{
					"low": "flag", "medium": "redact", "high": "block", "critical": "block",
				},
				Params: map[string]any{
					"max_output_chars":   200000,
					"block_data_urls":    true,
					"allowed_link_hosts": []any{},
				},
			},

			GuardRestore: {
				Enabled:  true,
				Timeout:  sec(5),
				FailMode: FailOpen,
				Actions:  map[string]string{"info": "redact"},
			},

			// Multimodal ingest. The extraction runs before the stage (it has
			// its own deadline, extract_timeout_seconds); this guard grades
			// what it found. Unscannable content is medium, so the balanced
			// profile flags it and the strict profile blocks it.
			GuardMedia:       mediaDefaults(sec(10), "flag"),
			GuardMediaResult: mediaDefaults(sec(10), "flag"),

			// Operator-defined rules: keywords and regular expressions with a
			// category, severity and optional replacement. Off until rules are
			// written, because an empty rule list protects nothing.
			GuardCustomRules:           customRuleDefaults(sec(10)),
			GuardCustomRulesOutbound:   customRuleDefaults(sec(10)),
			GuardCustomRulesToolResult: customRuleDefaults(sec(10)),

			// URL allow-listing, the deterministic counterpart of OpenAI
			// Guardrails' URL filter. Off by default: an empty allow list
			// would block every link.
			GuardURLFilter:         urlFilterDefaults(sec(10)),
			GuardURLFilterOutbound: urlFilterDefaults(sec(10)),
		},
	}
}

func mediaDefaults(timeout time.Duration, medium string) *GuardConfig {
	return &GuardConfig{
		Enabled:  true,
		Timeout:  timeout,
		FailMode: FailClosed, // an attachment nobody read must not pass because the reader broke
		Actions: map[string]string{
			"info": "flag", "low": "flag", "medium": medium, "high": "block", "critical": "block",
		},
		Categories: map[string]CategoryOverride{
			// Image metadata text is scanned by every text guard; its mere
			// presence is a statistic, not an incident.
			"media.metadata_text": {Severity: "info", Action: "flag"},
		},
		Params: map[string]any{
			"max_parts":               16,
			"max_part_bytes":          25 << 20,
			"max_total_bytes":         64 << 20,
			"max_pixels":              50_000_000,
			"max_extract_chars":       200_000,
			"max_audio_seconds":       1800,
			"max_archive_entries":     5000,
			"max_uncompressed_bytes":  200 << 20,
			"max_compression_ratio":   150,
			"max_pdf_ocr_images":      8,
			"extract_timeout_seconds": 60,
			"concurrency":             4,
			"fetch_remote":            false,
			"fetch_allow_hosts":       []any{},
			"forward":                 "native",
			"binary_redaction":        "replace_with_text",
			"ocr_scanned_documents":   true,
		},
	}
}

func customRuleDefaults(timeout time.Duration) *GuardConfig {
	return &GuardConfig{
		Enabled:  false,
		Timeout:  timeout,
		FailMode: FailOpen,
		Actions: map[string]string{
			"info": "flag", "low": "flag", "medium": "flag", "high": "block", "critical": "block",
		},
		Params: map[string]any{"rules": []any{}},
	}
}

func urlFilterDefaults(timeout time.Duration) *GuardConfig {
	return &GuardConfig{
		Enabled:  false,
		Timeout:  timeout,
		FailMode: FailOpen,
		Actions: map[string]string{
			"low": "flag", "medium": "redact", "high": "block", "critical": "block",
		},
		Params: map[string]any{
			"allow":             []any{},
			"deny":              []any{},
			"allowed_schemes":   []any{"https"},
			"allow_subdomains":  true,
			"block_userinfo":    true,
			"block_ip_literals": true,
			"block_private":     true,
			"severity":          "medium",
		},
	}
}

// StrictPolicy is the enterprise posture: default-deny, fail-closed, no
// unmasking of vaulted values on egress.
func StrictPolicy() *Policy {
	p := DefaultPolicy()
	p.Version = "1.0.0-strict"
	p.Name = "strict"
	p.Description = "Enterprise posture: fail-closed everywhere, lower injection threshold, no PII restore."
	p.DefaultFailMode = FailClosed
	p.DefaultActions = map[string]string{
		"info": "flag", "low": "flag", "medium": "block", "high": "block", "critical": "block",
	}

	// Raising DefaultActions is not enough on its own.
	//
	// Action resolution checks the per-guard map BEFORE the policy default, so
	// every guard that inherited an explicit "medium: flag" from the balanced
	// profile would keep flagging -- and the strict profile would quietly
	// enforce less than it advertises. That is the worst kind of policy bug:
	// the operator picked the stricter option and got weaker behaviour, with
	// nothing anywhere to tell them.
	//
	// "redact" is left alone. It is a stronger response than "flag", not a
	// weaker one than "block", and downgrading PII masking into an outright
	// refusal would break every legitimate request that merely mentions an
	// email address.
	for _, g := range p.Guards {
		g.FailMode = FailClosed
		for _, sev := range []string{"medium", "high", "critical"} {
			switch g.Actions[sev] {
			case "flag", "allow":
				g.Actions[sev] = "block"
			}
		}
	}
	p.Guards[GuardInjection].Threshold = 0.40
	p.Guards[GuardTopic].Threshold = 0.40
	p.Guards[GuardPII].Params["restore_outbound"] = false
	p.Guards[GuardRestore].Enabled = false
	p.Guards[GuardSchema].FailMode = FailClosed
	p.Guards[GuardQuota].Params["max_cost_usd"] = 1.00
	p.Guards[GuardBudget].Params["max_trace_cost_usd"] = 2.00
	p.Guards[GuardLoop].Params["max_steps"] = 12
	p.Guards[GuardToolResult].Threshold = 0.40
	// Strict means the gateway will not move money or change access, whatever
	// capabilities a session was granted. This is the one knob an operator can
	// set once instead of auditing every grant for the rest of the deployment.
	p.Guards[GuardToolSafety].Params["max_tier"] = "T3"
	return p
}

// ---- typed Params accessors -------------------------------------------------
//
// YAML gives us map[string]any; guards need typed values with clear errors.
// These helpers keep the "bad param" failure at construction time, where it
// surfaces as a startup error rather than a nil-map panic under load.

func (g *GuardConfig) Int(key string, def int) int {
	v, ok := g.Params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return def
}

func (g *GuardConfig) Float(key string, def float64) float64 {
	v, ok := g.Params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return def
}

func (g *GuardConfig) Bool(key string, def bool) bool {
	if v, ok := g.Params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func (g *GuardConfig) String(key, def string) string {
	if v, ok := g.Params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func (g *GuardConfig) Strings(key string) []string {
	v, ok := g.Params[key]
	if !ok {
		return nil
	}
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, fmt.Sprint(item))
		}
		return out
	}
	return nil
}

// EffectiveTimeout resolves the guard timeout against the policy default.
func (p *Policy) EffectiveTimeout(guard string) time.Duration {
	if g := p.Guard(guard); g.Timeout > 0 {
		return g.Timeout
	}
	if p.DefaultTimeout > 0 {
		return p.DefaultTimeout
	}
	return 10 * time.Millisecond
}

// EffectiveFailMode resolves the guard fail mode against the policy default.
func (p *Policy) EffectiveFailMode(guard string) FailMode {
	if g := p.Guard(guard); g.FailMode.Valid() {
		return g.FailMode
	}
	if p.DefaultFailMode.Valid() {
		return p.DefaultFailMode
	}
	return FailOpen
}
