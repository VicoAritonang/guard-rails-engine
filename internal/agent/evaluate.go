package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

// Request is one proposed tool call, with everything the controls need to
// judge it.
type Request struct {
	Trace          string
	Call           core.ToolCall
	Session        *core.SessionState
	IdempotencyKey string
	ApprovalToken  string

	// DryRun asks for a simulation instead of the real effect. A dry run is
	// still fully authorised -- capability, allowlist, taint -- because a
	// simulation that runs under weaker rules teaches the agent the wrong
	// thing about what it is allowed to do.
	DryRun bool
}

// Requirement is a control the caller has not yet satisfied, phrased as
// something they can act on.
//
// This is the part of the design that decides whether the whole system gets
// used or routed around. A gateway that answers "denied" forces the agent
// runtime to guess what to do next, and the guess is usually to retry, then to
// disable the gateway. Answering "denied, and here is the exact thing that is
// missing" turns enforcement into a protocol -- the same reason a good API
// returns 401 with a WWW-Authenticate header instead of a bare 403.
type Requirement struct {
	Control string `json:"control"`
	Message string `json:"message"`
	Remedy  string `json:"remedy"`
}

// Assessment is the verdict on one proposed call.
type Assessment struct {
	Tool      string   `json:"tool"`
	Tier      string   `json:"tier"`
	Signature string   `json:"signature"`
	Controls  []string `json:"controls"`

	Findings     []core.Finding `json:"findings,omitempty"`
	Requirements []Requirement  `json:"requirements,omitempty"`

	// Replay is true when this exact call already ran under this idempotency
	// key. The caller must return the earlier result rather than act again.
	Replay bool `json:"replay,omitempty"`

	// Reversible records whether the effect can be undone, and how, so the
	// answer is in the audit record rather than in someone's memory.
	Reversible bool   `json:"reversible"`
	Undo       string `json:"undo,omitempty"`
}

// Allowed reports whether the call may proceed.
//
// The rule is deliberately strict: any unmet requirement, or any finding at
// high severity or above, stops the call. Tool execution is the one place in
// this engine where "probably fine" is not an available answer, because there
// is no later stage that can take the effect back.
func (a *Assessment) Allowed() bool {
	if len(a.Requirements) > 0 {
		return false
	}
	for _, f := range a.Findings {
		if f.Severity >= core.SeverityHigh {
			return false
		}
	}
	return true
}

// Options configures the evaluator.
type Options struct {
	Catalog  *Catalog
	Approver *Approver

	// EgressAllowlist lists the domains a destination argument may point at.
	//
	// An empty list is treated as "not configured" rather than as "deny
	// everything", and reported once by `grctl policy lint`. Denying by
	// default here would be the more secure choice and the wrong one: it makes
	// every egress tool fail on day one, and a control that has to be switched
	// off to get the product working is a control that stays off.
	EgressAllowlist []string

	// MaxTier is the ceiling for the whole deployment. Anything above it is
	// refused regardless of capabilities, which is how an operator says "this
	// agent will never move money" once instead of auditing every grant.
	MaxTier Tier

	// Disabled switches off controls by policy, for a tenant that has accepted
	// the risk. Recorded on every assessment so the audit trail shows which
	// controls were not applied.
	Disabled Control

	Now func() time.Time
}

// Evaluator applies the tool-level controls. It is stateless and safe for
// concurrent use.
type Evaluator struct {
	opts Options
}

// NewEvaluator validates the options and builds an evaluator.
func NewEvaluator(opts Options) (*Evaluator, error) {
	if opts.Catalog == nil {
		c, err := DefaultCatalog()
		if err != nil {
			return nil, err
		}
		opts.Catalog = c
	}
	if opts.MaxTier == 0 {
		opts.MaxTier = T4
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Evaluator{opts: opts}, nil
}

// Catalog exposes the tool catalog in use.
func (e *Evaluator) Catalog() *Catalog { return e.opts.Catalog }

// Options exposes the effective configuration, for introspection endpoints.
func (e *Evaluator) Options() Options { return e.opts }

// Lint reports configuration weaknesses that are invisible at request time.
//
// These are deliberately not findings. A finding describes a request; a lint
// describes a deployment, and mixing the two means every benign call carries a
// detection that nobody can act on from where they are standing.
func (e *Evaluator) Lint() []string {
	var out []string
	if len(e.opts.EgressAllowlist) == 0 {
		var egress []string
		for _, t := range e.opts.Catalog.Tools() {
			if t.Egress {
				egress = append(egress, t.Name)
			}
		}
		if len(egress) > 0 {
			out = append(out, fmt.Sprintf(
				"no egress allowlist is configured: %s may send data to any destination "+
					"(set guards.tool_safety.params.egress_allowlist)",
				strings.Join(egress, ", ")))
		}
	}
	if e.opts.Approver == nil && e.opts.MaxTier >= T4 {
		out = append(out, "no approval signing key is available, so every T4 tool will be "+
			"refused; set a GUARDRAILS_SECRET of at least 16 bytes, or lower max_tier to T3")
	}
	if e.opts.Disabled != 0 {
		out = append(out, fmt.Sprintf("controls disabled by policy: %s", e.opts.Disabled))
	}
	for _, t := range e.opts.Catalog.Tools() {
		if t.Waive != 0 {
			out = append(out, fmt.Sprintf("tool %q waives %s", t.Name, t.Waive))
		}
		if t.Tier() >= T3 && t.MaxPerSession == 0 {
			out = append(out, fmt.Sprintf(
				"tool %q is tier %s with no per-session limit", t.Name, t.Tier()))
		}
	}
	return out
}

const guardName = "tool_safety"

// Assess runs every applicable control against one proposed call.
//
// It never mutates the session. Committing the effects of a call -- the rate
// counter, the idempotency claim, the spent approval -- is Commit's job, and
// keeping the two apart is what lets a guard evaluate a call it is not going to
// execute without corrupting the trace.
func (e *Evaluator) Assess(req Request) Assessment {
	sig := core.CallSignature(req.Call)
	name := req.Call.Name

	tool, known := e.opts.Catalog.Lookup(name)
	if !known {
		// A call to a tool that is not in the catalog is either a hallucinated
		// name or an attempt to reach something the operator never registered.
		// Both are refusals, and neither has a remedy the agent can apply.
		a := Assessment{Tool: name, Tier: "unknown", Signature: sig}
		a.Findings = append(a.Findings, finding("unknown_tool", "tool.unknown",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("tool %q is not in the catalog", name),
			map[string]string{"tool": name}))
		return a
	}

	controls := tool.Controls() &^ e.opts.Disabled
	a := Assessment{
		Tool:       tool.Name,
		Tier:       tool.Tier().String(),
		Signature:  sig,
		Controls:   controls.Names(),
		Reversible: tool.Reversibility != RevIrreversible,
		Undo:       tool.Undo,
	}

	if tool.Tier() > e.opts.MaxTier {
		a.Findings = append(a.Findings, finding("tier_ceiling", "tool.tier_ceiling",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("tool %q is tier %s; this deployment permits at most %s",
				tool.Name, tool.Tier(), e.opts.MaxTier),
			map[string]string{"tool": tool.Name, "tier": tool.Tier().String()}))
		return a
	}

	args := normalizeArgs(req.Call)

	if controls.Has(CtrlSchema) {
		a.Findings = append(a.Findings, e.checkSchema(tool, args)...)
	}
	if controls.Has(CtrlCapability) {
		a.checkCapability(tool, req.Session)
	}
	if controls.Has(CtrlRateLimit) {
		a.checkRateLimit(tool, req.Session)
	}
	if controls.Has(CtrlAmountLimit) {
		a.checkAmount(tool, args)
	}
	if controls.Has(CtrlEgressAllowlist) {
		a.Findings = append(a.Findings, e.checkEgress(tool, args)...)
	}
	if controls.Has(CtrlTaintBlock) {
		a.Findings = append(a.Findings, e.checkTaint(tool, args, req.Session)...)
	}
	if controls.Has(CtrlTrifecta) {
		a.checkTrifecta(tool, req.Session)
	}
	// The conflict and replay checks run whenever a key was supplied, not only
	// when the tier demands one. A caller that sends an idempotency key
	// believes it is protected by it, and silently ignoring a key collision on
	// a T2 tool because T2 does not require keys would break exactly the
	// promise the caller thought they had. Only the "you must supply one"
	// requirement is tier-gated.
	if controls.Has(CtrlIdempotency) || req.IdempotencyKey != "" {
		a.checkIdempotency(tool, req, sig, controls.Has(CtrlIdempotency))
	}
	// A verified replay is answered from the ledger and never reaches the
	// executor, so the controls that gate an *effect* do not apply to it.
	// Demanding a fresh approval for a call that is not going to happen is not
	// merely redundant: it teaches an operator to mint a second signature for
	// an action that already occurred, which is exactly the habit the
	// single-use rule exists to prevent.
	if !a.Replay {
		if controls.Has(CtrlDryRun) && !req.DryRun {
			a.checkDryRun(tool, req.Session, sig)
		}
		if controls.Has(CtrlApproval) && !req.DryRun {
			e.checkApproval(&a, tool, req, sig)
		}
	}

	sort.SliceStable(a.Findings, func(i, j int) bool {
		return a.Findings[i].Severity > a.Findings[j].Severity
	})
	return a
}

// ---------------------------------------------------------------- individual controls

func (e *Evaluator) checkSchema(t *Tool, args map[string]any) []core.Finding {
	var out []core.Finding
	declared := map[string]Param{}
	for _, p := range t.Params {
		declared[p.Name] = p
	}

	for _, p := range t.Params {
		v, present := args[p.Name]
		if !present || v == nil {
			if p.Required {
				out = append(out, finding("missing_argument", "tool.schema_violation",
					core.SeverityHigh, 1.0,
					fmt.Sprintf("tool %q requires argument %q", t.Name, p.Name),
					map[string]string{"tool": t.Name, "param": p.Name}))
			}
			continue
		}
		if err := checkType(p, v); err != nil {
			out = append(out, finding("bad_argument_type", "tool.schema_violation",
				core.SeverityHigh, 1.0,
				fmt.Sprintf("tool %q argument %q: %v", t.Name, p.Name, err),
				map[string]string{"tool": t.Name, "param": p.Name}))
			continue
		}
		if s, ok := v.(string); ok {
			if p.MaxLen > 0 && len(s) > p.MaxLen {
				out = append(out, finding("argument_too_long", "tool.schema_violation",
					core.SeverityMedium, 1.0,
					fmt.Sprintf("tool %q argument %q is %d bytes, limit is %d",
						t.Name, p.Name, len(s), p.MaxLen),
					map[string]string{"tool": t.Name, "param": p.Name}))
			}
			if len(p.Enum) > 0 && !hasFold(p.Enum, s) {
				out = append(out, finding("argument_not_in_enum", "tool.schema_violation",
					core.SeverityHigh, 1.0,
					fmt.Sprintf("tool %q argument %q must be one of %s",
						t.Name, p.Name, strings.Join(p.Enum, ", ")),
					map[string]string{"tool": t.Name, "param": p.Name}))
			}
		}
	}

	// Undeclared arguments are a finding, not a shrug. A model that invents a
	// parameter has either misunderstood the tool or been talked into passing
	// something the executor might honour, and both are worth seeing.
	for name := range args {
		if _, ok := declared[name]; !ok {
			out = append(out, finding("undeclared_argument", "tool.schema_violation",
				core.SeverityMedium, 0.9,
				fmt.Sprintf("tool %q was called with undeclared argument %q", t.Name, name),
				map[string]string{"tool": t.Name, "param": name}))
		}
	}
	return out
}

func (a *Assessment) checkCapability(t *Tool, s *core.SessionState) {
	if t.Capability == "" || s.Has(t.Capability) {
		return
	}
	a.Findings = append(a.Findings, finding("capability_missing", "tool.capability_missing",
		core.SeverityHigh, 1.0,
		fmt.Sprintf("tool %q requires capability %q, which this session was not granted",
			t.Name, t.Capability),
		map[string]string{"tool": t.Name, "capability": t.Capability}))
	a.Requirements = append(a.Requirements, Requirement{
		Control: "capability",
		Message: fmt.Sprintf("session lacks capability %q", t.Capability),
		Remedy: fmt.Sprintf(
			"grant %q when the session is created, or route this step to an agent that holds it",
			t.Capability),
	})
}

func (a *Assessment) checkRateLimit(t *Tool, s *core.SessionState) {
	if t.MaxPerSession <= 0 {
		return
	}
	used := s.Count(t.Name)
	if used < t.MaxPerSession {
		return
	}
	a.Findings = append(a.Findings, finding("rate_limit", "tool.rate_limit",
		core.SeverityHigh, 1.0,
		fmt.Sprintf("tool %q already ran %d times in this session, limit is %d",
			t.Name, used, t.MaxPerSession),
		map[string]string{"tool": t.Name, "used": strconv.Itoa(used),
			"limit": strconv.Itoa(t.MaxPerSession)}))
	a.Requirements = append(a.Requirements, Requirement{
		Control: "rate_limit",
		Message: fmt.Sprintf("per-session limit of %d reached for %q", t.MaxPerSession, t.Name),
		Remedy:  "start a new session, or raise max_per_session in the tool catalog",
	})
}

func (a *Assessment) checkAmount(t *Tool, args map[string]any) {
	for _, p := range t.Params {
		if !p.Amount {
			continue
		}
		v, ok := toFloat(args[p.Name])
		if !ok {
			continue // a non-numeric amount is already a schema finding
		}
		switch {
		case v < 0:
			a.Findings = append(a.Findings, finding("negative_amount", "tool.amount_limit",
				core.SeverityHigh, 1.0,
				fmt.Sprintf("tool %q was called with a negative %s", t.Name, p.Name),
				map[string]string{"tool": t.Name, "param": p.Name}))
		case v > t.AmountLimitUSD:
			a.Findings = append(a.Findings, finding("amount_limit", "tool.amount_limit",
				core.SeverityCritical, 1.0,
				fmt.Sprintf("tool %q was called with %s=%.2f, ceiling is %.2f",
					t.Name, p.Name, v, t.AmountLimitUSD),
				map[string]string{"tool": t.Name, "param": p.Name,
					"amount": fmt.Sprintf("%.2f", v),
					"limit":  fmt.Sprintf("%.2f", t.AmountLimitUSD)}))
			a.Requirements = append(a.Requirements, Requirement{
				Control: "amount_limit",
				Message: fmt.Sprintf("%s exceeds the per-call ceiling of %.2f", p.Name, t.AmountLimitUSD),
				Remedy:  "split the action, or have a human perform it outside the agent",
			})
		}

		// The ceiling is a number, not a currency-aware limit. Saying so in the
		// record is better than pretending the comparison meant more than it
		// did: 500 IDR and 500 USD are not the same risk, and this control does
		// not know the difference.
		if cur, ok := args["currency"].(string); ok && !strings.EqualFold(cur, "USD") {
			a.Findings = append(a.Findings, finding("amount_currency_unconverted",
				"tool.amount_unconverted", core.SeverityInfo, 0.5,
				fmt.Sprintf("ceiling compared against %s without conversion", strings.ToUpper(cur)),
				map[string]string{"tool": t.Name, "currency": strings.ToUpper(cur)}))
		}
	}
}

func (e *Evaluator) checkEgress(t *Tool, args map[string]any) []core.Finding {
	p, ok := t.Destination()
	if !ok {
		return nil
	}
	var out []core.Finding
	opaqueGoverned := hasOpaqueEntry(e.opts.EgressAllowlist)

	for _, raw := range stringValues(args[p.Name]) {
		d := ParseDestination(raw)

		// A domain allowlist governs network destinations. A bank account
		// number and a chat channel are destinations too, and checking them
		// against a list of hostnames denies every one of them -- which reads
		// like a working control and is really just a broken comparison. They
		// are governed instead by capability, approval and the amount ceiling,
		// unless the operator has explicitly listed opaque destinations, in
		// which case an exact match is required.
		//
		// The residual risk is real and worth naming: nothing here constrains
		// which account a transfer reaches. The right instrument for that is a
		// payee allowlist inside the payments system, not a hostname list at
		// the gateway.
		if d.Kind == "opaque" && !opaqueGoverned {
			continue
		}

		switch d.Scope {
		case "metadata":
			out = append(out, finding("metadata_endpoint", "tool.metadata_endpoint",
				core.SeverityCritical, 1.0,
				fmt.Sprintf("tool %q targets the cloud metadata endpoint %q", t.Name, d.Host),
				map[string]string{"tool": t.Name, "host": d.Host}))
			continue
		case "private":
			out = append(out, finding("private_destination", "tool.private_network",
				core.SeverityHigh, 0.95,
				fmt.Sprintf("tool %q targets internal host %q", t.Name, d.Host),
				map[string]string{"tool": t.Name, "host": d.Host}))
			continue
		}

		if len(e.opts.EgressAllowlist) == 0 {
			// "No allowlist is configured" is a property of the deployment, not
			// of this request, and emitting it as a per-call finding made every
			// benign egress call look like a detection -- which is measurable:
			// it put a false positive on the one benign web_fetch in the eval
			// corpus and dragged benign FPR from 0.0% to 3.1%. It surfaces once,
			// from Lint, where the person who can fix it will see it.
			continue
		}
		if !d.AllowedBy(e.opts.EgressAllowlist) {
			out = append(out, finding("egress_denied", "tool.egress_denied",
				core.SeverityHigh, 1.0,
				fmt.Sprintf("tool %q targets %q, which is not on the egress allowlist",
					t.Name, redactDestination(d)),
				map[string]string{"tool": t.Name, "destination": redactDestination(d),
					"kind": d.Kind}))
		}
	}
	return out
}

// checkTaint is the control that turns prompt injection from a text problem
// into an action problem.
//
// The attack it exists for has three steps and no individually suspicious one:
// the agent reads a document, the document contains an instruction, the agent
// obeys it. Nothing about the final tool call looks wrong -- send_email is a
// tool the agent is allowed to use, to an address that is a perfectly valid
// address. What is wrong is the provenance of the argument, and provenance is
// the only place the attack is visible.
func (e *Evaluator) checkTaint(t *Tool, args map[string]any, s *core.SessionState) []core.Finding {
	if s == nil || s.Taint.Empty() {
		return nil
	}
	var out []core.Finding
	for _, p := range t.Params {
		// Only the arguments that decide where the effect lands or what it
		// carries. Matching every argument would flag an agent that summarises
		// a page into a ticket title, which is the product working.
		if !p.Destination && !p.Payload {
			continue
		}
		for _, v := range stringValues(args[p.Name]) {
			m := s.Taint.Match(v)
			if !m.Hit() {
				continue
			}
			sev, score := core.SeverityHigh, 0.85
			if p.Destination {
				// A destination lifted from untrusted content is the whole
				// attack. Nothing legitimate makes the agent mail a stranger
				// an address it found on a page it was asked to summarise.
				sev, score = core.SeverityCritical, 0.97
			}
			out = append(out, finding("untrusted_derived_argument", "tool.taint_derived",
				sev, score,
				fmt.Sprintf("tool %q argument %q was derived from untrusted content ingested earlier in this trace (%s match)",
					t.Name, p.Name, m.Kind),
				map[string]string{
					"tool":    t.Name,
					"param":   p.Name,
					"match":   m.Kind,
					"ratio":   fmt.Sprintf("%.2f", m.Ratio),
					"sources": strings.Join(s.Taint.Sources, ","),
				}))
		}
	}
	return out
}

func (a *Assessment) checkTrifecta(t *Tool, s *core.SessionState) {
	if s == nil {
		return
	}
	// The tool about to run supplies the third leg, so evaluate the ledger with
	// it already counted. Waiting until after execution would report the
	// trifecta in the audit log of the request that completed it.
	eff := s.Effects
	eff.MarkCanExfiltrate(t.Name)
	if !eff.Trifecta() {
		return
	}
	a.Findings = append(a.Findings, finding("lethal_trifecta", "tool.trifecta",
		core.SeverityCritical, 0.95,
		fmt.Sprintf("this session has read private data (%s), ingested untrusted content (%s), and is now calling %q, which can send data outward",
			eff.Witness["read_private"], eff.Witness["ingested_untrusted"], t.Name),
		map[string]string{
			"tool":              t.Name,
			"read_private":      eff.Witness["read_private"],
			"untrusted_source":  eff.Witness["ingested_untrusted"],
			"exfiltration_tool": t.Name,
		}))
	a.Requirements = append(a.Requirements, Requirement{
		Control: "trifecta",
		Message: "private data, untrusted content and an outbound channel are all present in one session",
		Remedy: "split the work: do the retrieval in a session without private data, " +
			"or the send in a session that never read the untrusted source",
	})
}

func (a *Assessment) checkIdempotency(t *Tool, req Request, sig string, required bool) {
	if req.IdempotencyKey == "" {
		if !required {
			return
		}
		a.Findings = append(a.Findings, finding("idempotency_missing", "tool.idempotency_missing",
			core.SeverityHigh, 1.0,
			fmt.Sprintf("tool %q requires an idempotency key", t.Name),
			map[string]string{"tool": t.Name}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "idempotency",
			Message: "no idempotency key was supplied",
			Remedy: "resend with idempotency_key set to a value derived from the intent, " +
				"so a retry after a timeout repeats the request without repeating the effect",
		})
		return
	}
	if req.Session == nil {
		return
	}
	prior, seen := req.Session.Executed[req.IdempotencyKey]
	switch {
	case !seen:
		return
	case prior == sig:
		a.Replay = true
		a.Findings = append(a.Findings, finding("idempotent_replay", "tool.replay",
			core.SeverityMedium, 1.0,
			fmt.Sprintf("this exact call already ran under key %q; return the stored result rather than acting again",
				req.IdempotencyKey),
			map[string]string{"tool": t.Name, "key": req.IdempotencyKey}))
	default:
		// The same key on different arguments is the failure that turns a
		// retry-safety mechanism into a hazard, because the caller believes
		// the key is protecting them.
		a.Findings = append(a.Findings, finding("idempotency_conflict", "tool.idempotency_conflict",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("idempotency key %q was already used for different arguments", req.IdempotencyKey),
			map[string]string{"tool": t.Name, "key": req.IdempotencyKey}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "idempotency",
			Message: "idempotency key collision",
			Remedy:  "use a key derived from the arguments, not from the step number",
		})
	}
}

func (a *Assessment) checkDryRun(t *Tool, s *core.SessionState, sig string) {
	if s.WasSimulated(sig) {
		return
	}
	a.Findings = append(a.Findings, finding("dry_run_required", "tool.dry_run_required",
		core.SeverityHigh, 1.0,
		fmt.Sprintf("tool %q must be simulated before it is executed", t.Name),
		map[string]string{"tool": t.Name, "signature": sig}))
	a.Requirements = append(a.Requirements, Requirement{
		Control: "dry_run",
		Message: "this call has not been simulated",
		Remedy: "resend with dry_run=true, show the simulated effect to the approver, " +
			"then resend the identical call for execution",
	})
}

func (e *Evaluator) checkApproval(a *Assessment, t *Tool, req Request, sig string) {
	if e.opts.Approver == nil {
		// No approver configured means approvals cannot be verified. Failing
		// closed here is the only defensible choice: the alternative is a
		// deployment that silently executes wire transfers because the operator
		// forgot to set a secret.
		a.Findings = append(a.Findings, finding("approval_unavailable", "tool.approval_required",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("tool %q requires human approval but no approver is configured", t.Name),
			map[string]string{"tool": t.Name}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "approval",
			Message: "the gateway has no approval signing key",
			Remedy:  "configure GUARDRAILS_SECRET and restart, or lower max_tier below T4",
		})
		return
	}
	if req.ApprovalToken == "" {
		a.Findings = append(a.Findings, finding("approval_required", "tool.approval_required",
			core.SeverityHigh, 1.0,
			fmt.Sprintf("tool %q is tier %s and requires a human approval", t.Name, t.Tier()),
			map[string]string{"tool": t.Name, "signature": sig}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "approval",
			Message: fmt.Sprintf("no approval token for signature %s", sig),
			Remedy: fmt.Sprintf(
				"have a person review this exact call and POST /v1/agent/approve with signature=%s", sig),
		})
		return
	}

	grant, err := e.opts.Approver.Verify(req.ApprovalToken, req.Trace, t.Name, sig)
	if err != nil {
		a.Findings = append(a.Findings, finding("approval_invalid", "tool.approval_invalid",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("approval rejected: %v", err),
			map[string]string{"tool": t.Name}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "approval",
			Message: err.Error(),
			Remedy:  "obtain a fresh approval for the exact call being attempted",
		})
		return
	}
	if req.Session.ApprovalSpent(grant.ID) {
		// One approval, one action. Without this, an agent that obtained a
		// signature for one payment could make the same payment in a loop, and
		// every call would verify perfectly.
		a.Findings = append(a.Findings, finding("approval_reused", "tool.approval_reused",
			core.SeverityCritical, 1.0,
			fmt.Sprintf("approval %s has already been used in this session", grant.ID),
			map[string]string{"tool": t.Name, "grant": grant.ID}))
		a.Requirements = append(a.Requirements, Requirement{
			Control: "approval",
			Message: "approval already spent",
			Remedy:  "each irreversible action needs its own approval",
		})
	}
}

// Commit records the effects of a call that was allowed and executed.
//
// Separate from Assess so that evaluating a call never advances the trace. The
// runtime guard assesses without committing; the broker commits only after the
// executor returns.
func (e *Evaluator) Commit(req Request, a *Assessment) {
	s := req.Session
	if s == nil {
		return
	}
	tool, ok := e.opts.Catalog.Lookup(a.Tool)
	if !ok {
		return
	}
	s.RecordCall(tool.Name)
	if req.IdempotencyKey != "" {
		s.ClaimIdempotencyKey(req.IdempotencyKey, a.Signature)
	}
	if tool.Egress {
		s.Effects.MarkCanExfiltrate(tool.Name)
	}
	if req.ApprovalToken != "" && e.opts.Approver != nil {
		if g, err := e.opts.Approver.Verify(req.ApprovalToken, req.Trace, tool.Name, a.Signature); err == nil {
			s.ConsumeApproval(g.ID)
		}
	}
}

// ObserveResult folds a tool's output into the session: what it exposed, and
// what it made untrusted.
//
// This is the other half of the tool rails and the half that is easy to forget.
// A control that inspects calls but never inspects results cannot see the
// trifecta forming, because two of its three legs are properties of what came
// back rather than of what was asked for.
func (e *Evaluator) ObserveResult(s *core.SessionState, res core.ToolResult) {
	if s == nil {
		return
	}
	tool, known := e.opts.Catalog.Lookup(res.Name)
	exposure := ExposureNone
	if known {
		exposure = tool.Exposure
	}
	if res.Origin.Untrusted() {
		exposure |= ExposureUntrusted
	}
	if res.Sensitive {
		exposure |= ExposurePrivate
	}

	if exposure.Has(ExposurePrivate) {
		s.Effects.MarkReadPrivate(res.Name)
	}
	if exposure.Has(ExposureUntrusted) {
		s.Effects.MarkIngestedUntrusted(res.Name)
		s.Taint.Add(res.Name, res.Content)
	}
}

// ---------------------------------------------------------------- helpers

func finding(rule, category string, sev core.Severity, score float64, msg string, meta map[string]string) core.Finding {
	f := core.NewFinding(guardName, rule, category, sev, score, msg)
	f.Meta = meta
	return f
}

// normalizeArgs returns the call's arguments as a map, parsing Raw when the
// structured form is absent. Every control reads arguments through this, so a
// call that arrives as raw JSON is checked exactly as carefully as one that
// arrives parsed.
func normalizeArgs(c core.ToolCall) map[string]any {
	if len(c.Arguments) > 0 {
		return c.Arguments
	}
	if c.Raw == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(c.Raw), &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func checkType(p Param, v any) error {
	switch p.Type {
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("expected a string, got %T", v)
		}
	case "integer":
		f, ok := toFloat(v)
		if !ok {
			return fmt.Errorf("expected an integer, got %T", v)
		}
		if f != float64(int64(f)) {
			return fmt.Errorf("expected an integer, got %v", f)
		}
	case "number":
		if _, ok := toFloat(v); !ok {
			return fmt.Errorf("expected a number, got %T", v)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("expected a boolean, got %T", v)
		}
	case "array":
		if _, ok := v.([]any); !ok {
			if _, ok := v.([]string); !ok {
				return fmt.Errorf("expected an array, got %T", v)
			}
		}
	}
	return nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		// A model that emits "12.40" for a numeric field is common enough that
		// refusing to parse it would reject correct intent; the value is still
		// held to the ceiling.
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// stringValues flattens an argument to the strings inside it, so a destination
// declared as an array of recipients is checked element by element.
func stringValues(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, stringValues(e)...)
		}
		return out
	default:
		return nil
	}
}

// hasOpaqueEntry reports whether the allowlist mentions anything that is not a
// domain, which is how an operator opts in to governing opaque destinations.
func hasOpaqueEntry(allowlist []string) bool {
	for _, e := range allowlist {
		e = strings.TrimSpace(strings.TrimPrefix(e, "*."))
		if e != "" && e != "*" && !strings.Contains(e, ".") {
			return true
		}
	}
	return false
}

func hasFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// redactDestination keeps a denied destination legible without echoing a full
// address into a log line. The domain is the part an operator needs.
func redactDestination(d Destination) string {
	switch d.Kind {
	case "email":
		return "…@" + d.Host
	case "url":
		return d.Host
	default:
		if len(d.Raw) > 64 {
			return d.Raw[:64] + "…"
		}
		return d.Raw
	}
}
