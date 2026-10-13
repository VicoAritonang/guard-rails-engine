// Package agent implements tool-level safety: the controls that have to run
// before a tool executes, because by the time there is a completion to inspect
// the money has moved and the email has been delivered.
//
// The input and output rails in internal/guards shape text. This package
// governs actions, and actions are different in one way that changes the whole
// design: they cannot be un-run. An output rail that misses a bad sentence
// produces a bad sentence. A tool rail that misses a bad call produces a
// deleted production table. Everything here follows from that asymmetry --
// fail-closed by default, human approval for the irreversible tier, and a
// dry run before any call that cannot be taken back.
package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Reversibility is the first risk axis: what it costs to undo the effect.
//
// This is a property of the effect in the real world, not of the code. A
// "delete" that writes to a soft-delete column is compensable. A "delete" that
// issues a DROP is not, no matter how the function is named.
type Reversibility int

const (
	// RevNone marks a call with no effect at all: a read.
	RevNone Reversibility = iota
	// RevCompensable marks an effect with a defined, automatable undo -- a
	// previous file version, a soft delete, a ticket that can be reopened.
	RevCompensable
	// RevIrreversible marks an effect that no later call can retract. The
	// recipient has already read the email; the counterparty already has the
	// money.
	RevIrreversible
)

var revNames = map[Reversibility]string{
	RevNone:         "none",
	RevCompensable:  "compensable",
	RevIrreversible: "irreversible",
}

func (r Reversibility) String() string { return orUnknown(revNames[r]) }

// Radius is the second risk axis: how far the effect travels.
type Radius int

const (
	// RadiusSelf stays inside the agent's own scratch space.
	RadiusSelf Radius = iota
	// RadiusWorkspace touches this user's own data.
	RadiusWorkspace
	// RadiusOrg touches shared systems of record that colleagues depend on.
	RadiusOrg
	// RadiusExternal crosses the trust boundary: a third party sees it.
	RadiusExternal
	// RadiusCritical touches money, identity, credentials, or production
	// infrastructure -- the effects with legal or safety consequences.
	RadiusCritical
)

var radiusNames = map[Radius]string{
	RadiusSelf:      "self",
	RadiusWorkspace: "workspace",
	RadiusOrg:       "org",
	RadiusExternal:  "external",
	RadiusCritical:  "critical",
}

func (r Radius) String() string { return orUnknown(radiusNames[r]) }

// Tier is the derived effect severity, T0 through T4.
type Tier int

const (
	T0 Tier = iota // inert: no effect worth governing
	T1             // read: no effect, but data leaves a system of record
	T2             // reversible write: undo exists and is automatable
	T3             // external effect: visible outside, retraction is best-effort
	T4             // irreversible critical: money, destruction, access, production
)

var tierNames = map[Tier]string{
	T0: "T0-inert",
	T1: "T1-read",
	T2: "T2-reversible",
	T3: "T3-external",
	T4: "T4-irreversible",
}

func (t Tier) String() string { return orUnknown(tierNames[t]) }

// tierMatrix derives the tier from the two axes.
//
// Written as a table rather than a chain of conditionals because this is the
// part a security reviewer will actually argue with, and a table can be read
// and disputed cell by cell. Rows are reversibility, columns are radius.
//
//	                self      workspace   org       external   critical
//	read            T0        T1          T1        T1         T2
//	compensable     T1        T2          T2        T3         T3
//	irreversible    T2        T3          T3        T4         T4
var tierMatrix = [3][5]Tier{
	{T0, T1, T1, T1, T2},
	{T1, T2, T2, T3, T3},
	{T2, T3, T3, T4, T4},
}

// DeriveTier looks up the effect tier for a pair of axes.
func DeriveTier(rev Reversibility, rad Radius) Tier {
	r := clampInt(int(rev), 0, len(tierMatrix)-1)
	c := clampInt(int(rad), 0, len(tierMatrix[0])-1)
	return tierMatrix[r][c]
}

// Exposure is the orthogonal axis: not what the call can break, but what it can
// leak or let in.
//
// Keeping this separate from the tier is the design decision in this file that
// pays for itself. web_fetch breaks nothing -- it is a read, tier T0 by effect
// -- and it is also the single most dangerous tool in the catalog, because it
// is how attacker-authored text gets into the context window. Folding both
// concerns into one number would have forced a choice between calling it safe
// and calling it destructive, and it is neither.
type Exposure int

const (
	// ExposureNone returns nothing that came from a person.
	ExposureNone Exposure = 0
	// ExposurePrivate returns data out of a system of record.
	ExposurePrivate Exposure = 1 << iota
	// ExposureUntrusted returns content whose author is not the operator and
	// not the user: a web page, an inbound email, a shared document.
	ExposureUntrusted
)

func (e Exposure) Has(f Exposure) bool { return e&f != 0 }

func (e Exposure) String() string {
	var parts []string
	if e.Has(ExposurePrivate) {
		parts = append(parts, "private")
	}
	if e.Has(ExposureUntrusted) {
		parts = append(parts, "untrusted")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
}

// Control is one required safeguard. Controls are a bitmask so that the
// baseline for a tier and the extras a specific tool declares compose by
// bitwise OR, and so that a decision can report the exact set that applied.
type Control uint32

const (
	// CtrlSchema validates arguments against the declared parameter schema.
	CtrlSchema Control = 1 << iota
	// CtrlCapability requires the session to hold the tool's capability.
	CtrlCapability
	// CtrlRateLimit bounds executions per session.
	CtrlRateLimit
	// CtrlAudit writes a tamper-evident receipt.
	CtrlAudit
	// CtrlIdempotency requires a caller-supplied key, so a retry after a
	// timeout cannot send the payment twice.
	CtrlIdempotency
	// CtrlTaintBlock refuses arguments derived from untrusted content.
	CtrlTaintBlock
	// CtrlEgressAllowlist restricts destinations to the configured list.
	CtrlEgressAllowlist
	// CtrlDryRun requires a successful simulation before the real call.
	CtrlDryRun
	// CtrlApproval requires a signed, single-use human approval.
	CtrlApproval
	// CtrlTrifecta refuses the call when the session has already read private
	// data and ingested untrusted content.
	CtrlTrifecta
	// CtrlAmountLimit caps a monetary value carried in the arguments.
	CtrlAmountLimit
)

var controlNames = []struct {
	c    Control
	name string
}{
	{CtrlSchema, "schema"},
	{CtrlCapability, "capability"},
	{CtrlRateLimit, "rate_limit"},
	{CtrlAudit, "audit"},
	{CtrlIdempotency, "idempotency"},
	{CtrlTaintBlock, "taint_block"},
	{CtrlEgressAllowlist, "egress_allowlist"},
	{CtrlDryRun, "dry_run"},
	{CtrlApproval, "approval"},
	{CtrlTrifecta, "trifecta"},
	{CtrlAmountLimit, "amount_limit"},
}

// Has reports whether a control is in the set.
func (c Control) Has(x Control) bool { return c&x != 0 }

// Names lists the controls in the set, in declaration order.
func (c Control) Names() []string {
	var out []string
	for _, e := range controlNames {
		if c.Has(e.c) {
			out = append(out, e.name)
		}
	}
	return out
}

func (c Control) String() string {
	n := c.Names()
	if len(n) == 0 {
		return "none"
	}
	return strings.Join(n, ",")
}

// ParseControl resolves a control by name, for policy files.
func ParseControl(s string) (Control, error) {
	for _, e := range controlNames {
		if e.name == s {
			return e.c, nil
		}
	}
	return 0, fmt.Errorf("unknown control %q", s)
}

// baselineControls is the minimum set required at each tier.
//
// The escalation is deliberate and cumulative. T2 is where least privilege
// starts to matter, because something is being written. T3 adds the controls
// that assume the arguments may have been authored by an attacker rather than
// by the user: no values derived from untrusted content, an idempotency key so
// a network retry cannot double-post, and the trifecta check. T4 adds the two
// controls that cost a human their time, on the grounds that a wire transfer is
// worth a human's time: simulate first, then collect a signature.
//
// CtrlEgressAllowlist is deliberately absent from every row. It is not a
// function of tier -- it applies to tools that send bytes outward, which is a
// property of the tool, so Tool.Controls derives it from the Egress flag. A
// baseline that demanded an allowlist from execute_shell, which has no
// destination argument to check, would be dead configuration that reads like
// protection.
var baselineControls = map[Tier]Control{
	T0: CtrlSchema,
	T1: CtrlSchema | CtrlCapability | CtrlRateLimit,
	T2: CtrlSchema | CtrlCapability | CtrlRateLimit | CtrlAudit,
	T3: CtrlSchema | CtrlCapability | CtrlRateLimit | CtrlAudit |
		CtrlIdempotency | CtrlTaintBlock | CtrlTrifecta,
	T4: CtrlSchema | CtrlCapability | CtrlRateLimit | CtrlAudit |
		CtrlIdempotency | CtrlTaintBlock | CtrlTrifecta |
		CtrlDryRun | CtrlApproval,
}

// BaselineControls returns the required control set for a tier.
func BaselineControls(t Tier) Control { return baselineControls[t] }

// Tiers lists every tier in order, for report rendering.
func Tiers() []Tier { return []Tier{T0, T1, T2, T3, T4} }

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
