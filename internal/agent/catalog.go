package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Param describes one tool argument.
//
// Three of the flags mark *roles* rather than types, because the controls need
// to know which argument means what. "Validate that url is a string" is worth
// little; "this is the argument that decides where the data goes, so apply the
// egress allowlist and the taint check to it" is worth a great deal.
type Param struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // string | integer | number | boolean | array
	Required bool     `json:"required,omitempty"`
	MaxLen   int      `json:"max_len,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	Desc     string   `json:"description,omitempty"`

	// Destination names where the effect lands: a recipient, a URL, a channel,
	// an account number. Egress allowlisting and taint blocking apply here.
	Destination bool `json:"destination,omitempty"`
	// Payload carries the content being sent or written. Leak scanning applies
	// here.
	Payload bool `json:"payload,omitempty"`
	// Amount carries a monetary value, subject to a per-call ceiling.
	Amount bool `json:"amount,omitempty"`
}

// Tool is one entry in the catalog: everything the broker needs to decide how
// carefully to treat a call to it.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Domain      string `json:"domain"`

	Reversibility Reversibility `json:"-"`
	Radius        Radius        `json:"-"`
	Exposure      Exposure      `json:"-"`

	// Egress marks a tool that moves bytes outside the trust boundary. It is
	// separate from Radius because a plain HTTP GET has a tiny blast radius and
	// is still a perfectly good exfiltration channel: the secret rides in the
	// query string.
	Egress bool `json:"egress"`

	// Capability the session must hold. Empty only for T0 tools.
	Capability string `json:"capability,omitempty"`

	Params []Param `json:"params,omitempty"`

	// Extra adds controls beyond the tier baseline, for a tool whose specific
	// shape is riskier than its tier.
	Extra Control `json:"-"`
	// Waive removes controls from the baseline. Present because a blanket rule
	// with no escape hatch gets disabled wholesale during the first incident;
	// every use of it in the built-in catalog carries a written reason.
	Waive Control `json:"-"`

	// MaxPerSession bounds executions in one trace. Zero means unlimited, which
	// is only appropriate for reads.
	MaxPerSession int `json:"max_per_session,omitempty"`

	// AmountLimitUSD caps any parameter marked Amount.
	AmountLimitUSD float64 `json:"amount_limit_usd,omitempty"`

	// Undo names the compensating action, empty when there is none. A tool
	// declaring RevCompensable without an Undo is rejected at catalog build:
	// "it can be undone" is a claim, and an unnamed undo is an unbacked one.
	Undo string `json:"undo,omitempty"`

	// Rationale is the one-line justification for the risk grading, rendered
	// into the control matrix so a reviewer can dispute it.
	Rationale string `json:"rationale,omitempty"`
}

// Tier is the derived effect severity.
func (t *Tool) Tier() Tier { return DeriveTier(t.Reversibility, t.Radius) }

// Controls is the effective control set: the tier baseline, plus the tool's
// extras, plus the controls implied by its exposure, minus explicit waivers.
func (t *Tool) Controls() Control {
	c := BaselineControls(t.Tier()) | t.Extra

	// A declared capability is always enforced. Otherwise a T0 tool could name
	// one and have it quietly ignored, which is the worst kind of control:
	// visible in the catalog, absent at runtime.
	if t.Capability != "" {
		c |= CtrlCapability
	}

	// A tool that can send bytes outward gets the egress controls regardless of
	// tier. This is the clause that catches http_request-style reads: harmless
	// by blast radius, and the classic exfiltration path.
	if t.Egress {
		c |= CtrlEgressAllowlist | CtrlTaintBlock | CtrlTrifecta | CtrlAudit
	}
	if t.AmountLimitUSD > 0 {
		c |= CtrlAmountLimit
	}
	if t.MaxPerSession > 0 {
		c |= CtrlRateLimit
	}
	return c &^ t.Waive
}

// MarshalJSON renders the derived fields alongside the declared ones, because
// the derived ones are what an operator reading /v1/agent/tools needs.
func (t Tool) MarshalJSON() ([]byte, error) {
	type alias Tool
	return marshalWith(alias(t), map[string]any{
		"tier":          t.Tier().String(),
		"reversibility": t.Reversibility.String(),
		"radius":        t.Radius.String(),
		"exposure":      t.Exposure.String(),
		"controls":      t.Controls().Names(),
	})
}

// Destination returns the parameter that decides where the effect lands.
func (t *Tool) Destination() (Param, bool) {
	for _, p := range t.Params {
		if p.Destination {
			return p, true
		}
	}
	return Param{}, false
}

// Param looks up a parameter by name.
func (t *Tool) Param(name string) (Param, bool) {
	for _, p := range t.Params {
		if p.Name == name {
			return p, true
		}
	}
	return Param{}, false
}

// Catalog is the set of tools an agent is allowed to know about.
//
// It is a closed set on purpose. An agent runtime that can invent a tool name
// at inference time has no risk model, because there is nothing to look the
// name up in -- and "unknown tool" is exactly the shape of a hallucinated call
// that a permissive gateway would forward to whatever happened to be listening.
type Catalog struct {
	byName map[string]*Tool
	names  []string
}

// NewCatalog validates and indexes a tool list.
func NewCatalog(tools []Tool) (*Catalog, error) {
	c := &Catalog{byName: make(map[string]*Tool, len(tools))}
	var errs []string
	for i := range tools {
		t := tools[i]
		if t.Name == "" {
			errs = append(errs, fmt.Sprintf("tool %d: missing name", i))
			continue
		}
		if _, dup := c.byName[t.Name]; dup {
			errs = append(errs, fmt.Sprintf("tool %q: declared twice", t.Name))
			continue
		}
		errs = append(errs, validateTool(&t)...)
		c.byName[t.Name] = &t
		c.names = append(c.names, t.Name)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("catalog: %s", strings.Join(errs, "; "))
	}
	sort.Strings(c.names)
	return c, nil
}

func validateTool(t *Tool) []string {
	var errs []string
	if t.Tier() >= T1 && t.Capability == "" {
		errs = append(errs, fmt.Sprintf("tool %q: tier %s requires a capability", t.Name, t.Tier()))
	}
	if t.Reversibility == RevCompensable && t.Undo == "" {
		errs = append(errs, fmt.Sprintf(
			"tool %q: declared compensable but names no undo action", t.Name))
	}
	if t.Reversibility == RevIrreversible && t.Undo != "" {
		errs = append(errs, fmt.Sprintf(
			"tool %q: declared irreversible but names an undo action %q", t.Name, t.Undo))
	}
	seen := map[string]bool{}
	destinations, amounts := 0, 0
	for _, p := range t.Params {
		if p.Name == "" {
			errs = append(errs, fmt.Sprintf("tool %q: parameter with no name", t.Name))
			continue
		}
		if seen[p.Name] {
			errs = append(errs, fmt.Sprintf("tool %q: parameter %q declared twice", t.Name, p.Name))
		}
		seen[p.Name] = true
		switch p.Type {
		case "string", "integer", "number", "boolean", "array":
		default:
			errs = append(errs, fmt.Sprintf("tool %q: parameter %q has unknown type %q",
				t.Name, p.Name, p.Type))
		}
		if p.Destination {
			destinations++
		}
		if p.Amount {
			amounts++
			if p.Type != "number" && p.Type != "integer" {
				errs = append(errs, fmt.Sprintf("tool %q: amount parameter %q must be numeric",
					t.Name, p.Name))
			}
		}
	}
	if destinations > 1 {
		errs = append(errs, fmt.Sprintf("tool %q: more than one destination parameter", t.Name))
	}
	if t.AmountLimitUSD > 0 && amounts == 0 {
		errs = append(errs, fmt.Sprintf(
			"tool %q: declares an amount limit but no parameter is marked as the amount", t.Name))
	}
	// An egress control with nothing to apply it to is dead configuration that
	// reads like protection.
	if t.Controls().Has(CtrlEgressAllowlist) && destinations == 0 {
		errs = append(errs, fmt.Sprintf(
			"tool %q: requires an egress allowlist but declares no destination parameter", t.Name))
	}
	return errs
}

// Lookup returns a tool by name.
func (c *Catalog) Lookup(name string) (*Tool, bool) {
	t, ok := c.byName[name]
	return t, ok
}

// Names lists every tool, sorted.
func (c *Catalog) Names() []string { return append([]string(nil), c.names...) }

// Tools returns every tool, sorted by name.
func (c *Catalog) Tools() []*Tool {
	out := make([]*Tool, 0, len(c.names))
	for _, n := range c.names {
		out = append(out, c.byName[n])
	}
	return out
}

// ByTier groups the catalog for report rendering.
func (c *Catalog) ByTier() map[Tier][]*Tool {
	out := map[Tier][]*Tool{}
	for _, t := range c.Tools() {
		out[t.Tier()] = append(out[t.Tier()], t)
	}
	return out
}

// Capabilities lists every capability the catalog can require, which is the
// menu an operator picks from when granting a session its privileges.
func (c *Catalog) Capabilities() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range c.Tools() {
		if t.Capability != "" && !seen[t.Capability] {
			seen[t.Capability] = true
			out = append(out, t.Capability)
		}
	}
	return sortedStrings(out)
}

// CapabilitiesUpTo returns the capabilities of every tool at or below a tier.
// This is how a least-privilege grant is built: "this session may read and
// write, but may not spend money".
func (c *Catalog) CapabilitiesUpTo(max Tier) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range c.Tools() {
		if t.Tier() > max || t.Capability == "" || seen[t.Capability] {
			continue
		}
		seen[t.Capability] = true
		out = append(out, t.Capability)
	}
	return sortedStrings(out)
}
