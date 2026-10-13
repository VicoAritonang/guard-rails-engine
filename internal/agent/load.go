package agent

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseTier resolves a tier name such as "T3" or "t3-external".
func ParseTier(s string) (Tier, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return T4, nil
	}
	for _, t := range Tiers() {
		if v == strings.ToLower(t.String()) || v == fmt.Sprintf("t%d", int(t)) {
			return t, nil
		}
	}
	return 0, fmt.Errorf("unknown tier %q (want T0..T4)", s)
}

func parseReversibility(s string) (Reversibility, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "read", "readonly", "read_only":
		return RevNone, nil
	case "compensable", "reversible", "undoable":
		return RevCompensable, nil
	case "irreversible", "permanent":
		return RevIrreversible, nil
	}
	return 0, fmt.Errorf("unknown reversibility %q (want none|compensable|irreversible)", s)
}

func parseRadius(s string) (Radius, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "self":
		return RadiusSelf, nil
	case "workspace", "user":
		return RadiusWorkspace, nil
	case "org", "organisation", "organization", "tenant":
		return RadiusOrg, nil
	case "external", "third_party":
		return RadiusExternal, nil
	case "critical", "financial", "production":
		return RadiusCritical, nil
	}
	return 0, fmt.Errorf("unknown radius %q (want self|workspace|org|external|critical)", s)
}

func parseExposure(list []string) (Exposure, error) {
	var out Exposure
	for _, s := range list {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "", "none":
		case "private", "sensitive":
			out |= ExposurePrivate
		case "untrusted", "external_content":
			out |= ExposureUntrusted
		default:
			return 0, fmt.Errorf("unknown exposure %q (want private|untrusted)", s)
		}
	}
	return out, nil
}

// catalogFile is the on-disk catalog format.
//
// It exists because a tool catalog is deployment-specific: every organisation
// has its own tools, and a risk model that only grades the twenty-nine tools
// somebody else thought of is a demo rather than a control. The grading axes
// are the reusable part; the tool list is not.
type catalogFile struct {
	Version string     `yaml:"version"`
	Extends string     `yaml:"extends"` // "builtin" to start from the built-in catalog
	Tools   []toolFile `yaml:"tools"`
}

type toolFile struct {
	Name          string      `yaml:"name"`
	Description   string      `yaml:"description"`
	Domain        string      `yaml:"domain"`
	Reversibility string      `yaml:"reversibility"`
	Radius        string      `yaml:"radius"`
	Exposure      []string    `yaml:"exposure"`
	Egress        bool        `yaml:"egress"`
	Capability    string      `yaml:"capability"`
	MaxPerSession int         `yaml:"max_per_session"`
	AmountLimit   float64     `yaml:"amount_limit_usd"`
	Undo          string      `yaml:"undo"`
	Rationale     string      `yaml:"rationale"`
	Extra         []string    `yaml:"extra_controls"`
	Waive         []string    `yaml:"waive_controls"`
	Params        []paramFile `yaml:"params"`
}

type paramFile struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	Required    bool     `yaml:"required"`
	MaxLen      int      `yaml:"max_len"`
	Enum        []string `yaml:"enum"`
	Description string   `yaml:"description"`
	Destination bool     `yaml:"destination"`
	Payload     bool     `yaml:"payload"`
	Amount      bool     `yaml:"amount"`
}

// LoadCatalog reads a YAML catalog.
//
// With `extends: builtin`, the file's tools are layered over the built-in
// catalog, replacing entries with the same name. That is the common case: an
// operator adds four tools of their own and re-grades one of the defaults,
// rather than restating twenty-nine gradings they agree with.
func LoadCatalog(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var doc catalogFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// A typo in a catalog silently drops a control. Reject unknown fields for
	// the same reason the policy loader does.
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse catalog %s: %w", path, err)
	}

	var tools []Tool
	switch strings.ToLower(strings.TrimSpace(doc.Extends)) {
	case "", "none":
	case "builtin":
		tools = append(tools, builtinTools...)
	default:
		return nil, fmt.Errorf("catalog %s: extends must be empty or \"builtin\"", path)
	}

	index := map[string]int{}
	for i, t := range tools {
		index[t.Name] = i
	}
	for i, tf := range doc.Tools {
		t, err := tf.toTool()
		if err != nil {
			return nil, fmt.Errorf("catalog %s: tool %d: %w", path, i, err)
		}
		if at, replacing := index[t.Name]; replacing {
			tools[at] = t
			continue
		}
		index[t.Name] = len(tools)
		tools = append(tools, t)
	}

	cat, err := NewCatalog(tools)
	if err != nil {
		return nil, fmt.Errorf("catalog %s: %w", path, err)
	}
	return cat, nil
}

func (tf toolFile) toTool() (Tool, error) {
	rev, err := parseReversibility(tf.Reversibility)
	if err != nil {
		return Tool{}, err
	}
	rad, err := parseRadius(tf.Radius)
	if err != nil {
		return Tool{}, err
	}
	exp, err := parseExposure(tf.Exposure)
	if err != nil {
		return Tool{}, err
	}
	extra, err := parseControls(tf.Extra)
	if err != nil {
		return Tool{}, err
	}
	waive, err := parseControls(tf.Waive)
	if err != nil {
		return Tool{}, err
	}

	t := Tool{
		Name:           tf.Name,
		Description:    tf.Description,
		Domain:         tf.Domain,
		Reversibility:  rev,
		Radius:         rad,
		Exposure:       exp,
		Egress:         tf.Egress,
		Capability:     tf.Capability,
		Extra:          extra,
		Waive:          waive,
		MaxPerSession:  tf.MaxPerSession,
		AmountLimitUSD: tf.AmountLimit,
		Undo:           tf.Undo,
		Rationale:      tf.Rationale,
	}
	for _, pf := range tf.Params {
		t.Params = append(t.Params, Param{
			Name:        pf.Name,
			Type:        pf.Type,
			Required:    pf.Required,
			MaxLen:      pf.MaxLen,
			Enum:        pf.Enum,
			Desc:        pf.Description,
			Destination: pf.Destination,
			Payload:     pf.Payload,
			Amount:      pf.Amount,
		})
	}
	return t, nil
}

func parseControls(names []string) (Control, error) {
	var out Control
	for _, n := range names {
		c, err := ParseControl(strings.ToLower(strings.TrimSpace(n)))
		if err != nil {
			return 0, err
		}
		out |= c
	}
	return out, nil
}

// ParseReversibility parses none | compensable | irreversible.
func ParseReversibility(s string) (Reversibility, error) { return parseReversibility(s) }

// ParseRadius parses self | workspace | org | external | critical.
func ParseRadius(s string) (Radius, error) { return parseRadius(s) }
