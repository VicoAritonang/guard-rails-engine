package agent

import "encoding/json"

// marshalWith renders v and folds in extra keys.
//
// The derived risk fields -- tier, controls, exposure -- are computed, not
// stored, and an operator reading the catalog over HTTP needs exactly those.
// Duplicating them as struct fields would create two sources of truth for the
// same grading, which is the bug this whole package exists to avoid.
func marshalWith(v any, extra map[string]any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	for k, val := range extra {
		m[k] = val
	}
	return json.Marshal(m)
}
