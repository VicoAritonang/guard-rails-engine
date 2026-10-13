package outbound

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// JSONSchema is a deliberately small subset of JSON Schema draft 2020-12.
//
// The full specification is large and most of it -- $ref resolution across
// documents, dynamic anchors, unevaluatedProperties -- has no bearing on
// validating an LLM completion. Pulling in a complete implementation would add
// a dependency and a meaningful slice of the latency budget to check things no
// caller declares. What is here covers the shapes people actually ask a model
// for: typed objects with required fields, enums, arrays, numeric bounds, and
// string patterns.
//
// Anything unsupported is ignored rather than rejected, so an over-specified
// schema still validates the parts this engine understands instead of failing
// the request outright.
type JSONSchema struct {
	Type       any                    `json:"type,omitempty"` // string or []string
	Properties map[string]*JSONSchema `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
	Items      *JSONSchema            `json:"items,omitempty"`
	Enum       []any                  `json:"enum,omitempty"`

	AdditionalProperties *bool `json:"additionalProperties,omitempty"`

	MinLength *int     `json:"minLength,omitempty"`
	MaxLength *int     `json:"maxLength,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	MinItems  *int     `json:"minItems,omitempty"`
	MaxItems  *int     `json:"maxItems,omitempty"`

	AnyOf []*JSONSchema `json:"anyOf,omitempty"`
	OneOf []*JSONSchema `json:"oneOf,omitempty"`
	AllOf []*JSONSchema `json:"allOf,omitempty"`

	compiled *regexp.Regexp
	once     sync.Once
}

// toSchema accepts either a decoded map (the common case, since the schema
// arrives as JSON metadata) or a raw JSON string.
func toSchema(v any) (*JSONSchema, error) {
	var raw []byte
	var err error
	switch t := v.(type) {
	case string:
		raw = []byte(t)
	case []byte:
		raw = t
	default:
		raw, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal schema: %w", err)
		}
	}
	var s JSONSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Type == nil && s.Properties == nil && s.AnyOf == nil && s.OneOf == nil &&
		s.AllOf == nil && s.Enum == nil {
		return nil, fmt.Errorf("schema declares no constraints")
	}
	return &s, nil
}

// Validate returns a list of human-readable violations. An empty result means
// the document conforms.
//
// Returning every violation rather than the first matters here: a model that
// got three fields wrong should be told about three fields, because the caller
// often feeds these messages straight back into a retry prompt.
func (s *JSONSchema) Validate(doc any, path string) []string {
	if s == nil {
		return nil
	}
	var out []string

	if len(s.AllOf) > 0 {
		for i, sub := range s.AllOf {
			if v := sub.Validate(doc, fmt.Sprintf("%s/allOf[%d]", path, i)); len(v) > 0 {
				out = append(out, v...)
			}
		}
	}
	if len(s.AnyOf) > 0 && !anyMatches(s.AnyOf, doc, path) {
		out = append(out, fmt.Sprintf("%s: does not match any of the %d allowed shapes", path, len(s.AnyOf)))
	}
	if len(s.OneOf) > 0 {
		matches := 0
		for _, sub := range s.OneOf {
			if len(sub.Validate(doc, path)) == 0 {
				matches++
			}
		}
		if matches != 1 {
			out = append(out, fmt.Sprintf("%s: matched %d oneOf branches, expected exactly 1", path, matches))
		}
	}

	if s.Type != nil && !s.typeMatches(doc) {
		out = append(out, fmt.Sprintf("%s: expected type %v, got %s", path, s.Type, jsonTypeOf(doc)))
		return out // further checks would be noise once the type is wrong
	}

	if len(s.Enum) > 0 && !containsValue(s.Enum, doc) {
		out = append(out, fmt.Sprintf("%s: value %v is not one of the permitted values", path, doc))
	}

	switch v := doc.(type) {
	case map[string]any:
		out = append(out, s.validateObject(v, path)...)
	case []any:
		out = append(out, s.validateArray(v, path)...)
	case string:
		out = append(out, s.validateString(v, path)...)
	case float64:
		out = append(out, s.validateNumber(v, path)...)
	}
	return out
}

func (s *JSONSchema) validateObject(v map[string]any, path string) []string {
	var out []string
	for _, req := range s.Required {
		if _, ok := v[req]; !ok {
			out = append(out, fmt.Sprintf("%s: missing required property %q", path, req))
		}
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties && s.Properties != nil {
		extra := make([]string, 0, 4)
		for k := range v {
			if _, declared := s.Properties[k]; !declared {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			out = append(out, fmt.Sprintf("%s: unexpected property %q", path, k))
		}
	}
	// Iterate the schema, not the document, so violation order is stable.
	keys := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if child, ok := v[k]; ok {
			out = append(out, s.Properties[k].Validate(child, path+"."+k)...)
		}
	}
	return out
}

func (s *JSONSchema) validateArray(v []any, path string) []string {
	var out []string
	if s.MinItems != nil && len(v) < *s.MinItems {
		out = append(out, fmt.Sprintf("%s: has %d items, minimum is %d", path, len(v), *s.MinItems))
	}
	if s.MaxItems != nil && len(v) > *s.MaxItems {
		out = append(out, fmt.Sprintf("%s: has %d items, maximum is %d", path, len(v), *s.MaxItems))
	}
	if s.Items != nil {
		for i, item := range v {
			out = append(out, s.Items.Validate(item, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}

func (s *JSONSchema) validateString(v, path string) []string {
	var out []string
	if s.MinLength != nil && len([]rune(v)) < *s.MinLength {
		out = append(out, fmt.Sprintf("%s: length %d is below minLength %d", path, len([]rune(v)), *s.MinLength))
	}
	if s.MaxLength != nil && len([]rune(v)) > *s.MaxLength {
		out = append(out, fmt.Sprintf("%s: length %d exceeds maxLength %d", path, len([]rune(v)), *s.MaxLength))
	}
	if s.Pattern != "" {
		s.once.Do(func() {
			// An invalid pattern is the caller's error; compiling once and
			// leaving it nil degrades to "no pattern check" rather than
			// panicking inside a guard on every request.
			s.compiled, _ = regexp.Compile(s.Pattern)
		})
		if s.compiled != nil && !s.compiled.MatchString(v) {
			out = append(out, fmt.Sprintf("%s: does not match pattern %q", path, s.Pattern))
		}
	}
	return out
}

func (s *JSONSchema) validateNumber(v float64, path string) []string {
	var out []string
	if s.Minimum != nil && v < *s.Minimum {
		out = append(out, fmt.Sprintf("%s: %v is below minimum %v", path, v, *s.Minimum))
	}
	if s.Maximum != nil && v > *s.Maximum {
		out = append(out, fmt.Sprintf("%s: %v exceeds maximum %v", path, v, *s.Maximum))
	}
	return out
}

func (s *JSONSchema) typeMatches(doc any) bool {
	actual := jsonTypeOf(doc)
	switch t := s.Type.(type) {
	case string:
		return typeEqual(t, actual, doc)
	case []any:
		for _, item := range t {
			if name, ok := item.(string); ok && typeEqual(name, actual, doc) {
				return true
			}
		}
		return false
	}
	return true
}

func typeEqual(want, actual string, doc any) bool {
	if want == actual {
		return true
	}
	// JSON has one number type; "integer" is a constraint on it.
	if want == "integer" && actual == "number" {
		f, _ := doc.(float64)
		return f == float64(int64(f))
	}
	return false
}

func jsonTypeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, int, int64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func anyMatches(schemas []*JSONSchema, doc any, path string) bool {
	for _, sub := range schemas {
		if len(sub.Validate(doc, path)) == 0 {
			return true
		}
	}
	return false
}

func containsValue(list []any, v any) bool {
	for _, item := range list {
		if valueEqual(item, v) {
			return true
		}
	}
	return false
}

func valueEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	// Compare through the JSON encoding so that numeric and nested values
	// compare structurally rather than by Go identity.
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(string(ab), string(bb))
}
