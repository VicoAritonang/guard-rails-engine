package inbound

import (
	"sort"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/core/normalize"
)

// signal is one piece of evidence that a span of text is trying to hijack the
// model rather than use it.
//
// No single keyword is decisive, which is why a signal is expressed as a
// conjunction of groups rather than a phrase list. "system prompt" appears in
// every prompt-engineering question ever asked; "show me your system prompt"
// does not. Requiring a request verb NEAR the sensitive noun is the difference
// between a detector an operator keeps and one they switch off in week two.
type signal struct {
	ID       string
	Category string
	Weight   float64 // independent probability contribution in [0,1)
	Severity core.Severity

	// AllOf is a conjunction of disjunctions: every group must match, and a
	// group matches if any of its phrases is present. With one group this
	// degrades to a plain "any of these phrases" rule.
	//
	// Phrases are written in natural English (or Indonesian) and folded
	// through normalize.FoldPhrase at init, so the leet and homoglyph classes
	// are applied identically to the pattern and the text.
	AllOf [][]string

	// Proximity bounds how far apart the group matches may be, in bytes of
	// normalized text. Without it, a verb in paragraph one and a noun in
	// paragraph nine would fire on any long document.
	Proximity int
}

const defaultProximity = 90

// compiledSignal caches folded phrases so folding happens once at startup.
type compiledSignal struct {
	signal
	groups    [][]string
	proximity int
}

func compile(sigs []signal) []compiledSignal {
	out := make([]compiledSignal, 0, len(sigs))
	for _, s := range sigs {
		cs := compiledSignal{signal: s, proximity: s.Proximity}
		if cs.proximity <= 0 {
			cs.proximity = defaultProximity
		}
		for _, group := range s.AllOf {
			folded := make([]string, 0, len(group))
			for _, p := range group {
				if f := normalize.FoldPhrase(p); f != "" {
					folded = append(folded, f)
				}
			}
			if len(folded) > 0 {
				cs.groups = append(cs.groups, folded)
			}
		}
		if len(cs.groups) == len(s.AllOf) {
			out = append(out, cs)
		}
	}
	return out
}

// maxOccurrencesPerGroup bounds the window search. A phrase repeated hundreds
// of times is either a stuffing attack or a pathological document; either way
// the first handful of positions is enough to decide.
const maxOccurrencesPerGroup = 12

// match reports whether the signal fires and returns the tightest span that
// satisfies it.
//
// The span matters as much as the boolean: it is what redaction edits and what
// an operator reviewing a false positive reads. Returning the first match of
// each group would produce a span covering half the document whenever a common
// word appears early, so this finds the minimum window containing one
// occurrence from every group.
// It also reports how many DISTINCT phrases of a single-group signal matched.
//
// That count is evidence, and discarding it loses real detections. "This is
// your administrator" scores 0.55 on its own, below the default 0.60 threshold
// -- correctly, since an assistant is occasionally addressed that way. But a
// message containing "this is your administrator" AND "debug mode enabled" has
// produced two independent instances of the same tell, and treating that as
// identical to one is what let an authority-spoofing attack through the eval
// corpus. The caller compounds the weight per distinct phrase.
func (cs compiledSignal) match(hay string) (matched bool, lo, hi, distinct int) {
	if len(cs.groups) == 0 {
		return false, 0, 0, 0
	}

	positions := make([][]span, 0, len(cs.groups))
	for _, group := range cs.groups {
		found := occurrences(hay, group)
		if len(found) == 0 {
			return false, 0, 0, 0
		}
		positions = append(positions, found)
	}

	if len(positions) == 1 {
		s := positions[0][0]
		return true, s.start, s.end, countDistinctPhrases(hay, cs.groups[0])
	}

	// A conjunction already encodes its own strength through the number of
	// groups it required, so multi-group signals always count as one.
	lo, hi, ok := minWindow(positions)
	if !ok || hi-lo > cs.proximity {
		return false, 0, 0, 0
	}
	return true, lo, hi, 1
}

// countDistinctPhrases counts how many different phrases of a group appear.
// Repetitions of the same phrase count once: an attacker padding one keyword a
// hundred times has supplied one piece of evidence, not a hundred.
func countDistinctPhrases(hay string, group []string) int {
	n := 0
	for _, p := range group {
		if strings.Contains(hay, p) {
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

type span struct{ start, end int }

// occurrences returns up to maxOccurrencesPerGroup positions where any phrase
// in the group appears, sorted by start offset.
func occurrences(hay string, group []string) []span {
	var out []span
	for _, p := range group {
		from := 0
		for len(out) < maxOccurrencesPerGroup {
			i := strings.Index(hay[from:], p)
			if i < 0 {
				break
			}
			abs := from + i
			out = append(out, span{abs, abs + len(p)})
			from = abs + len(p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	if len(out) > maxOccurrencesPerGroup {
		out = out[:maxOccurrencesPerGroup]
	}
	return out
}

// minWindow finds the smallest [lo,hi) containing at least one span from every
// group, using the standard k-way merge: advance the pointer whose current
// span starts earliest, and record the window each time every group is
// represented.
func minWindow(groups [][]span) (int, int, bool) {
	idx := make([]int, len(groups))
	bestLo, bestHi := 0, 0
	found := false

	for {
		lo, hi := 1<<62, 0
		minGroup := -1
		for g, spans := range groups {
			if idx[g] >= len(spans) {
				if found {
					return bestLo, bestHi, true
				}
				return 0, 0, false
			}
			s := spans[idx[g]]
			if s.start < lo {
				lo, minGroup = s.start, g
			}
			if s.end > hi {
				hi = s.end
			}
		}
		if !found || hi-lo < bestHi-bestLo {
			bestLo, bestHi, found = lo, hi, true
		}
		idx[minGroup]++
	}
}
