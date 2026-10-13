package inbound

import "strings"

// textStats is a single-pass summary of a payload, computed once and shared by
// every rule that scans it.
//
// The problem it solves is that the PII and secrets tables together hold two
// dozen regexes, and running all of them over a 60 KB prompt costs about 40 ms
// -- most of the inbound stage's entire 50 ms budget, spent almost entirely
// inside RE2 on text that could not possibly match. Go's regexp runs at roughly
// 20-50 MB/s here; strings.Contains runs at several GB/s. Rejecting a rule with
// a literal test before ever entering the regex engine is the difference
// between an engine that scales to real documents and one that does not.
//
// Every prefilter must be a strict necessary condition of the pattern it
// guards. A prefilter that is merely usually-true silently converts a detector
// into a false-negative generator, which is the worst possible failure for a
// security control -- so each one below is derived from a literal the regex
// cannot match without.
type textStats struct {
	lower       string
	digitCount  int
	maxDigitRun int
	hasAt       bool
	hasColon    bool
	hasDot      bool
	hasDash     bool
	hasPlus     bool
	hasUpper    bool
}

func computeStats(s string) textStats {
	st := textStats{lower: strings.ToLower(s)}
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			st.digitCount++
			run++
			if run > st.maxDigitRun {
				st.maxDigitRun = run
			}
			continue
		case c == '@':
			st.hasAt = true
		case c == ':':
			st.hasColon = true
		case c == '.':
			st.hasDot = true
		case c == '-':
			st.hasDash = true
		case c == '+':
			st.hasPlus = true
		case c >= 'A' && c <= 'Z':
			st.hasUpper = true
		}
		run = 0
	}
	return st
}

// prefilter declares the necessary conditions for one rule.
type prefilter struct {
	// AnyLiteral: at least one of these case-sensitive substrings must appear.
	AnyLiteral []string
	// AnyLiteralFold: same, but matched against the lowercased text.
	AnyLiteralFold []string
	// NeedBytes: every one of these characters must appear.
	NeedBytes string
	// MinDigits / MinDigitRun: total digits, and longest consecutive run.
	MinDigits   int
	MinDigitRun int
}

// pass reports whether the rule could possibly match.
func (p prefilter) pass(st textStats) bool {
	if p.MinDigits > 0 && st.digitCount < p.MinDigits {
		return false
	}
	if p.MinDigitRun > 0 && st.maxDigitRun < p.MinDigitRun {
		return false
	}
	for i := 0; i < len(p.NeedBytes); i++ {
		switch p.NeedBytes[i] {
		case '@':
			if !st.hasAt {
				return false
			}
		case ':':
			if !st.hasColon {
				return false
			}
		case '.':
			if !st.hasDot {
				return false
			}
		case '-':
			if !st.hasDash {
				return false
			}
		case '+':
			if !st.hasPlus {
				return false
			}
		}
	}
	if len(p.AnyLiteral) > 0 && !containsAnyLiteral(st.lower, p.AnyLiteral, false) {
		return false
	}
	if len(p.AnyLiteralFold) > 0 && !containsAnyLiteral(st.lower, p.AnyLiteralFold, true) {
		return false
	}
	return true
}

// containsAnyLiteral checks the lowercased text. Case-sensitive literals are
// still tested against it -- a lowercase-folded search can only over-match, and
// over-matching a prefilter costs one regex run, while under-matching would
// drop a real detection.
func containsAnyLiteral(lower string, needles []string, alreadyFolded bool) bool {
	for _, n := range needles {
		probe := n
		if !alreadyFolded {
			probe = strings.ToLower(n)
		}
		if strings.Contains(lower, probe) {
			return true
		}
	}
	return false
}
