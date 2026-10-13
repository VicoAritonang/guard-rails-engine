// Package tokenize provides a fast, dependency-free token-count estimate.
//
// It is explicitly an estimate. The exact count for a Claude request comes from
// the provider's /v1/messages/count_tokens endpoint, which the Anthropic
// adapter exposes as CountTokens. But a guardrail cannot make a network call to
// decide whether to admit a request -- that would add more latency than the
// entire rest of the pipeline and introduce an availability dependency on the
// very provider it is protecting.
//
// So quota enforcement uses this estimator with a deliberate safety margin, and
// exact accounting happens after the fact from the provider's usage response.
// The estimator is tuned to over-count slightly: admitting a request that turns
// out to be over budget is worse than rejecting one that was marginally under.
package tokenize

import (
	"strings"
	"unicode"
)

// Bytes-per-token ratios by script. English prose runs about 3.6-4.0 bytes per
// token on modern BPE vocabularies; CJK is far denser per byte because each
// character is 3 UTF-8 bytes but often 1-2 tokens; code sits between the two
// because punctuation and indentation fragment badly.
const (
	latinBytesPerToken = 3.6
	cjkBytesPerToken   = 1.6
	otherBytesPerToken = 2.4
	// safetyMargin biases the estimate upward. 8% covers the observed spread
	// between this estimator and the provider count on mixed corpora.
	safetyMargin = 1.08
)

// Estimate returns an approximate token count for s.
func Estimate(s string) int {
	if s == "" {
		return 0
	}
	var latin, cjk, other, punct int
	for _, r := range s {
		switch {
		case r < 0x80:
			latin++
			if unicode.IsPunct(r) || unicode.IsSymbol(r) {
				punct++
			}
		case isCJK(r):
			cjk += 3 // UTF-8 width
		default:
			other += utf8Len(r)
		}
	}

	est := float64(latin)/latinBytesPerToken +
		float64(cjk)/cjkBytesPerToken +
		float64(other)/otherBytesPerToken

	// Dense punctuation means code or structured data, which tokenizes worse
	// than prose. Ignoring this under-counts JSON payloads by 30% or more,
	// and JSON payloads are exactly what an agent pipeline sends.
	if latin > 0 {
		if ratio := float64(punct) / float64(latin); ratio > 0.10 {
			est *= 1 + (ratio-0.10)*1.5
		}
	}

	n := int(est*safetyMargin) + 1
	return n
}

// EstimateMessages approximates a full chat request, including the per-message
// framing overhead the provider adds around each turn.
func EstimateMessages(system string, contents []string) int {
	const perMessageOverhead = 4 // role markers and separators
	total := Estimate(system)
	if system != "" {
		total += perMessageOverhead
	}
	for _, c := range contents {
		total += Estimate(c) + perMessageOverhead
	}
	return total
}

func isCJK(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF, // CJK unified ideographs
		r >= 0x3040 && r <= 0x30FF, // hiragana + katakana
		r >= 0xAC00 && r <= 0xD7AF, // hangul syllables
		r >= 0x3400 && r <= 0x4DBF: // CJK extension A
		return true
	}
	return false
}

func utf8Len(r rune) int {
	switch {
	case r < 0x80:
		return 1
	case r < 0x800:
		return 2
	case r < 0x10000:
		return 3
	default:
		return 4
	}
}

// Words is a cheap word count used by the grounding and format guards.
func Words(s string) int {
	return len(strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}))
}
