package normalize

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"unicode"
)

// Layer is a decoded view of a region of the input.
//
// Encoding smuggling is the highest-yield prompt-injection technique that
// keyword matching misses entirely: the attacker base64-encodes the payload,
// asks the model to decode it, and the model happily complies. The guardrail
// sees random-looking ASCII and waves it through. Decoding candidate regions
// and re-scanning the plaintext closes that hole, and reporting the span of
// the *encoded* region means redaction still edits something meaningful.
type Layer struct {
	Kind     string // base64 | hex | rot13 | urlencode | tagchars
	Text     string // decoded plaintext
	SrcStart int    // byte offsets of the encoded region in the original
	SrcEnd   int
	Depth    int // 1 for a single decode, 2 for base64-of-base64, ...
}

// DecodeLayers finds encoded regions in s and returns their plaintext.
// maxDepth bounds recursive decoding so that a nested-encoding bomb cannot
// turn a guardrail into a CPU sink.
func DecodeLayers(s string, maxDepth int) []Layer {
	if maxDepth <= 0 {
		maxDepth = 1
	}
	var out []Layer
	seen := map[string]struct{}{}
	decodeInto(s, 1, maxDepth, 0, &out, seen)
	return out
}

func decodeInto(s string, depth, maxDepth, baseOff int, out *[]Layer, seen map[string]struct{}) {
	if depth > maxDepth || len(*out) > 32 {
		return
	}
	for _, l := range scanOnce(s) {
		// A decode that returns its input is not a layer. Without this, ROT13
		// -- which is its own inverse -- decodes at depth 2 back to the exact
		// original text. Every plain-text attack then produced a phantom
		// "rot13-encoded" hit, which both mislabelled the surface in telemetry
		// and double-counted the same signals into the noisy-OR score.
		if l.Text == s {
			continue
		}
		l.Depth = depth
		l.SrcStart += baseOff
		l.SrcEnd += baseOff
		key := l.Kind + "\x00" + l.Text
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		*out = append(*out, l)

		// Self-inverse whole-string transforms cannot usefully nest: applying
		// them again either restores the input (handled above) or produces
		// noise. Recursing into them only burns budget.
		if l.Kind == "rot13" {
			continue
		}
		// A decoded layer can itself contain an encoded payload.
		decodeInto(l.Text, depth+1, maxDepth, l.SrcStart, out, seen)
	}
}

func scanOnce(s string) []Layer {
	var out []Layer
	out = append(out, findBase64(s)...)
	out = append(out, findHex(s)...)
	out = append(out, findURLEncoded(s)...)
	out = append(out, findTagChars(s)...)
	if l, ok := tryROT13(s); ok {
		out = append(out, l)
	}
	return out
}

const minEncodedRun = 16

// findBase64 extracts standard and URL-safe base64 runs that decode to text.
func findBase64(s string) []Layer {
	var out []Layer
	i := 0
	for i < len(s) {
		if !isB64Char(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isB64Char(s[j]) {
			j++
		}
		for j < len(s) && s[j] == '=' {
			j++
		}
		run := s[i:j]
		if len(run) >= minEncodedRun {
			if dec, ok := decodeB64(run); ok && looksLikeText(dec) {
				out = append(out, Layer{Kind: "base64", Text: dec, SrcStart: i, SrcEnd: j})
			}
		}
		i = j
		if i < len(s) {
			i++
		}
	}
	return out
}

func isB64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

func decodeB64(run string) (string, bool) {
	trimmed := strings.TrimRight(run, "=")
	// Try the four encodings an attacker might have used, cheapest first.
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(trimmed); err == nil && len(b) >= 8 {
			return string(b), true
		}
	}
	return "", false
}

// findHex extracts long hex runs that decode to text.
func findHex(s string) []Layer {
	var out []Layer
	i := 0
	for i < len(s) {
		if !isHexChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isHexChar(s[j]) {
			j++
		}
		run := s[i:j]
		if len(run) >= 2*minEncodedRun && len(run)%2 == 0 {
			if b, err := hex.DecodeString(run); err == nil && looksLikeText(string(b)) {
				out = append(out, Layer{Kind: "hex", Text: string(b), SrcStart: i, SrcEnd: j})
			}
		}
		i = j
		if i < len(s) {
			i++
		}
	}
	return out
}

func isHexChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// findURLEncoded catches percent-encoded payloads.
func findURLEncoded(s string) []Layer {
	if strings.Count(s, "%") < 4 {
		return nil
	}
	dec, err := url.QueryUnescape(s)
	if err != nil || dec == s || !looksLikeText(dec) {
		return nil
	}
	return []Layer{{Kind: "urlencode", Text: dec, SrcStart: 0, SrcEnd: len(s)}}
}

// findTagChars decodes Unicode tag characters (U+E0000 block), which render as
// nothing at all yet carry a full ASCII message. This is the "invisible
// prompt" technique: the visible text is benign, the tag-char payload is not.
func findTagChars(s string) []Layer {
	var b strings.Builder
	start, end := -1, -1
	for off, r := range s {
		if r >= 0xE0020 && r <= 0xE007E {
			if start < 0 {
				start = off
			}
			end = off + 4
			b.WriteRune(r - 0xE0000)
		}
	}
	if b.Len() < 8 {
		return nil
	}
	return []Layer{{Kind: "tagchars", Text: b.String(), SrcStart: start, SrcEnd: end}}
}

// tryROT13 is applied whole-string: ROT13 has no detectable signature, so the
// only sound approach is to decode everything and let the downstream matcher
// decide whether the result looks like an attack.
func tryROT13(s string) (Layer, bool) {
	if len(s) < minEncodedRun || len(s) > 8192 {
		return Layer{}, false
	}
	var b strings.Builder
	b.Grow(len(s))
	letters := 0
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune('a' + (r-'a'+13)%26)
			letters++
		case r >= 'A' && r <= 'Z':
			b.WriteRune('A' + (r-'A'+13)%26)
			letters++
		default:
			b.WriteRune(r)
		}
	}
	if letters < minEncodedRun {
		return Layer{}, false
	}
	return Layer{Kind: "rot13", Text: b.String(), SrcStart: 0, SrcEnd: len(s)}, true
}

// looksLikeText rejects decoded binary. Without this, every long random ID in
// a request would produce a "decoded layer" of garbage and the injection
// scorer would burn its budget on noise.
func looksLikeText(s string) bool {
	if len(s) < 8 {
		return false
	}
	printable, letters := 0, 0
	for _, r := range s {
		if r == unicode.ReplacementChar {
			return false
		}
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			printable++
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	total := len([]rune(s))
	if total == 0 {
		return false
	}
	return float64(printable)/float64(total) > 0.90 && float64(letters)/float64(total) > 0.45
}
