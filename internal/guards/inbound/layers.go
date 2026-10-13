package inbound

import "github.com/vicoaritonang/guardrails-engine/internal/core/normalize"

// valueSafeLayer reports whether a decoded layer may be scanned by a detector
// that extracts exact VALUES (the PII and secrets guards) rather than meaning.
//
// ROT13 is excluded, and the reason is worth stating because it cost a
// regression to find. The decoder applies ROT13 to the entire field
// unconditionally -- it has no signature to look for -- so every request
// produces a full-length "decoded" view. That view is still letter-shaped, so
// a structural regex hits it by chance: ROT13 of "budi.santoso@contoh.co.id"
// is "ohqv.fnagbfb@pbagbu.pb.vq", which matches the email pattern perfectly.
// The detector then reports a finding whose source span is the whole field,
// and redaction replaces the entire message with one placeholder.
//
// The injection guard is unaffected by the same layer because it matches
// multi-word English phrases, and ROT13 of ordinary text is not English. That
// asymmetry -- meaning-matchers tolerate speculative decoding, value-matchers
// do not -- is the rule this function encodes.
func valueSafeLayer(l normalize.Layer) bool {
	switch l.Kind {
	case "base64", "hex", "tagchars", "urlencode":
		// These have a discrete encoded region that was deliberately produced.
		// A chance match inside one is vanishingly unlikely, and the span they
		// report is a real substring worth redacting.
		return true
	default:
		return false
	}
}
