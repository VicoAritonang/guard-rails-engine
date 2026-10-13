package core

import (
	"hash/fnv"
	"maps"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// SessionState is everything the guards need to know about an agent trace that
// cannot be seen in a single step.
//
// It lives on the transaction rather than inside the engine on purpose. The
// interesting agent failures are trajectory-shaped -- read a customer record,
// read a web page, then email someone -- and each of those steps is a separate
// request that may land on a different instance. Keeping the state in the
// payload means the caller owns it, the guards stay pure, and the gateway can
// still be scaled by adding replicas rather than by adding sticky routing.
//
// The cost of that choice is that a caller can lie about its own history. That
// is acceptable here because the caller is the agent runtime, which sits inside
// the trust boundary; it stops being acceptable the moment the state becomes
// browser-supplied, and the fix at that point is to sign it. See
// docs/adr/0006-tool-safety.md.
type SessionState struct {
	TraceID string `json:"trace_id,omitempty"`
	Step    int    `json:"step,omitempty"`

	// Granted lists the capabilities this session holds. Least privilege is
	// enforced against this list, not against what the tool catalog allows.
	Granted []string `json:"granted,omitempty"`

	// Effects accumulates what the agent has already done, which is what turns
	// three individually-reasonable calls into one dangerous trajectory.
	Effects EffectLedger `json:"effects,omitzero"`

	// Taint fingerprints untrusted content the agent has ingested, so a later
	// argument can be tested for having come from it.
	Taint TaintLedger `json:"taint,omitzero"`

	// ToolCalls counts executions per tool name, for per-tool rate limits.
	ToolCalls map[string]int `json:"tool_calls,omitempty"`

	// Executed maps an idempotency key to the call signature that claimed it.
	// A repeat with the same key is a retry to suppress; a repeat with a
	// different signature is a key collision worth refusing.
	Executed map[string]string `json:"executed,omitempty"`

	// ApprovalsUsed records consumed approval grants, so a single human "yes"
	// cannot authorise a second irreversible action.
	ApprovalsUsed []string `json:"approvals_used,omitempty"`

	// AuditChain is the hash of the most recent execution receipt. Each new
	// receipt commits to it, so a receipt removed from the middle of a trace
	// breaks the chain instead of disappearing quietly.
	AuditChain string `json:"audit_chain,omitempty"`

	// Simulated lists call signatures that have completed a dry run. A tool
	// requiring simulation checks this, which is what makes "simulate, then
	// commit the exact call you simulated" enforceable rather than advisory.
	Simulated []string `json:"simulated,omitempty"`
}

// WasSimulated reports whether this exact call has been dry-run.
func (s *SessionState) WasSimulated(signature string) bool {
	return s != nil && contains(s.Simulated, signature)
}

// RecordSimulation notes that a call signature completed a dry run.
func (s *SessionState) RecordSimulation(signature string) {
	if !contains(s.Simulated, signature) {
		s.Simulated = append(s.Simulated, signature)
	}
}

// EffectLedger is the coarse record of what a trace has already touched.
//
// The three booleans are deliberately the three legs of the exfiltration
// trifecta: access to private data, exposure to untrusted content, and a way to
// send bytes outward. Any one of them is ordinary. All three inside one context
// window is the shape of every published agent data-theft chain, and no
// single-call check can see it.
type EffectLedger struct {
	ReadPrivate       bool `json:"read_private,omitempty"`
	IngestedUntrusted bool `json:"ingested_untrusted,omitempty"`
	CanExfiltrate     bool `json:"can_exfiltrate,omitempty"`

	// Witness records which tool set each leg, so a finding can name the three
	// calls instead of asserting a verdict the operator has to take on faith.
	Witness map[string]string `json:"witness,omitempty"`
}

// Trifecta reports whether all three legs are present.
func (e EffectLedger) Trifecta() bool {
	return e.ReadPrivate && e.IngestedUntrusted && e.CanExfiltrate
}

// Legs returns the legs currently set, in a stable order.
func (e EffectLedger) Legs() []string {
	var out []string
	if e.ReadPrivate {
		out = append(out, "read_private")
	}
	if e.IngestedUntrusted {
		out = append(out, "ingested_untrusted")
	}
	if e.CanExfiltrate {
		out = append(out, "can_exfiltrate")
	}
	return out
}

func (e *EffectLedger) set(leg, witness string) {
	if e.Witness == nil {
		e.Witness = map[string]string{}
	}
	if _, seen := e.Witness[leg]; !seen {
		e.Witness[leg] = witness
	}
}

// MarkReadPrivate records that a tool returned data from a system of record.
func (e *EffectLedger) MarkReadPrivate(tool string) {
	e.ReadPrivate = true
	e.set("read_private", tool)
}

// MarkIngestedUntrusted records that content of unknown authorship entered the
// context window.
func (e *EffectLedger) MarkIngestedUntrusted(tool string) {
	e.IngestedUntrusted = true
	e.set("ingested_untrusted", tool)
}

// MarkCanExfiltrate records that the agent has invoked, or is about to invoke,
// a tool that moves bytes outside the trust boundary.
func (e *EffectLedger) MarkCanExfiltrate(tool string) {
	e.CanExfiltrate = true
	e.set("can_exfiltrate", tool)
}

// Bounds on the taint ledger, so a long trace cannot grow the session payload
// without limit. Both are generous next to a real trace and small next to a
// request body.
const (
	maxShingles = 4096
	maxTokens   = 512
	shingleN    = 5
)

// TaintLedger fingerprints untrusted text so a later value can be tested for
// having been copied out of it.
//
// It stores hashes, never text. That is a privacy property worth having --
// this structure travels in request bodies and lands in logs -- and it is also
// what keeps the state small enough to pass around every step.
type TaintLedger struct {
	// Shingles are hashes of overlapping 5-word windows, which is what catches
	// a sentence lifted out of a poisoned document.
	Shingles []uint64 `json:"shingles,omitempty"`
	// Tokens are hashes of individually distinctive strings: URLs, email
	// addresses, long opaque identifiers. A word window never matches a bare
	// address, and "mail the report to the address on that page" is the whole
	// attack, so these are tracked separately.
	Tokens []uint64 `json:"tokens,omitempty"`
	// Sources names the tools that contributed, for explainability.
	Sources []string `json:"sources,omitempty"`
}

// Add folds untrusted text into the ledger.
func (t *TaintLedger) Add(source, text string) {
	if text == "" {
		return
	}
	words := taintWords(text)
	seen := make(map[uint64]struct{}, len(t.Shingles))
	for _, h := range t.Shingles {
		seen[h] = struct{}{}
	}
	for i := 0; i+shingleN <= len(words) && len(t.Shingles) < maxShingles; i++ {
		h := hashWords(words[i : i+shingleN])
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		t.Shingles = append(t.Shingles, h)
	}

	tokSeen := make(map[uint64]struct{}, len(t.Tokens))
	for _, h := range t.Tokens {
		tokSeen[h] = struct{}{}
	}
	for _, tok := range distinctiveTokens(text) {
		if len(t.Tokens) >= maxTokens {
			break
		}
		h := hashWords([]string{tok})
		if _, dup := tokSeen[h]; dup {
			continue
		}
		tokSeen[h] = struct{}{}
		t.Tokens = append(t.Tokens, h)
	}

	if source != "" && !contains(t.Sources, source) {
		t.Sources = append(t.Sources, source)
		sort.Strings(t.Sources)
	}
}

// Empty reports whether anything untrusted has been recorded.
func (t *TaintLedger) Empty() bool { return len(t.Shingles) == 0 && len(t.Tokens) == 0 }

// TaintMatch describes why a value was judged to have come from untrusted
// content. An empty Kind means no match.
type TaintMatch struct {
	Kind    string  // "token" | "phrase"
	Ratio   float64 // fraction of the value's windows that were tainted
	Matched int
	Total   int
}

// Hit reports whether the value is considered derived from untrusted content.
func (m TaintMatch) Hit() bool { return m.Kind != "" }

// Match tests a candidate value against the ledger.
//
// Two independent tests, because they fail on different inputs. An exact-token
// hit is strong evidence by itself: a URL or an address that appeared in a
// poisoned document and now appears in an outgoing tool call did not get there
// by coincidence. Phrase overlap needs a majority of windows to match, which is
// what stops a value that merely shares common English with a document from
// being flagged.
func (t *TaintLedger) Match(value string) TaintMatch {
	if value == "" || t.Empty() {
		return TaintMatch{}
	}
	if len(t.Tokens) > 0 {
		set := make(map[uint64]struct{}, len(t.Tokens))
		for _, h := range t.Tokens {
			set[h] = struct{}{}
		}
		for _, tok := range distinctiveTokens(value) {
			if _, hit := set[hashWords([]string{tok})]; hit {
				return TaintMatch{Kind: "token", Ratio: 1, Matched: 1, Total: 1}
			}
		}
	}

	words := taintWords(value)
	if len(words) < shingleN || len(t.Shingles) == 0 {
		return TaintMatch{}
	}
	set := make(map[uint64]struct{}, len(t.Shingles))
	for _, h := range t.Shingles {
		set[h] = struct{}{}
	}
	total, matched := 0, 0
	for i := 0; i+shingleN <= len(words); i++ {
		total++
		if _, hit := set[hashWords(words[i:i+shingleN])]; hit {
			matched++
		}
	}
	if total == 0 {
		return TaintMatch{}
	}
	ratio := float64(matched) / float64(total)
	if matched >= 2 && ratio >= 0.6 {
		return TaintMatch{Kind: "phrase", Ratio: ratio, Matched: matched, Total: total}
	}
	return TaintMatch{Ratio: ratio, Matched: matched, Total: total}
}

// taintWords lowercases and splits on non-alphanumerics. Case and punctuation
// are exactly what an attacker would vary for free, so folding them costs
// nothing and removes a trivial evasion.
func taintWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// distinctiveTokens pulls out the substrings that identify a destination or a
// record: URLs, email addresses, and long opaque identifiers. Ordinary words
// are excluded because matching them would flag any sentence in the language.
func distinctiveTokens(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, unicode.IsSpace) {
		f = strings.Trim(f, ".,;:!?\"'()[]{}<>")
		low := strings.ToLower(f)
		switch {
		case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
			out = append(out, low)
		case strings.Count(low, "@") == 1 && strings.Contains(low, ".") && len(low) > 5:
			out = append(out, low)
		case len(low) >= 16 && isOpaque(low):
			out = append(out, low)
		}
	}
	return out
}

// isOpaque reports whether a token looks like an identifier rather than a word:
// alphanumeric, and carrying at least one digit.
func isOpaque(s string) bool {
	digit := false
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsLetter(r), r == '-', r == '_':
		default:
			return false
		}
	}
	return digit
}

func hashWords(words []string) uint64 {
	h := fnv.New64a()
	for i, w := range words {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(w))
	}
	return h.Sum64()
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }

// Has reports whether the session was granted a capability.
func (s *SessionState) Has(capability string) bool {
	if s == nil {
		return false
	}
	for _, c := range s.Granted {
		if c == capability || c == "*" {
			return true
		}
	}
	return false
}

// Count returns how many times a tool has already executed in this session.
func (s *SessionState) Count(tool string) int {
	if s == nil {
		return 0
	}
	return s.ToolCalls[tool]
}

// RecordCall increments the per-tool counter.
func (s *SessionState) RecordCall(tool string) {
	if s.ToolCalls == nil {
		s.ToolCalls = map[string]int{}
	}
	s.ToolCalls[tool]++
}

// ClaimIdempotencyKey reserves a key for a call signature.
//
// replay is true when the same key was already used for the same call, which is
// a retry to answer from the first result rather than act on again. ok is false
// when the key was used for a *different* call, which means the caller is
// recycling keys: the engine refuses rather than guessing which action it was
// meant to suppress.
func (s *SessionState) ClaimIdempotencyKey(key, signature string) (replay, ok bool) {
	if key == "" {
		return false, true
	}
	if s.Executed == nil {
		s.Executed = map[string]string{}
	}
	prior, seen := s.Executed[key]
	switch {
	case !seen:
		s.Executed[key] = signature
		return false, true
	case prior == signature:
		return true, true
	default:
		return false, false
	}
}

// ApprovalSpent reports whether an approval grant has already been consumed.
func (s *SessionState) ApprovalSpent(id string) bool {
	return s != nil && contains(s.ApprovalsUsed, id)
}

// ConsumeApproval marks an approval grant as spent, returning false if it had
// already been used.
func (s *SessionState) ConsumeApproval(id string) bool {
	if s.ApprovalSpent(id) {
		return false
	}
	s.ApprovalsUsed = append(s.ApprovalsUsed, id)
	return true
}

// Clone returns a deep copy, so a dry run can advance a session without
// committing the changes.
func (s *SessionState) Clone() *SessionState {
	if s == nil {
		return nil
	}
	out := *s
	out.Granted = append([]string(nil), s.Granted...)
	out.ApprovalsUsed = append([]string(nil), s.ApprovalsUsed...)
	out.Simulated = append([]string(nil), s.Simulated...)
	out.Taint.Shingles = append([]uint64(nil), s.Taint.Shingles...)
	out.Taint.Tokens = append([]uint64(nil), s.Taint.Tokens...)
	out.Taint.Sources = append([]string(nil), s.Taint.Sources...)
	if s.Effects.Witness != nil {
		out.Effects.Witness = maps.Clone(s.Effects.Witness)
	}
	if s.ToolCalls != nil {
		out.ToolCalls = maps.Clone(s.ToolCalls)
	}
	if s.Executed != nil {
		out.Executed = maps.Clone(s.Executed)
	}
	return &out
}
