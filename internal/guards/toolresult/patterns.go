package toolresult

import (
	"regexp"
	"strings"

	"github.com/VicoAritonang/guard-rails-engine/internal/core/normalize"
)

// This file holds every pattern the tool-result rails match with, and it exists
// as a separate file to make one rule impossible to forget: a pattern that runs
// against folded text must itself be folded, and a pattern that runs against
// raw text must not be.
//
// The rule sounds pedantic until it costs you a detection. The injection preset
// folds the character class {i, l, 1, |} to 'i', so "call send_email" becomes
// "caii sendemaii". A pattern compiled from the literal string "call" then
// matches nothing at all -- and it looks completely correct in review, passes
// every unit test written against unfolded input, and fails silently on real
// traffic. The red-team suite is what found it here, twice: first on the tool
// names, then again on the verbs in front of them.
//
// So: folded patterns are built from plain phrases at init, through the same
// FoldPhrase the text goes through. Raw patterns are written as ordinary
// regexes and marked as such.

// ---------------------------------------------------------------- folded

// governedTools are the tool names a result has no business naming. A page that
// tells the agent which tool to call next is not data.
var governedTools = []string{
	"send_email", "http_request", "transfer_funds", "execute_shell",
	"delete_record", "delete_file", "grant_access", "rotate_credentials",
	"deploy_service", "post_message", "issue_refund", "update_record",
	"create_pull_request", "calendar_create",
}

// directiveVerbs introduce a tool call.
var directiveVerbs = []string{"call", "invoke", "use", "run", "execute", "trigger"}

// authorityPhrases claim to speak with the operator's voice.
var authorityPhrases = []string{
	"system note", "system message", "system instruction", "system prompt",
	"note to the assistant", "note to assistant", "note to the ai",
	"note to the agent", "note to the model",
	"admin override", "administrator override", "admin instruction",
	"important instruction", "important system", "important note",
	"updated policy", "update policy", "updated instructions", "new instructions",
}

// addressingPhrases speak to the model rather than to the reader. A document
// written for a person has no reason to contain any of them.
var addressingPhrases = []string{
	"before answering", "before you answer", "before you respond", "before you reply",
	"do not tell the user", "do not mention to the user", "do not inform the user",
	"do not reveal to the user", "do not reveal this to the user",
	"without telling the user", "without informing the user",
	"you must now", "you must instead", "you must first",
	"you should now", "you should instead", "you should first",
	"as the assistant", "ignore the user",
}

// foldedAlternation compiles a phrase list into a pattern that matches folded
// text, deduplicating phrases that fold together.
func foldedAlternation(phrases []string) *regexp.Regexp {
	seen := map[string]bool{}
	alts := make([]string, 0, len(phrases))
	for _, p := range phrases {
		f := normalize.FoldPhrase(p)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		alts = append(alts, regexp.QuoteMeta(f))
	}
	// Longest first, so "system instruction" wins over "system" if both were
	// ever listed; alternation in RE2 is leftmost, not longest.
	sortByLengthDesc(alts)
	return regexp.MustCompile(`\b(?:` + strings.Join(alts, "|") + `)\b`)
}

func sortByLengthDesc(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && len(s[j]) > len(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var (
	authorityFraming = foldedAlternation(authorityPhrases)
	agentAddressing  = foldedAlternation(addressingPhrases)
	reToolDirective  = buildToolDirective()
)

// buildToolDirective matches "call send_email"-shaped text, with both halves
// folded: the verb and the tool name.
func buildToolDirective() *regexp.Regexp {
	fold := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			out = append(out, regexp.QuoteMeta(normalize.FoldPhrase(v)))
		}
		sortByLengthDesc(out)
		return out
	}
	verbs := strings.Join(fold(directiveVerbs), "|")
	tools := strings.Join(fold(governedTools), "|")
	the := normalize.FoldPhrase("the")
	tool := normalize.FoldPhrase("tool")

	// The optional quote class covers a name the document wrapped in quotes or
	// backticks, which is how a poisoned page usually writes one.
	return regexp.MustCompile(
		`\b(?:` + verbs + `)\s+(?:` + the + `\s+)?(?:` + tool + `\s+)?` +
			"[\"'`]?(" + tools + `)\b`)
}

// ------------------------------------------------------------------- raw

// reExfilLink matches a markdown image or link whose URL carries a long query
// string. It runs on raw text: the injection preset strips '.' and '/' between
// word characters, and a folded URL is not a URL.
//
// The image form is the dangerous one. The client fetches it while rendering
// the answer, so the data leaves without anyone clicking anything.
var reExfilLink = regexp.MustCompile(`!?\[[^\]]{0,200}\]\((https?://[^)\s]{40,})\)`)

// exfilIntent is an instruction to move content to a named destination. Raw,
// for the same reason: the preset de-leets '@' to 'a', so on folded text
// "billing-ops@vendor.example" is "billingopsavendorexample" -- no address left
// to match.
//
// The cost of running raw is that "s3nd a copy to ..." evades this one signal.
// That is an accepted trade rather than an oversight: it is one of three
// signals, two are required to fire, and both of the others are folded.
var exfilIntent = regexp.MustCompile(
	`(?i)\b(?:send|forward|email|post|upload|transmit|copy)\b` +
		`[^.\n]{0,80}?\b(?:to|at)\b\s+(?:https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)`)
