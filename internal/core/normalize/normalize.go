// Package normalize turns adversarially-formatted text into a canonical form
// that pattern matchers can actually match, while preserving the ability to
// report offsets back in the original string.
//
// This exists because naive guardrails are trivially bypassed. "ignore all
// previous instructions" is caught by any regex; the same sentence written
// with a Cyrillic "о", a zero-width space after every third character, or as
// "1gn0re a11 prev10us 1nstruct10ns" is not. Every one of those variants
// reaches the model with identical semantics, so a detector that only sees raw
// bytes is security theatre.
//
// The offset map is the non-obvious part. Once you fold, strip and collapse,
// a match at normalized byte 40 has no relationship to byte 40 of the input --
// but redaction has to edit the *original* string, and an operator reviewing a
// false positive has to see the *original* excerpt. So every normalized byte
// carries a back-pointer to the source span it came from.
package normalize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Options selects which transformations to apply. Different detectors need
// different aggressiveness: prompt-injection matching wants everything folded,
// while PII matching must not lowercase or de-leet, since that would corrupt
// the very values it is trying to extract.
type Options struct {
	StripZeroWidth  bool // remove ZWSP/ZWNJ/ZWJ/BOM/soft hyphen and friends
	FoldConfusables bool // Cyrillic/Greek/fullwidth/math lookalikes -> ASCII
	StripDiacritics bool // "ígnóre" -> "ignore"
	Lowercase       bool
	CollapseSpace   bool // runs of whitespace -> single space
	DeLeet          bool // 0->o, 1->l, 3->e, @->a, $->s
	StripSeparators bool // drop . - _ * between letters ("i.g.n.o.r.e" -> "ignore")
}

// ForInjection folds aggressively: recall matters more than fidelity because
// the output is only ever used for matching, never for display or storage.
var ForInjection = Options{
	StripZeroWidth:  true,
	FoldConfusables: true,
	StripDiacritics: true,
	Lowercase:       true,
	CollapseSpace:   true,
	DeLeet:          true,
	StripSeparators: true,
}

// ForPII folds only what cannot change a value's meaning. Lowercasing an email
// is harmless but de-leeting a credit card number would destroy it, and the
// Luhn check downstream would then reject a real card.
var ForPII = Options{
	StripZeroWidth:  true,
	FoldConfusables: true,
	CollapseSpace:   false,
}

// ForTopic sits between the two.
var ForTopic = Options{
	StripZeroWidth:  true,
	FoldConfusables: true,
	StripDiacritics: true,
	Lowercase:       true,
	CollapseSpace:   true,
}

// Text is normalized output plus the map back to the source.
type Text struct {
	Value string

	// srcStart[i] / srcEnd[i] give the original byte span that produced
	// normalized byte i. Both have len(Value) entries.
	srcStart []int
	srcEnd   []int

	// Original is retained so callers can slice excerpts without threading the
	// input string through every call site.
	Original string
}

// Origin maps a normalized byte span onto the original string. The result is
// always a valid slice of Original, even for a degenerate input span.
func (t Text) Origin(start, end int) (int, int) {
	n := len(t.Value)
	if n == 0 || len(t.srcStart) == 0 {
		return 0, 0
	}
	if start < 0 {
		start = 0
	}
	if end > n {
		end = n
	}
	if start >= n {
		start = n - 1
	}
	if end <= start {
		s := t.srcStart[start]
		return s, s
	}
	return t.srcStart[start], t.srcEnd[end-1]
}

// Excerpt returns the original text behind a normalized span.
func (t Text) Excerpt(start, end int) string {
	s, e := t.Origin(start, end)
	if s < 0 || e > len(t.Original) || e < s {
		return ""
	}
	return t.Original[s:e]
}

// Empty reports whether normalization produced nothing scannable.
func (t Text) Empty() bool { return strings.TrimSpace(t.Value) == "" }

// Normalize applies opts to s.
//
// The output is built in a single pass straight into the buffer. An earlier
// version materialised an intermediate slice of per-rune "emission" structs,
// each holding a freshly allocated one-rune string; that cost two allocations
// per input rune and dominated the whole engine's profile -- a 60 KB prompt
// spent 42 ms here, against a 50 ms budget for the entire stage. Writing runes
// directly removes both allocations and leaves the offset map as the only
// heap-resident output.
func Normalize(s string, opts Options) Text {
	if s == "" {
		return Text{Original: s}
	}

	var b strings.Builder
	b.Grow(len(s))
	srcStart := make([]int, 0, len(s))
	srcEnd := make([]int, 0, len(s))

	// emit writes one output rune and records, for each of its bytes, the
	// source span it came from.
	emit := func(r rune, from, to int) {
		b.WriteRune(r)
		for range utf8.RuneLen(r) {
			srcStart = append(srcStart, from)
			srcEnd = append(srcEnd, to)
		}
	}

	pendingSpace := -1 // source offset of a whitespace run awaiting collapse

	for off, r := range s {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1 // invalid UTF-8: range yields RuneError with width 1
		}
		end := off + size

		if opts.StripZeroWidth && isInvisible(r) {
			continue
		}

		if opts.CollapseSpace && unicode.IsSpace(r) {
			if pendingSpace < 0 {
				pendingSpace = off
			}
			continue
		}
		if pendingSpace >= 0 {
			emit(' ', pendingSpace, off)
			pendingSpace = -1
		}

		out := r
		if opts.FoldConfusables {
			out = foldConfusable(out)
		}
		if opts.StripDiacritics {
			if base, ok := stripDiacritic(out); ok {
				out = base
			}
		}
		// Lowercase must precede DeLeet: the leet classes are keyed on lower
		// case, so folding "L" before casing it would leave it unmapped while
		// "l" got mapped, and the two would stop comparing equal.
		if opts.Lowercase {
			out = unicode.ToLower(out)
		}
		if opts.DeLeet {
			out = foldLeetClass(out)
		}

		// Only drop a separator when it sits between two word characters,
		// which is the shape of "i.g.n.o.r.e" but not of a real sentence.
		if opts.StripSeparators && isSeparatorNoise(out) && betweenWordChars(s, off, size) {
			continue
		}

		emit(out, off, end)
	}
	if pendingSpace >= 0 {
		emit(' ', pendingSpace, len(s))
	}

	return Text{
		Value:    b.String(),
		srcStart: srcStart,
		srcEnd:   srcEnd,
		Original: s,
	}
}

// isInvisible covers the characters used to break up keywords without changing
// how the text renders to a human or tokenizes for a model. Written as numeric
// escapes on purpose: these are invisible in an editor, so spelling them out
// is the only way the next reader can tell what is in this list.
func isInvisible(r rune) bool {
	switch r {
	case '\u200B', // zero width space
		'\u200C',           // zero width non-joiner
		'\u200D',           // zero width joiner
		'\u2060',           // word joiner
		'\uFEFF',           // BOM / zero width no-break space
		'\u00AD',           // soft hyphen
		'\u180E',           // mongolian vowel separator
		'\u200E', '\u200F', // LTR / RTL marks
		'\u202A', '\u202B', '\u202C', '\u202D', '\u202E', // bidi embedding/override
		'\u2066', '\u2067', '\u2068', '\u2069': // bidi isolates
		return true
	}
	// Variation selectors and combining grapheme joiner.
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	if r >= 0xE0000 && r <= 0xE007F { // tag characters: invisible, used to smuggle ASCII
		return true
	}
	return unicode.Is(unicode.Cf, r) && r != '\n'
}

func isSeparatorNoise(r rune) bool {
	switch r {
	case '.', '-', '_', '*', '|', '/', '\\', '+', '~':
		return true
	}
	return false
}

// betweenWordChars decides whether a separator sits inside a word, which is
// what makes "i.g.n.o.r.e" fold to "ignore".
//
// Both neighbour lookups skip invisible characters, and that is the whole
// subtlety. The neighbours are read from the *source* string, but the invisible
// characters are being deleted from the output -- so without the skip, an
// attacker defeats separator stripping by putting one zero-width space next to
// each separator. The separator then has an invisible neighbour instead of a
// letter, the "inside a word" test fails, and "send_email" survives folding
// intact while every other evasion is folded away.
//
// The red-team suite found this: tr-003~zero_width was the only variant in the
// corpus that still evaded after the tool-result patterns were folded, and it
// evaded through the shared normaliser rather than through anything specific to
// tool results. The same trick worked on the inbound rails.
func betweenWordChars(s string, off, size int) bool {
	prev := prevVisibleRune(s, off)
	next := nextVisibleRune(s, off+size)
	return isWordRune(prev) && isWordRune(next)
}

// skippable reports whether a rune will be removed from the output anyway, and
// so should not count as a neighbour when deciding whether a separator sits
// inside a word.
//
// Separators are skippable for the same reason invisibles are, and the case is
// "s.e.n.d._.e.m.a.i.l": the underscore's immediate neighbours are dots, so a
// single pass leaves it in place and the word never folds to "sendemail". An
// attacker only has to alternate two separator characters to defeat the whole
// check. Looking through anything destined for deletion closes that without a
// second pass over the string, which matters because the offset map is built in
// the same pass.
func skippable(r rune) bool { return isInvisible(r) || isSeparatorNoise(r) }

func isWordRune(r rune) bool {
	return r != 0 && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

// maxInvisibleSkip bounds the neighbour scan. A handful of skippable characters
// is an evasion; hundreds of them is a payload trying to make this loop the
// expensive part of the request. The bound keeps the whole normaliser linear.
const maxInvisibleSkip = 16

func prevVisibleRune(s string, off int) rune {
	for skipped := 0; skipped <= maxInvisibleSkip; skipped++ {
		r, start := runeBefore(s, off)
		if r == 0 {
			return 0
		}
		if !skippable(r) {
			return r
		}
		off = start
	}
	return 0
}

func nextVisibleRune(s string, off int) rune {
	for skipped := 0; skipped <= maxInvisibleSkip; skipped++ {
		if off >= len(s) {
			return 0
		}
		r, size := utf8.DecodeRuneInString(s[off:])
		if r == utf8.RuneError && size <= 1 {
			return 0
		}
		if !skippable(r) {
			return r
		}
		off += size
	}
	return 0
}

// runeBefore returns the rune ending at off, and the offset it starts at.
func runeBefore(s string, off int) (rune, int) {
	if off <= 0 || off > len(s) {
		return 0, 0
	}
	r, size := utf8.DecodeLastRuneInString(s[:off])
	if r == utf8.RuneError && size <= 1 {
		return 0, 0
	}
	return r, off - size
}

// foldLeetClass collapses each set of mutually-confusable characters onto a
// single representative.
//
// The subtlety is that leet substitution is many-to-many, not one-to-one: "1"
// stands for both "i" and "l", so any single-valued mapping is wrong half the
// time. Rewriting "1gn0re a11" with 1->l yields "lgnore all" and rewriting it
// with 1->i yields "ignore aii"; neither equals "ignore all", so a matcher
// keyed on real English never fires.
//
// Folding the whole class instead -- {i, l, 1, |} all become 'i' -- makes the
// mapping total and, crucially, idempotent. The catch is that patterns must be
// folded through this same function before matching, so that "ignore all"
// becomes "ignore aii" on both sides and compares equal. See
// injection.foldPhrase, which is the only supported way to author a signature.
func foldLeetClass(r rune) rune {
	switch r {
	case 'i', 'l', '1', '|':
		return 'i'
	case 'o', '0':
		return 'o'
	case 'e', '3':
		return 'e'
	case 'a', '4', '@':
		return 'a'
	case 's', '5', '$':
		return 's'
	case 't', '7':
		return 't'
	case 'b', '8':
		return 'b'
	case 'g', '9':
		return 'g'
	}
	return r
}

// FoldPhrase applies the injection-time normalization to a literal phrase so
// that signature authors can write natural English and still match folded
// text. Exported because the guards package must use exactly this function --
// a hand-folded constant would silently drift from the normalizer.
func FoldPhrase(s string) string { return Normalize(s, ForInjection).Value }

// stripDiacritic maps a precomposed accented Latin letter to its base form.
// A full NFD decomposition would pull in golang.org/x/text; this table covers
// Latin-1 Supplement and Latin Extended-A, which is where the realistic
// evasions live, with zero dependencies and no allocation.
func stripDiacritic(r rune) (rune, bool) {
	if r < 0xC0 || r > 0x17F {
		return r, false
	}
	const (
		upper = "AAAAAAACEEEEIIIIDNOOOOO*OUUUUY  aaaaaaaceeeeiiiidnooooo/ouuuuy y"
		extA  = "AaAaAaCcCcCcCcDdDdEeEeEeEeEeGgGgGgGgHhHhIiIiIiIiIiJjKkkLlLlLlLlLlNnNnNnnNnOoOoOoRrRrRrSsSsSsSsTtTtTtUuUuUuUuUuUuWwYyYZzZzZzs"
	)
	if r <= 0xFF {
		idx := int(r - 0xC0)
		if idx < len(upper) {
			c := rune(upper[idx])
			if c != ' ' && c != '*' && c != '/' {
				return c, true
			}
		}
		return r, false
	}
	idx := int(r - 0x100)
	if idx < len(extA) {
		return rune(extA[idx]), true
	}
	return r, false
}

// foldConfusable maps visually-identical non-ASCII characters to ASCII.
func foldConfusable(r rune) rune {
	if r < 0x80 {
		return r
	}
	// Fullwidth forms: ！ through ～ map linearly onto ASCII 0x21..0x7E.
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFF01 + '!'
	}
	// Mathematical alphanumeric symbols: 13 contiguous 52-letter alphabets
	// (bold, italic, script, fraktur, double-struck, sans, mono, ...).
	if r >= 0x1D400 && r <= 0x1D7CB {
		if c, ok := foldMathAlnum(r); ok {
			return c
		}
	}
	// Enclosed alphanumerics: circled latin small letters.
	if r >= 0x24D0 && r <= 0x24E9 {
		return 'a' + (r - 0x24D0)
	}
	if r >= 0x24B6 && r <= 0x24CF {
		return 'A' + (r - 0x24B6)
	}
	if c, ok := confusables[r]; ok {
		return c
	}
	return r
}

func foldMathAlnum(r rune) (rune, bool) {
	// Digits first: five 10-digit runs at the end of the block.
	if r >= 0x1D7CE && r <= 0x1D7FF {
		return '0' + (r-0x1D7CE)%10, true
	}
	if r > 0x1D7CB {
		return r, false
	}
	off := r - 0x1D400
	// Letter alphabets are 52 runes each (A-Z then a-z), though the block has
	// holes where characters were unified with earlier BMP assignments. The
	// modulo below is right for every unbroken alphabet and degrades to a
	// harmless near-miss inside the holed ones.
	pos := off % 52
	if pos < 26 {
		return 'A' + pos, true
	}
	return 'a' + (pos - 26), true
}

// confusables covers the Cyrillic and Greek homoglyphs that render
// indistinguishably from ASCII in almost every font.
var confusables = map[rune]rune{
	// Cyrillic lowercase
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ɡ': 'g', 'п': 'n',
	'в': 'b', 'м': 'm', 'к': 'k', 'т': 't',
	// Cyrillic uppercase
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'У': 'Y', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k',
	'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
	'χ': 'x', 'γ': 'y', 'σ': 'o', 'η': 'n',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
	'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	// Punctuation that breaks quoted-string and delimiter matching
	'‘': '\'', '’': '\'', '“': '"', '”': '"',
	'–': '-', '—': '-', '−': '-', ' ': ' ',
	'⁄': '/', 'ʼ': '\'', '،': ',',
	// Digits from other scripts
	'٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4',
	'٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9',
	'۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4',
	'۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9',
}
