// Package inbound implements the pre-model interception layer: everything that
// must be true about a prompt before it is allowed to reach a provider.
package inbound

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/config"
	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/core/normalize"
	"github.com/vicoaritonang/guardrails-engine/internal/guards/detect"
)

// piiRule pairs a cheap regex with an expensive-but-decisive validator.
//
// The two-phase shape is deliberate. The regex is a recall-oriented filter that
// runs over the whole prompt; the validator is a precision-oriented check that
// runs only over candidates. Inverting that order -- validating everything, or
// trusting the regex alone -- either costs too much or produces a detector
// nobody keeps enabled.
type piiRule struct {
	ID       string
	Category string
	Label    string // vault label, e.g. EMAIL
	Severity core.Severity
	Pattern  *regexp.Regexp

	// Pre is the cheap necessary condition tested before the regex runs.
	Pre prefilter

	// Validate rejects candidates that match the shape but not the semantics.
	// A nil validator means the pattern is self-validating.
	Validate func(string) bool

	// Reject inspects the surrounding text and drops the match. Some false
	// positives are only visible from context: "user:hunter2@db.internal" is
	// a database password, not an email address, and no amount of looking at
	// the matched substring alone can tell the difference.
	Reject func(hay string, start, end int) bool

	// Base is the confidence when the pattern matches and validates with no
	// supporting context.
	Base float64

	// Context are lowercase keywords that, within contextWindow bytes of the
	// match, raise confidence. "4111111111111111" is probably a card; "card
	// number: 4111111111111111" certainly is.
	Context []string
}

const contextWindow = 48

var (
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}`)
	// Indonesian mobile numbers: +62/62/0 followed by 8 and 8-12 more digits.
	rePhoneID = regexp.MustCompile(`(?:\+62|\b62|\b0)8[1-9][0-9\-. ]{6,14}[0-9]`)
	// E.164-ish international numbers with separators.
	rePhoneIntl = regexp.MustCompile(`\+[1-9][0-9]{0,2}[\-. ]?(?:\([0-9]{1,4}\)[\-. ]?)?[0-9]{2,4}[\-. ]?[0-9]{2,4}[\-. ]?[0-9]{0,4}`)
	reCard      = regexp.MustCompile(`\b[0-9](?:[ \-]?[0-9]){11,18}\b`)
	reNIK       = regexp.MustCompile(`\b[0-9]{16}\b`)
	reNPWP      = regexp.MustCompile(`\b[0-9]{2}[.\-]?[0-9]{3}[.\-]?[0-9]{3}[.\-]?[0-9][.\-]?[0-9]{3}[.\-]?[0-9]{3}\b`)
	reSSN       = regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)
	reIBAN      = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b`)
	reIPv4      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)
	reIPv6      = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	rePassport  = regexp.MustCompile(`\b[A-Z][0-9]{7}\b`)
)

// piiRules is the detector table.
//
// Severity here answers "how bad is it if this reaches a third party", not
// "how confident are we". Confidence lives in Base/Context, and the policy
// decides what action a given severity earns.
var piiRules = []piiRule{
	{
		ID: "email", Category: "pii.email", Label: "EMAIL", Severity: core.SeverityMedium,
		Pattern: reEmail, Base: 0.95,
		Pre:     prefilter{NeedBytes: "@"},
		Context: []string{"email", "e-mail", "surel", "contact", "kontak"},
		Reject:  insideURLUserinfo,
		Validate: func(s string) bool {
			// Reject the placeholder addresses that litter documentation and
			// would otherwise make every code-help prompt a PII incident.
			low := strings.ToLower(s)
			for _, d := range []string{"@example.com", "@example.org", "@test.com", "@localhost", "@email.com"} {
				if strings.HasSuffix(low, d) {
					return false
				}
			}
			return !strings.Contains(low, "..") && len(s) <= 254
		},
	},
	{
		ID: "credit_card", Category: "pii.credit_card", Label: "CARD", Severity: core.SeverityCritical,
		Pattern: reCard, Base: 0.90,
		Pre:     prefilter{MinDigits: 12},
		Context: []string{"card", "kartu", "visa", "mastercard", "amex", "cc", "credit", "debit", "cvv", "payment"},
		Validate: func(s string) bool {
			if detect.IsRepeatedDigits(s) || detect.IsSequential(s) {
				return false
			}
			return detect.Luhn(s)
		},
	},
	{
		ID: "nik", Category: "pii.national_id", Label: "NIK", Severity: core.SeverityCritical,
		Pattern: reNIK, Base: 0.75, // 16 digits is common; require context or a valid date
		Pre:      prefilter{MinDigitRun: 16},
		Context:  []string{"nik", "ktp", "identitas", "penduduk", "national id", "kependudukan"},
		Validate: detect.NIK,
	},
	{
		ID: "npwp", Category: "pii.tax_id", Label: "NPWP", Severity: core.SeverityHigh,
		Pattern: reNPWP, Base: 0.85,
		Pre:      prefilter{MinDigits: 15},
		Context:  []string{"npwp", "pajak", "tax"},
		Validate: detect.NPWP,
	},
	{
		ID: "ssn", Category: "pii.national_id", Label: "SSN", Severity: core.SeverityCritical,
		Pattern: reSSN, Base: 0.90,
		Pre:      prefilter{MinDigits: 9, MinDigitRun: 2, NeedBytes: "-"},
		Context:  []string{"ssn", "social security"},
		Validate: detect.USSSN,
	},
	{
		ID: "iban", Category: "pii.bank_account", Label: "IBAN", Severity: core.SeverityCritical,
		Pattern: reIBAN, Base: 0.95,
		Pre:      prefilter{MinDigits: 2, MinDigitRun: 2},
		Context:  []string{"iban", "bank", "account", "rekening", "transfer"},
		Validate: detect.Mod97,
	},
	{
		ID: "phone_id", Category: "pii.phone", Label: "PHONE", Severity: core.SeverityMedium,
		Pattern: rePhoneID, Base: 0.80,
		Pre:     prefilter{MinDigits: 9, MinDigitRun: 3},
		Context: []string{"phone", "telepon", "telp", "hp", "wa", "whatsapp", "nomor", "call", "hubungi"},
	},
	{
		ID: "phone_intl", Category: "pii.phone", Label: "PHONE", Severity: core.SeverityMedium,
		Pattern: rePhoneIntl, Base: 0.55, // loose shape: needs context to clear threshold
		Pre:     prefilter{NeedBytes: "+", MinDigitRun: 2},
		Context: []string{"phone", "telepon", "mobile", "cell", "call", "contact", "tel"},
	},
	{
		ID: "passport", Category: "pii.passport", Label: "PASSPORT", Severity: core.SeverityHigh,
		Pattern: rePassport, Base: 0.35, // letter+7 digits is far too common alone
		Pre:     prefilter{MinDigitRun: 7},
		Context: []string{"passport", "paspor", "travel document"},
	},
	{
		ID: "ipv4", Category: "pii.ip_address", Label: "IP", Severity: core.SeverityLow,
		Pattern: reIPv4, Base: 0.70,
		Pre: prefilter{NeedBytes: ".", MinDigits: 4},
		Validate: func(s string) bool {
			// Loopback, link-local and documentation ranges are configuration,
			// not personal data.
			for _, p := range []string{"127.", "0.", "255.255.255.", "169.254.", "192.0.2.", "198.51.100.", "203.0.113."} {
				if strings.HasPrefix(s, p) {
					return false
				}
			}
			return s != "1.1.1.1" && s != "8.8.8.8"
		},
	},
	{
		ID: "ipv6", Category: "pii.ip_address", Label: "IP", Severity: core.SeverityLow,
		Pattern: reIPv6, Base: 0.70,
		Pre: prefilter{NeedBytes: ":"},
	},
}

// PII masks personally identifiable information before it leaves the perimeter.
type PII struct {
	cfg         *config.GuardConfig
	maskMode    string
	rules       []piiRule
	secret      []byte
	scanEncoded bool
	maxDepth    int
}

// NewPII constructs the guard from policy.
func NewPII(cfg *config.GuardConfig, secret []byte) (*PII, error) {
	mode := cfg.String("mask_mode", "vault")
	switch mode {
	case "vault", "label", "hash":
	default:
		return nil, fmt.Errorf("pii: mask_mode %q must be vault|label|hash", mode)
	}

	rules := piiRules
	if !cfg.Bool("detect_indonesian", true) {
		rules = nil
		for _, r := range piiRules {
			switch r.ID {
			case "nik", "npwp", "phone_id":
				continue
			}
			rules = append(rules, r)
		}
	}
	return &PII{
		cfg: cfg, maskMode: mode, rules: rules, secret: secret,
		scanEncoded: cfg.Bool("scan_encoded_layers", true),
		maxDepth:    max(cfg.Int("max_decode_depth", 2), 1),
	}, nil
}

func (g *PII) Name() string      { return config.GuardPII }
func (g *PII) Stage() core.Stage { return core.StageInbound }

// Check scans every attacker- or user-controlled field.
//
// The system prompt is deliberately excluded: it is authored by the operator,
// masking it would corrupt the application's own instructions, and any PII in
// it is there by the operator's choice rather than a user's mistake.
func (g *PII) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	for _, field := range tx.UserFields() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		g.scanView(tx, field.Field, field.Text, field.Text, nil, &res)

		// Encoded payloads are scanned too. Base64-wrapping a credit card
		// bypasses every offset-based detector while still handing the number
		// to the provider, and the model decodes it perfectly well. This gap
		// was found by the red-team suite in testdata, not in review.
		if g.scanEncoded {
			for _, layer := range normalize.DecodeLayers(field.Text, g.maxDepth) {
				if !valueSafeLayer(layer) {
					continue
				}
				l := layer
				g.scanView(tx, field.Field, l.Text, field.Text, &l, &res)
			}
		}
	}
	return res, nil
}

// scanView applies the rule table to one view of a field.
//
// When layer is non-nil, text is decoded plaintext that does not exist in the
// original string, so every finding is attributed to the encoded region as a
// whole and redaction replaces that whole region. Surgically masking inside a
// base64 blob and re-encoding it would be cleverer and much worse: the result
// would still decode to something the provider can read.
func (g *PII) scanView(tx *core.Transaction, field, text, original string, layer *normalize.Layer, res *core.Result) {
	norm := normalize.Normalize(text, normalize.ForPII)
	if norm.Empty() {
		return
	}
	// One pass over the text answers "could this rule possibly match" for all
	// eleven rules, and doubles as the lowercased copy the context check needs.
	stats := computeStats(norm.Value)
	lower := stats.lower
	claimed := make([][2]int, 0, 8) // spans already taken, in normalized coords

	for _, rule := range g.rules {
		if !rule.Pre.pass(stats) {
			continue
		}
		for _, loc := range rule.Pattern.FindAllStringIndex(norm.Value, 64) {
			if overlapsAny(claimed, loc[0], loc[1]) {
				continue
			}
			match := norm.Value[loc[0]:loc[1]]
			if rule.Validate != nil && !rule.Validate(match) {
				continue
			}
			if rule.Reject != nil && rule.Reject(norm.Value, loc[0], loc[1]) {
				continue
			}
			score := rule.Base
			if hasContext(lower, loc[0], loc[1], rule.Context) {
				// Noisy-OR toward certainty rather than a flat addition, so
				// context can never push a weak rule above a strong one.
				score += (1 - score) * 0.6
			}
			claimed = append(claimed, [2]int{loc[0], loc[1]})

			var start, end int
			var value string
			if layer == nil {
				start, end = norm.Origin(loc[0], loc[1])
				value = safeSlice(original, start, end)
			} else {
				start, end = layer.SrcStart, layer.SrcEnd
				value = safeSlice(original, start, end)
			}

			msg := fmt.Sprintf("%s detected in %s", rule.Label, field)
			if layer != nil {
				msg = fmt.Sprintf("%s detected in %s inside a %s-encoded payload",
					rule.Label, field, layer.Kind)
			}
			f := core.NewFinding(g.Name(), rule.ID, rule.Category, rule.Severity, score, msg)
			f.Spans = []core.Span{{
				Field: field, Start: start, End: end,
				Excerpt: core.Preview(match),
			}}
			f.Meta = map[string]string{
				"fingerprint": core.Fingerprint(g.secret, match),
				"length":      fmt.Sprint(len(match)),
			}
			if rule.ID == "credit_card" {
				f.Meta["brand"] = detect.CardBrand(match)
			}
			if layer != nil {
				f.Meta["surface"] = layer.Kind
			}
			res.Findings = append(res.Findings, f)

			res.Mutations = append(res.Mutations, core.Mutation{
				Guard:       g.Name(),
				Field:       field,
				Start:       start,
				End:         end,
				Replacement: g.mask(tx, rule.Label, value),
				Reason:      rule.Category,
			})
		}
	}
}

// mask renders the replacement text for a detected value.
func (g *PII) mask(tx *core.Transaction, label, value string) string {
	switch g.maskMode {
	case "label":
		// Cheapest and most private, but destroys coreference: two different
		// emails both become [EMAIL] and the model can no longer tell them
		// apart.
		return "[" + label + "]"
	case "hash":
		return fmt.Sprintf("[%s:%s]", label, core.Fingerprint(g.secret, value))
	default:
		return tx.Vault.Mask(label, value)
	}
}

// hasContext looks for a supporting keyword in a window around the match.
func hasContext(lowerText string, start, end int, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}
	lo := max(start-contextWindow, 0)
	hi := min(end+contextWindow, len(lowerText))
	window := lowerText[lo:hi]
	for _, k := range keywords {
		if strings.Contains(window, k) {
			return true
		}
	}
	return false
}

// insideURLUserinfo reports whether a match sits in the credentials section of
// a URL, as in "postgres://appuser:s3cr3t@db.internal.example/prod". The regex
// for an email happily matches "s3cr3t@db.internal.example" there, and masking
// it as PII would both mis-classify the finding and corrupt the connection
// string. The secrets guard is the right detector for that text.
func insideURLUserinfo(hay string, start, end int) bool {
	_ = end
	// Walk back to the start of the token; a ':' before the local part with a
	// "//" earlier still is the userinfo shape.
	i := start
	for i > 0 && hay[i-1] != ' ' && hay[i-1] != '\n' && hay[i-1] != '\t' {
		i--
	}
	token := hay[i:start]
	if !strings.Contains(token, ":") {
		return false
	}
	return strings.Contains(token, "://") || strings.HasSuffix(token, ":")
}

func overlapsAny(claimed [][2]int, start, end int) bool {
	for _, c := range claimed {
		if start < c[1] && c[0] < end {
			return true
		}
	}
	return false
}

func safeSlice(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	if end <= start {
		return ""
	}
	return s[start:end]
}
