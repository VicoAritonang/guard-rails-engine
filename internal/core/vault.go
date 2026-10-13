package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Vault holds the mapping between a masked placeholder and the original
// sensitive value for the lifetime of a single request.
//
// This is what makes redaction usable rather than merely safe. Stripping a
// customer's order number out of a prompt protects the upstream provider but
// leaves the model unable to answer the question. Instead we substitute a
// stable placeholder, let the model reason over it symbolically, and restore
// the real value on the way out -- so the provider never sees the raw datum
// while the user still gets a useful answer.
//
// The vault is deliberately in-memory and request-scoped: persisting it would
// recreate exactly the sensitive datastore that redaction exists to avoid, and
// would break the stateless-execution requirement.
type Vault struct {
	mu     sync.RWMutex
	secret []byte
	fwd    map[string]string // placeholder -> original
	rev    map[string]string // original -> placeholder (stable within a request)
	order  []string
}

// NewVault creates a vault. The secret keys the HMAC used to derive
// placeholder suffixes, so tokens are non-guessable but deterministic for a
// given (secret, value) pair -- the same email masked twice in one prompt
// yields the same placeholder, which preserves coreference for the model.
func NewVault(secret []byte) *Vault {
	return &Vault{
		secret: secret,
		fwd:    make(map[string]string),
		rev:    make(map[string]string),
	}
}

// placeholderRE matches the tokens Mask emits, e.g. [[PII:EMAIL:9f3a2c1d]].
var placeholderRE = regexp.MustCompile(`\[\[PII:([A-Z0-9_]+):([0-9a-f]{8})\]\]`)

// Mask stores value under a derived placeholder and returns the placeholder.
func (v *Vault) Mask(label, value string) string {
	if v == nil {
		return "[[REDACTED]]"
	}
	label = normalizeLabel(label)

	v.mu.Lock()
	defer v.mu.Unlock()

	key := label + "\x00" + value
	if ph, ok := v.rev[key]; ok {
		return ph
	}

	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(key))
	digest := hex.EncodeToString(mac.Sum(nil))[:8]

	ph := fmt.Sprintf("[[PII:%s:%s]]", label, digest)
	v.fwd[ph] = value
	v.rev[key] = ph
	v.order = append(v.order, ph)
	return ph
}

// Restore replaces every known placeholder in s with its original value. It
// only substitutes placeholders this vault issued, so a model that invents a
// plausible-looking token cannot use Restore as an oracle to exfiltrate data
// it was never shown.
func (v *Vault) Restore(s string) (string, int) {
	if v == nil || s == "" {
		return s, 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.fwd) == 0 {
		return s, 0
	}

	n := 0
	out := placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		if orig, ok := v.fwd[m]; ok {
			n++
			return orig
		}
		return m // unknown token: leave it visible rather than silently dropping it
	})
	return out, n
}

// Len reports how many distinct values are held.
func (v *Vault) Len() int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.fwd)
}

// Labels returns the placeholder labels issued, in insertion order. Used for
// telemetry; never returns the underlying values.
func (v *Vault) Labels() []string {
	if v == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.order))
	for _, ph := range v.order {
		if m := placeholderRE.FindStringSubmatch(ph); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func normalizeLabel(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == ' ', r == '_':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "VALUE"
	}
	return b.String()
}

// Fingerprint returns a short, non-reversible tag for a sensitive value. Audit
// logs record this instead of the value itself, which still allows an operator
// to correlate "the same card number appeared in 40 requests" without the
// audit log itself becoming a breach target.
func Fingerprint(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

// Preview renders a loggable excerpt of a sensitive match: first and last
// character with the middle masked, which is enough for a human to recognize a
// false positive without exposing the value.
func Preview(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 2:
		return strings.Repeat("*", len(r))
	case len(r) <= 6:
		return string(r[0]) + strings.Repeat("*", len(r)-1)
	default:
		return string(r[0]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1])
	}
}

// MaskKnown replaces every value this vault has already issued a placeholder
// for with that placeholder. It closes the return path: a tool that echoes a
// restored value ("paid to GB82…") must not hand the real value back to the
// model the redaction was protecting it from.
func (v *Vault) MaskKnown(s string) (string, int) {
	if v == nil || s == "" {
		return s, 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	n := 0
	for _, ph := range v.order {
		orig := v.fwd[ph]
		if orig == "" || !strings.Contains(s, orig) {
			continue
		}
		n += strings.Count(s, orig)
		s = strings.ReplaceAll(s, orig, ph)
	}
	return s, n
}
