package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Grant is a human authorisation for one specific tool call.
//
// The field that makes this a control rather than a formality is Signature. A
// grant is bound to the exact call it was shown to a person -- tool name plus
// canonical arguments -- so an approval collected for "refund $12.40 on order
// A-3312" cannot be replayed against "refund $12,400 on order A-9000". Binding
// only to the tool name, which is the obvious implementation and the one most
// systems ship, would authorise the *category* of action and leave the argument
// unreviewed, which is precisely the part an injected instruction controls.
type Grant struct {
	ID        string    `json:"id"`
	Trace     string    `json:"trace"`
	Tool      string    `json:"tool"`
	Signature string    `json:"signature"`
	Approver  string    `json:"approver"`
	Reason    string    `json:"reason,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Approver mints and verifies grants.
//
// Grants are self-contained signed tokens rather than rows in a table, for the
// same reason the session state travels in the payload: the gateway stays
// stateless and any replica can verify any grant. Single use is enforced
// against the session's spent list, which the caller carries.
type Approver struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewApprover builds an approver. The secret must be the same across the fleet,
// or a grant minted by one replica fails verification on another.
func NewApprover(secret []byte, ttl time.Duration) (*Approver, error) {
	if len(secret) < 16 {
		return nil, errors.New("approver: secret must be at least 16 bytes")
	}
	if ttl <= 0 {
		// Short by design. An approval is a human saying "yes, now"; a grant
		// that outlives the conversation it belongs to is a standing
		// authorisation nobody remembers giving.
		ttl = 10 * time.Minute
	}
	return &Approver{secret: append([]byte(nil), secret...), ttl: ttl, now: time.Now}, nil
}

// SetClock overrides the time source, for tests.
func (a *Approver) SetClock(fn func() time.Time) {
	if fn != nil {
		a.now = fn
	}
}

// TTL reports the grant lifetime.
func (a *Approver) TTL() time.Duration { return a.ttl }

// Issue mints a grant token for a specific call.
func (a *Approver) Issue(trace, tool, signature, approver, reason string) (string, *Grant, error) {
	if tool == "" || signature == "" {
		return "", nil, errors.New("approver: tool and signature are required")
	}
	if approver == "" {
		// An unattributed approval is not an approval. If the console cannot
		// say who clicked, the audit trail cannot either.
		return "", nil, errors.New("approver: an approver identity is required")
	}
	now := a.now().UTC()
	g := &Grant{
		ID:        grantID(trace, signature, now),
		Trace:     trace,
		Tool:      tool,
		Signature: signature,
		Approver:  approver,
		Reason:    reason,
		IssuedAt:  now,
		ExpiresAt: now.Add(a.ttl),
	}
	body, err := json.Marshal(g)
	if err != nil {
		return "", nil, err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + a.sign(payload), g, nil
}

// Verify checks a token's signature, expiry and scope.
//
// The scope check is not optional and takes no "close enough" path: the grant's
// signature must equal the signature of the call being attempted, byte for
// byte.
func (a *Approver) Verify(token, trace, tool, signature string) (*Grant, error) {
	payload, mac, ok := strings.Cut(token, ".")
	if !ok {
		return nil, errors.New("approval token is malformed")
	}
	// Constant-time comparison: a token check that leaks timing is a token
	// check an attacker can grind.
	if !hmac.Equal([]byte(mac), []byte(a.sign(payload))) {
		return nil, errors.New("approval token signature is invalid")
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("approval token payload is malformed")
	}
	var g Grant
	if err := json.Unmarshal(body, &g); err != nil {
		return nil, errors.New("approval token payload is malformed")
	}
	if now := a.now().UTC(); now.After(g.ExpiresAt) {
		return nil, fmt.Errorf("approval expired at %s", g.ExpiresAt.Format(time.RFC3339))
	}
	if trace != "" && g.Trace != "" && g.Trace != trace {
		return nil, fmt.Errorf("approval was issued for trace %q, not %q", g.Trace, trace)
	}
	if g.Tool != tool {
		return nil, fmt.Errorf("approval was issued for tool %q, not %q", g.Tool, tool)
	}
	if g.Signature != signature {
		return nil, errors.New("approval was issued for different arguments than the call being attempted")
	}
	return &g, nil
}

func (a *Approver) sign(payload string) string {
	m := hmac.New(sha256.New, a.secret)
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func grantID(trace, signature string, now time.Time) string {
	h := sha256.New()
	_, _ = h.Write([]byte(trace))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(signature))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(now.Format(time.RFC3339Nano)))
	return "grant_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:16]
}
