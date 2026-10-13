package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CallSignature is a stable hash of a tool call's identity and arguments.
//
// It is the identity used by three unrelated controls -- loop detection,
// idempotency keys, and the scope binding on a human approval -- so it lives
// here rather than in any one of them. Arguments are serialised through
// encoding/json, which sorts map keys, so two semantically identical calls hash
// the same regardless of the field order the model emitted. Hashing the raw
// string instead would make every one of those controls defeatable by inserting
// a space.
func CallSignature(c ToolCall) string {
	h := sha256.New()
	h.Write([]byte(c.Name))
	h.Write([]byte{0})
	if len(c.Arguments) > 0 {
		if b, err := json.Marshal(c.Arguments); err == nil {
			h.Write(b)
		}
	} else {
		h.Write([]byte(c.Raw))
	}
	return c.Name + ":" + hex.EncodeToString(h.Sum(nil))[:12]
}
