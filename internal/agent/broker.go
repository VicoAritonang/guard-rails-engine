package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Executor performs a tool call, or describes what it would do.
//
// Preview and Execute are separate methods rather than one method with a flag,
// because a flag is one negation away from a dry run that mutates production.
// Splitting them means a mistake in the broker cannot turn a simulation into an
// effect: the code path that executes is never reached from the preview branch.
type Executor interface {
	// Preview returns a human-readable description of the effect, without
	// causing it. This is the text a person is shown when they approve.
	Preview(ctx context.Context, tool *Tool, args map[string]any) (string, error)
	// Execute causes the effect and returns what the tool produced.
	Execute(ctx context.Context, tool *Tool, args map[string]any) (core.ToolResult, error)
}

// Receipt is the audit record for one brokered call.
//
// Receipts chain: each one commits to the hash of the previous receipt in the
// session, so removing a call from the middle of a trace leaves a break rather
// than a gap. That is deliberately weaker than a signed log and deliberately
// cheaper -- it makes tampering detectable by anyone replaying the trace,
// without requiring a key on the read path.
type Receipt struct {
	ID        string    `json:"id"`
	Trace     string    `json:"trace,omitempty"`
	Tool      string    `json:"tool"`
	Tier      string    `json:"tier"`
	Signature string    `json:"signature"`
	At        time.Time `json:"at"`

	Allowed  bool     `json:"allowed"`
	DryRun   bool     `json:"dry_run,omitempty"`
	Replay   bool     `json:"replay,omitempty"`
	Controls []string `json:"controls,omitempty"`
	Denied   []string `json:"denied_by,omitempty"`

	// ArgsDigest fingerprints the arguments without recording them. Tool
	// arguments routinely carry exactly the data the rest of this engine works
	// to keep out of logs.
	ArgsDigest string `json:"args_digest"`

	Approver string `json:"approver,omitempty"`
	Error    string `json:"error,omitempty"`

	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash"`
}

// AuditSink receives receipts. Optional; the broker works without one.
type AuditSink interface {
	Receipt(r *Receipt)
}

// Outcome is the full result of brokering one call.
type Outcome struct {
	Assessment Assessment         `json:"assessment"`
	Executed   bool               `json:"executed"`
	DryRun     bool               `json:"dry_run,omitempty"`
	Preview    string             `json:"preview,omitempty"`
	Result     *core.ToolResult   `json:"result,omitempty"`
	Error      string             `json:"error,omitempty"`
	Receipt    *Receipt           `json:"receipt,omitempty"`
	Session    *core.SessionState `json:"session,omitempty"`
}

// Broker is the enforcement point for tool execution: assess, then act, then
// record. Nothing reaches an Executor without passing through here.
type Broker struct {
	eval  *Evaluator
	exec  Executor
	audit AuditSink
	now   func() time.Time
}

// NewBroker wires an evaluator to an executor.
func NewBroker(eval *Evaluator, exec Executor, audit AuditSink) (*Broker, error) {
	if eval == nil {
		return nil, errors.New("broker: an evaluator is required")
	}
	if exec == nil {
		return nil, errors.New("broker: an executor is required")
	}
	return &Broker{eval: eval, exec: exec, audit: audit, now: eval.opts.Now}, nil
}

// Evaluator exposes the evaluator, for handlers that need the catalog.
func (b *Broker) Evaluator() *Evaluator { return b.eval }

// Do brokers one tool call.
//
// The order is the whole point of the type: assess against a session that has
// not yet been advanced, refuse if anything is unmet, and only then execute.
// Committing state before the executor returns would leave a rate counter spent
// on a call that never happened; committing after is the correct trade, because
// the failure it admits -- a call that happened but was not counted -- is
// visible in the receipt.
func (b *Broker) Do(ctx context.Context, req Request) *Outcome {
	if req.Session == nil {
		req.Session = &core.SessionState{TraceID: req.Trace}
	}
	a := b.eval.Assess(req)
	out := &Outcome{Assessment: a, DryRun: req.DryRun, Session: req.Session}

	tool, known := b.eval.Catalog().Lookup(a.Tool)

	switch {
	case !a.Allowed():
		out.Receipt = b.record(req, &a, false, nil)
		return out

	case a.Replay:
		// A verified replay must not act again. Returning here rather than
		// re-executing is the entire value of the idempotency control: the
		// caller retried because it did not see the first response, not because
		// it wanted a second effect.
		out.Receipt = b.record(req, &a, false, nil)
		return out

	case !known:
		out.Error = "tool disappeared from the catalog between assessment and execution"
		out.Receipt = b.record(req, &a, false, errors.New(out.Error))
		return out
	}

	args := normalizeArgs(req.Call)

	if req.DryRun {
		preview, err := b.exec.Preview(ctx, tool, args)
		if err != nil {
			out.Error = err.Error()
			out.Receipt = b.record(req, &a, false, err)
			return out
		}
		out.Preview = preview
		// A completed dry run is what unlocks the real call, and it unlocks
		// exactly one call: the signature includes the arguments, so changing
		// so much as the recipient invalidates it.
		req.Session.RecordSimulation(a.Signature)
		out.Receipt = b.record(req, &a, true, nil)
		return out
	}

	res, err := b.exec.Execute(ctx, tool, args)
	if err != nil {
		out.Error = err.Error()
		// The call is still committed on failure. An executor error does not
		// prove the effect did not happen -- a timeout on a payment is the
		// canonical case -- so the rate counter and the idempotency claim
		// stand, and the retry is answered from the claim.
		b.eval.Commit(req, &a)
		out.Receipt = b.record(req, &a, false, err)
		return out
	}

	out.Executed = true
	out.Result = &res
	b.eval.Commit(req, &a)
	b.eval.ObserveResult(req.Session, res)
	req.Session.Step++
	out.Receipt = b.record(req, &a, true, nil)
	return out
}

func (b *Broker) record(req Request, a *Assessment, acted bool, err error) *Receipt {
	r := &Receipt{
		Trace:      req.Trace,
		Tool:       a.Tool,
		Tier:       a.Tier,
		Signature:  a.Signature,
		At:         b.now().UTC(),
		Allowed:    acted,
		DryRun:     req.DryRun,
		Replay:     a.Replay,
		Controls:   a.Controls,
		ArgsDigest: argsDigest(req.Call),
		PrevHash:   req.Session.AuditChain,
	}
	for _, req := range a.Requirements {
		r.Denied = append(r.Denied, req.Control)
	}
	if err != nil {
		r.Error = err.Error()
	}
	if req.ApprovalToken != "" && b.eval.opts.Approver != nil {
		if g, verr := b.eval.opts.Approver.Verify(
			req.ApprovalToken, req.Trace, a.Tool, a.Signature); verr == nil {
			r.Approver = g.Approver
		}
	}
	r.ID, r.Hash = receiptHash(r)
	req.Session.AuditChain = r.Hash
	if b.audit != nil {
		b.audit.Receipt(r)
	}
	return r
}

// receiptHash returns a stable id and chain hash for a receipt.
func receiptHash(r *Receipt) (id, hash string) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	// Hash the receipt with the hash fields cleared, so the value does not
	// depend on itself.
	clone := *r
	clone.ID, clone.Hash = "", ""
	_ = enc.Encode(clone)
	sum := hex.EncodeToString(h.Sum(nil))
	return "rcpt_" + sum[:16], sum
}

// argsDigest fingerprints arguments without storing them.
func argsDigest(c core.ToolCall) string {
	h := sha256.New()
	if len(c.Arguments) > 0 {
		if b, err := json.Marshal(c.Arguments); err == nil {
			h.Write(b)
		}
	} else {
		h.Write([]byte(c.Raw))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// VerifyChain replays a receipt list and reports the first break.
//
// A hash chain nobody checks is decoration, so the verifier ships with the
// writer.
func VerifyChain(receipts []*Receipt) error {
	prev := ""
	for i, r := range receipts {
		if r.PrevHash != prev {
			return fmt.Errorf("receipt %d (%s): chain breaks, expected prev_hash %q but found %q",
				i, r.ID, prev, r.PrevHash)
		}
		if _, want := receiptHash(r); want != r.Hash {
			return fmt.Errorf("receipt %d (%s): contents do not match its hash", i, r.ID)
		}
		prev = r.Hash
	}
	return nil
}
