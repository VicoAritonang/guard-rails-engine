# ADR 0006: Tool-level safety is its own layer

**Status:** accepted

## Context

The first three stages of this engine shape text. Inbound rails inspect what the
user wrote, outbound rails inspect what the model wrote, and both work because
text is inert until somebody reads it: a rail that misses a bad sentence
produces a bad sentence, and the worst case is bounded by that.

Agents break the assumption. Between the inbound and the outbound rail, the
model emits a tool call, and a tool call is not text; it is an effect. Money
moves. Email is delivered. A row is dropped. By the time there is a completion
to inspect, the outbound rail is auditing a receipt for something that already
happened.

Three consequences follow, and none of them is served by adding more patterns to
the existing rails:

1. **There is no later stage that can compensate.** Every other guard in this
   engine has a fallback: if inbound misses it, outbound might catch it. The
   tool rail has none, which is why it is the only layer here that fails closed
   by default with no per-tenant escape hatch above T3.
2. **The dangerous input is not the prompt.** It is the tool *result*: a web
   page, an inbound email, a support ticket someone else filed. That text
   reaches the model without any rail seeing it, and the user never wrote it and
   never read it.
3. **The dangerous pattern is a trajectory, not a call.** "Read a customer
   record" is fine. "Fetch a web page" is fine. "Send an email" is fine. The
   three of them in one session, in that order, is every published agent
   data-theft chain.

## Decision

Tool safety becomes a fourth interception point plus a control plane.

### A fourth stage

`StageToolResult` runs on what a tool returned, before that text is appended to
the model's context. It reuses the inbound injection detector and grades the
same signal one step higher, because the prior is different: a user typing
"ignore your instructions" is usually testing the product, and a web page saying
it has no benign reading at all.

### Two risk axes, not one number

Every tool is graded on **reversibility** (none / compensable / irreversible)
and **blast radius** (self / workspace / org / external / critical). A table
maps the pair to a tier, T0 through T4. The table is written as a table so a
reviewer can dispute it cell by cell.

**Exposure is tracked separately**: whether a tool returns private data,
attacker-authorable content, or both. This is the part of the design that pays
for itself. `web_fetch` breaks nothing and is a read: T0 by effect. It is also
the single most dangerous tool in the catalog, because it is how attacker-
authored text enters the context window. One number would have forced a choice
between calling it safe and calling it destructive, and it is neither.

### Controls escalate with tier

| Tier | Adds |
|---|---|
| T0 | argument schema |
| T1 | capability, rate limit |
| T2 | audit receipt |
| T3 | idempotency key, taint block, trifecta check |
| T4 | dry run, single-use human approval |

`egress_allowlist` is deliberately absent from that ladder: it is a property of
the tool (does it send bytes outward), not of the tier, so it is derived from
the tool's `Egress` flag. A baseline that demanded an allowlist from
`execute_shell`, which has no destination argument to check, would be dead
configuration that reads like protection.

### Four controls worth their own justification

**Taint.** Arguments derived from untrusted content are refused for T3+ tools.
This is what turns prompt injection from a text problem into an action problem:
nothing about the final call looks wrong: `send_email` is a permitted tool, and
the address is a valid address. What is wrong is the *provenance* of the
argument, and provenance is the only place the attack is visible.

**Approval scoped to the call.** A grant is bound to the tool name *and* the
canonical arguments. Binding to the tool name alone is the obvious
implementation and the one most systems ship; it authorises the category of
action and leaves the argument unreviewed, which is precisely the part an
injected instruction controls. An approval collected for "refund $12.40" cannot
be spent on "refund $12,400".

**Idempotency, checked whenever a key is supplied.** Not only when the tier
demands one. A caller that sends a key believes it is protected by it, and
ignoring a collision on a T2 tool because T2 does not require keys breaks
exactly the promise the caller thought they had.

**A closed catalog.** An agent runtime that can invent a tool name at inference
time has no risk model, because there is nothing to look the name up in.
Unknown tool is a refusal with no remedy.

### State travels in the payload

`SessionState` (capabilities, effect ledger, taint fingerprints, spent
approvals) lives on the transaction rather than inside the engine. The
interesting failures are trajectory-shaped and each step is a separate request
that may land on a different replica; keeping the state in the payload means the
guards stay pure and the gateway scales by adding replicas rather than by adding
sticky routing.

The taint ledger stores hashes, never text. That is a privacy property worth
having, since this structure travels in request bodies and lands in logs, and it
is also what keeps the state small enough to pass around every step.

## Consequences

**What this buys.** The exfiltration chain, the double payment, the hallucinated
tool, the injected instruction inside a retrieved document, and the approval
replayed on a larger amount are all refused by construction rather than by
pattern luck. Each is a scenario in `grctl agent`, which exits non-zero if any
of them stops behaving as documented.

**What it costs.** Every T4 tool needs a human in the loop, twice: once to see
the simulation, once to sign it. That is a real cost and the correct one for a
wire transfer; for a team that wants unattended email it is a real obstacle, and
they can lower `max_tier` or re-grade `send_email` in their own catalog. The
point is not that our grading is right for everyone. It is that lowering it is
an explicit act with a visible diff.

**What we accepted.** The session state is caller-supplied, so a compromised
agent runtime can lie about its own history. That is acceptable because the
runtime is inside the trust boundary; it stops being acceptable the moment the
state becomes browser-supplied, and the fix at that point is to sign it with the
same key that signs approvals.

**What we did not solve.** A domain allowlist is the wrong instrument for a bank
account number, and this engine does not constrain which account a transfer
reaches. The right control is a payee allowlist inside the payments system.
Naming the gap is better than shipping a hostname check against an IBAN and
calling it egress control.
