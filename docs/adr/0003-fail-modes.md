# ADR 0003: Fail mode is per-guard policy, never a library default

**Status:** accepted

## Context

Every guard can fail: a regex catastrophe, a nil map, a timeout under load. The
engine must decide what happens to the request when detection is unavailable.

Both answers are defensible and they are opposites:

- **Fail open.** A consumer chat product should not go down because a PII
  detector regressed. Availability is the product.
- **Fail closed.** A regulated workload must not forward unscanned traffic. A
  refused request is recoverable; an unlogged disclosure is not.

Picking one as a library default guarantees that half of all deployments are
silently wrong, and silently is the operative word, because a fail-open guard
that never fires looks exactly like a guard that finds nothing.

## Decision

`fail_mode` is a required, per-guard policy field, validated at load time. The
engine does not infer it.

The shipped defaults reflect blast radius rather than convenience. The balanced
profile fails open for detectors whose failure degrades quality (`injection`,
`topic`, `format`, `pii`) and fails **closed** for the four whose failure has
unbounded downside: `secrets` (a leaked credential cannot be un-leaked),
`tool_policy` (real infrastructure), `budget_breaker` and `quota` (real money),
and `leak` (system-prompt exfiltration). The strict profile fails closed
everywhere.

Every swallowed failure is recorded three ways: the decision is marked
`degraded`, `guardrails_guard_errors_total{guard,kind,fail_mode}` increments, and
the failure is logged at WARN. A guard timing out on every request must never be
indistinguishable from a guard finding nothing.

`grctl policy lint` warns when one of the four high-blast-radius guards is
configured fail-open.

## Consequences

Good: the operator's risk posture is explicit, greppable, and reviewable in a
pull request. The eval harness can assert both modes behave as specified.

Bad: a policy file cannot be minimal: every guard an operator overrides must
state its fail mode. That verbosity is the point.
