# ADR 0001: Three interception stages, not one filter

**Status:** accepted

## Context

The obvious design is one filter in front of the model: inspect the prompt,
allow or deny. Most guardrail libraries stop there.

That design cannot express three failures that dominate real incidents:

1. A model completion that leaks the operator's own system prompt. The prompt
   that caused it was innocuous, so no inbound filter would have fired.
2. An agent that calls the same tool four hundred times. Every individual call
   is legitimate; the trajectory is not.
3. Markdown image exfiltration. The attack is entirely in the *output*, and its
   payload is data the model was legitimately given.

Each of these is invisible from the position an inbound-only filter occupies.

## Decision

Three stages, each with its own guard set, budget, and policy mapping:

- **Inbound** sees one request before it reaches a provider.
- **Runtime** sees a trajectory: prior tool calls, step count, cumulative spend.
- **Outbound** sees the completion plus the system prompt it should not contain.

A guard declares exactly one stage. The pipeline rejects a guard registered on
the wrong stage at construction time rather than skipping it at runtime, so a
wiring mistake fails at startup instead of becoming a silent coverage gap.

## Consequences

Good: each stage has a distinct threat model and a distinct latency budget
(runtime gets 25 ms because it runs many times per request; inbound and outbound
get 50 ms each because they run once). Guards stay small because they only see
what they need.

Bad: state that must cross stages (the redaction vault, cumulative usage) has
to be threaded explicitly by the caller. That is deliberate: holding it inside
the engine would require sticky routing and break stateless execution. The cost
is a slightly larger API surface for anyone using sidecar mode.
