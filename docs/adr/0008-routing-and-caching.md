# 8. Model catalog, fallback routing and a response cache in the gateway

Date: 2026-10-04 · Status: accepted

## Context

The gateway originally fronted one provider. Adding Groq raised three
questions at once: how clients name models across vendors, what happens when a
vendor is down, and whether repeated questions should be paid for twice.

## Decisions

### Clients ask for aliases, not upstream ids

`config/models.yaml` maps stable aliases (`gpt-oss-20b`) to a provider and an
upstream id (`groq` / `openai/gpt-oss-20b`), plus per-route `max_tokens`,
reasoning effort and a fallback list. Vendor ids are naming decisions that
change; a client hard-coding them cannot be failed over to a model whose id it
never knew. `provider:model` bypasses the catalog. It uses a colon because Groq ids
already contain slashes.

### Fallback on upstream faults only

The router moves to the next route on retryable errors (429, 5xx, transport)
and never on 4xx: a malformed request is malformed everywhere, and falling back
would hide the bug while multiplying its cost. The router does **not** retry
the same upstream: the SDKs already do, and stacking retries turns a brown-out
into minutes of queued work.

### A circuit breaker per upstream

Without it, every request during an outage pays the full timeout against the
dead upstream before falling back. The breaker opens after N consecutive
faults, refuses for a cooldown, then lets exactly one probe through. The
resilience experiment measures what it buys: p95 during an outage drops from
the timeout to roughly the fallback's own latency.

### Groq gets its own constructor

The OpenAI SDK reads `OPENAI_API_KEY` and the organisation headers from the
environment when none are passed. Pointing it at Groq via a base-URL override
would send the OpenAI credential to a third party whenever `GROQ_API_KEY` was
unset. `NewGroq` refuses to start without its own key and strips those headers;
a unit test pins this.

### The cache keys on the masked payload and replays through outbound

- Keys include tenant, model, system prompt, messages and `max_tokens`, all
  **after** inbound redaction. Vault placeholders are an HMAC of the value, so
  the same email produces the same key, but the cache never holds the email.
- Entries hold the raw upstream completion. A hit is replayed through the
  outbound stage with the current policy and *this* request's vault, so a rule
  tightened after the entry was written still applies and placeholders restore
  to this caller's values.
- Tenants never share entries: a shared entry would let one tenant observe
  whether another asked a question.
- Refusals and truncated completions are not cached.

### The semantic cache is off by default

Embedding similarity cannot tell "how do I cancel my order" from "how do I
place my order" reliably. The efficiency experiment sweeps the threshold and
measures wrong answers on near-miss questions; with `text-embedding-3-small`
the safe threshold leaves few extra hits, and each exact miss pays an
embedding round-trip. It is available per deployment, after a sweep on that
deployment's own traffic.

## Consequences

- Both caches and the breaker are per-process. A fleet without sticky routing
  sees a lower hit rate; a shared cache (Redis) is the next step and would
  reintroduce a network dependency into the request path.
- Every proxied response reports `route`, `provider`, `attempts`, `cache` and a
  timing breakdown, so "why was this slow / expensive / from a different
  model" is answerable from the response alone.
