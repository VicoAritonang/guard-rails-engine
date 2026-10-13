# Resilience under provider failure: fallback chains and circuit breaking

**Question.** How much availability does a fallback chain buy during a provider outage, and what does the circuit breaker add on top?

Run `20261006-133405` · version `dev` · 2026-10-06 13:34 UTC · 0 upstream calls, 0 replayed from the call cache · $0.0000

| | |
|---|---|
| Availability, single provider | **62.5%** primary down for 20 s of 60 s |
| Availability, fallback + breaker | **99.2%** p95 1184ms |
| Dead-primary calls avoided by the breaker | **200 → 5** during the outage window |

## Findings

- A single provider serves 62.5% of traffic through a 20-second outage; a fallback chain serves 99.2%.
- Fallback alone still sends every outage request to the dead primary first (200 calls), so each one pays the 2 s timeout: p95 is 3128ms. The circuit breaker stops trying after 3 failures and probes once per cooldown, cutting dead calls to 5 and p95 to 1184ms.
- The breaker never refuses a request; it only reorders where the request is sent. Availability is the fallback chain's job, latency during an outage is the breaker's.

## Outcome by configuration

| Configuration | Success rate | Success during outage | p50 | p95 | p99 | Calls to the dead primary during outage | Served by backup |
|---|---|---|---|---|---|---|---|
| Single provider | 62.5% | 0.0% | 738ms | 2000ms | 2000ms | 200 | 0 |
| Fallback chain | 99.2% | 97.5% | 738ms | 3128ms | 3196ms | 200 | 220 |
| Fallback + circuit breaker | 99.2% | 97.5% | 710ms | 1184ms | 3095ms | 5 | 222 |

## Method notes

- 600 requests at one per 100ms (virtual clock); primary has 5% random 503s and is fully down from 20s to 40s; backup has 2% random 503s and is slower.
- The router and circuit breaker are the production implementation; only the providers are simulated (seeded, reproducible).
- Breaker: opens after 3 consecutive failures, half-opens after 5 s with a single probe.

<details><summary>Configuration</summary>

```json
{
  "policy": "balanced",
  "policy_version": "1.0.0",
  "quick": true,
  "seed": 42,
  "workers": 6
}
```
</details>
