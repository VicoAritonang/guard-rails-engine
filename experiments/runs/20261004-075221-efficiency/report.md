# Response caching: savings and the semantic-cache correctness trade

**Question.** How much spend and latency do exact and semantic caching save on a realistic support workload, and at what similarity threshold does the semantic cache start serving wrong answers?

Run `20261004-075221` · version `dev` · 2026-10-04 07:52 UTC · 0 upstream calls, 49 replayed from the call cache · $0.0000

| | |
|---|---|
| Exact cache hit rate | **75.5%** spend 76% lower, mean latency 195ms |
| Semantic cache hit rate | **77.0%** at threshold 0.88, 0.0% wrong answers |
| Semantic lookup latency | **518ms** one embedding round-trip per exact miss |

## Findings

- On a Zipf-distributed support workload the exact cache serves 75.5% of requests, cutting spend 76% and mean latency from 825ms to 195ms.
- The lowest threshold at which no stored question is served another's answer is 0.88; at that point only 10.0% of paraphrases hit. With text-embedding-3-small, paraphrases and near-miss questions overlap in similarity, so the semantic cache buys few extra hits before it starts answering the wrong question.
- Exact + semantic @ 0.85 serves 78.0% of requests, of which 1.5% are another question's answer: a correctness failure that no latency or cost dashboard would show.
- The semantic layer raises mean latency (384ms vs 195ms with the exact cache alone): every exact miss now pays a 518ms embedding round-trip, and on this workload too few of those misses become hits to pay it back.
- Recommendation: ship the exact cache on by default and the semantic cache off, enabling it per route only after a sweep like this one on that route's own traffic.

## Semantic cache threshold sweep (leave-one-out)

| Threshold | Paraphrases answered correctly from cache | Any query served a different question's answer |
|---|---|---|
| 0.80 | 36.7% | 10.0% |
| 0.85 | 20.0% | 3.3% |
| 0.88 | 10.0% | 0.0% |
| 0.90 | 6.7% | 0.0% |
| 0.92 | 0.0% | 0.0% |
| 0.94 | 0.0% | 0.0% |
| 0.96 | 0.0% | 0.0% |
| 0.98 | 0.0% | 0.0% |

## Workload replay

| Configuration | Requests | Upstream calls | Hit rate | Wrong answers | Total cost | Cost vs no cache | Mean latency | p95 latency |
|---|---|---|---|---|---|---|---|---|
| No cache | 200 | 200 | 0.0% | 0 (0.0%) | $0.00404 | +0.0% | 825ms | 957ms |
| Exact cache | 200 | 49 | 75.5% | 0 (0.0%) | $0.00097 | -76.0% | 195ms | 922ms |
| Exact + semantic @ 0.88 | 200 | 46 | 77.0% | 0 (0.0%) | $0.00092 | -77.2% | 384ms | 1426ms |
| Exact + semantic @ 0.85 | 200 | 44 | 78.0% | 3 (1.5%) | $0.00088 | -78.3% | 381ms | 1422ms |

## Method notes

- Workload: 200 requests drawn Zipf(1) over 10 FAQ groups; 50% exact repeats, 35% paraphrases, 15% near-miss questions with different answers. Seed 7.
- Upstream answers and latencies were recorded once per distinct question and replayed into every configuration, so configurations differ only in caching.
- Semantic lookup latency is the median of single-query embedding calls measured in this run; embedding cost is priced at text-embedding-3-small rates.
- A wrong answer is a semantic hit whose stored question has a different identity (a near-miss, or another group).

<details><summary>Configuration</summary>

```json
{
  "model": "gpt-4.1-nano",
  "policy": "balanced",
  "policy_version": "1.0.0",
  "requests": 200,
  "seed": 7,
  "workers": 6
}
```
</details>
