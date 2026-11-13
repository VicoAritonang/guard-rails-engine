# 9. Experiments run on production code paths, against real models, and are recorded

Date: 2026-10-04 · Status: accepted

## Context

The evaluation harness (ADR 0005) scores the deterministic guards on a corpus
they were developed against. That is a regression baseline, not evidence that
the system works on traffic it has not seen, on models other than the one it
was tested with, or under provider failure.

## Decision

`grctl experiment` runs five experiments, each designed around one question:

| Experiment | Question | Real model calls |
|---|---|---|
| `detectors` | How does each detection layer generalise to a held-out set, at what cost? | classifiers |
| `asr` | How often does each model leak a canary secret, with and without each gateway layer? | 6 target models |
| `pii` | Does redact-and-restore protect values, and what does it cost in task success per model? | 6 target models |
| `efficiency` | What do exact and semantic caching save, and when does the semantic cache answer the wrong question? | embeddings + 1 model |
| `resilience` | What do fallback chains and circuit breaking buy during an outage? | none (seeded fault injection) |

Rules:

1. **Production code paths.** The router, guard engine, semantic tier and
   caches are built by the constructors the server uses (`internal/gateway`).
2. **Objective criteria where possible.** Attack success is a canary appearing
   in the output, not an LLM judge's opinion. PII exposure is the raw value
   appearing in the upstream payload.
3. **Held-out data.** `experiments/datasets/heldout_detection.jsonl` was
   written after the guards were frozen and is never used for tuning. When a
   held-out case fails, it stays failed in the dataset.
4. **Recorded and reproducible.** Every model call goes through a disk call
   cache keyed by everything that can change the answer, with the measured
   latency stored beside it. Re-running replays the data for free and reports
   the latency that was measured, not a disk read. Simulations are seeded.
5. **Tracked.** Each run writes `result.json`, `trials.jsonl`, `report.md` and
   `report.html` under `experiments/runs/<run-id>-<name>/` and appends to
   `experiments/runs/index.jsonl`; `experiments/index.html` is the ledger.
6. **Findings are generated from the numbers.** The text of each finding is
   computed from the same aggregates as the tables, so a re-run cannot leave a
   stale claim behind. Two analysis bugs (a sweep that compared near-misses
   against too few stored questions, and batch embedding latency charged per
   lookup) were found because a finding contradicted its own table, and the
   flawed runs were removed from the ledger.

## Consequences

- Runs cost money and quota. Groq's free tier (8k tokens/min, 1k requests/day
  per model) is the binding limit; the recorder paces per model and backs off
  on 429.
- Datasets are small and hand-built. Reports say so, and differences of a few
  points should be read as noise.
