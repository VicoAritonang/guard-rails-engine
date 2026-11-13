# ADR 0005: Evaluation is a build gate, not a report

**Status:** accepted

## Context

A guardrail with no evaluation is a claim, not a control. But an evaluation that
produces a document nobody opens is barely better: detection quality regresses
silently, and the regression is discovered by an incident rather than by CI.

The specific failure this guards against is subtle. Detection rules are edited
constantly (a new phrasing here, a tightened pattern there), and almost every
such edit that improves recall on one attack family costs precision on another.
Without a gate, that trade is invisible and unattributed.

## Decision

`internal/eval` ships a labelled corpus, a scoring harness, and thresholds that
**fail the build**:

```
--min-f1 0.90  --min-recall 0.80  --max-benign-fpr 0.05  --max-p99 50ms
--min-catch-rate 0.90   (red team)
```

Four properties make the numbers trustworthy rather than decorative:

1. **Detection and enforcement are scored separately.** A detector can be right
   while the severity-to-action mapping is wrong; conflating them hides both.
2. **Benign false-positive rate is a headline metric**, not a footnote. It is the
   number that decides whether a guardrail survives contact with a product team.
3. **Macro, not micro, averaging.** Micro-averaging lets a large easy family mask
   total failure on a small hard one, and the small hard one is usually why the
   guardrail exists.
4. **Cases run sequentially.** Parallelism would finish faster and make the
   latency percentiles meaningless.

The red-team suite regenerates evasion variants from the labelled attacks on
every run, so "we handle homoglyphs" is re-proved rather than remembered.

## Consequences

Good: a detection regression fails a pull request with a named case id. Six real
bugs in this codebase were found this way, including one (an inflated injection
score caused by ROT13 double-decoding) that no unit test would have caught,
because every individual component was behaving as written.

Bad: the corpus is small and hand-built, so the absolute figures are a regression
baseline rather than a benchmark claim. The report says so itself: when the
precision curve is flat across the whole threshold range, it prints a warning
that the corpus lacks hard negatives and that the "suggested threshold" is a
dataset artefact. A number that flatters the system without saying what it cannot
see is worse than no number.
