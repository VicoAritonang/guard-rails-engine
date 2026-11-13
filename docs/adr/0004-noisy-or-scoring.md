# ADR 0004: Score with noisy-OR, not summed weights

**Status:** accepted

## Context

Prompt injection has no single decisive tell. "Ignore" appears in legitimate
prompts ("ignore case when sorting"), role markers appear in any discussion of
prompting, and base64 appears in half of all engineering questions. What
distinguishes an attack is the *combination*, so the detector has to score
rather than match, and the combination rule is a real modelling choice.

The naive rule is to sum signal weights and clamp at 1.0. It saturates: two
mid-weight signals reach the ceiling, after which every additional signal is
free. Ranking collapses, and a tunable threshold stops meaning anything,
which defeats the entire point of shipping a threshold sweep.

## Decision

Combine independent signals with noisy-OR:

```
P(attack) = 1 - Π (1 - wᵢ)
```

Each signal is treated as an independent chance to catch the attack. The result
is bounded by construction, strictly increasing in every signal, and never
saturates, so the ordering between a two-signal and a five-signal prompt is
preserved and a threshold sweep produces a meaningful curve.

Two refinements, both added because the evaluation harness demanded them:

- **Distinct phrases within one signal compound.** A message containing both
  "this is your administrator" and "debug mode enabled" has produced two
  independent instances of the same tell. Treating that identically to one let an
  authority-spoofing case through the corpus. The compounding is capped at three
  so a long document cannot accumulate certainty from vocabulary alone.
- **Encoded hits are boosted.** Reaching the model through a base64 layer is
  itself evidence of intent, so the same phrase weighs more when it arrives
  encoded than when written in the clear.

## Consequences

Good: the threshold is a real knob with a real curve behind it, published in
`docs/eval-report.md`. Adding a signal cannot silently break the ranking of
existing ones.

Bad: weights are not independently interpretable: changing one shifts the whole
distribution, so the sweep must be re-run after any edit to the table. The
signal table says so in a comment directly above it.

A footnote on why this matters: an early bug had ROT13 decoding return the
original text at depth 2, so every plain-text prompt produced a phantom "encoded"
duplicate of its own signals. Noisy-OR compounded them into scores near 0.999.
Fixing the decoder dropped the score for a real attack from 0.999 to an honest
0.96, and immediately exposed a genuine false negative that the inflated score
had been hiding. Scores that are too high are not a safety margin; they are a
blindfold.
