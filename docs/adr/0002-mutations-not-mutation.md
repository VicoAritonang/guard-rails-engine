# ADR 0002: Detectors describe mutations; the pipeline applies them

**Status:** accepted

## Context

Redaction has to rewrite the payload. The obvious implementation lets each guard
edit the transaction directly.

That forces a choice between two bad options. Either guards run sequentially,
and stage latency becomes the *sum* of every detector rather than the max, or
they run concurrently and race on the same string.

There is a subtler problem. Two detectors can legitimately claim overlapping
spans: the PII guard sees an email inside a connection string, the secrets guard
sees the whole connection string. If both apply their own edit, the second
splices a replacement into the middle of the first, and the output is corrupt in
a way no test that checks only "was it redacted" will catch.

## Decision

`Guard.Check` is pure with respect to the transaction. It returns `Mutation`
values (`{field, start, end, replacement}`) describing edits it *wants*.

The pipeline then:

1. Fans out every detector concurrently under a shared stage deadline.
2. Aggregates findings and mutations serially, in sorted guard order.
3. Resolves overlaps deterministically (earliest start wins; at equal starts the
   longest span wins; ties break on guard name).
4. Applies survivors **back to front**, so earlier offsets stay valid as the
   string changes length.
5. Discards mutations entirely when the resolved action is only `flag`:
   "observe" must not rewrite traffic.

## Consequences

Good: p99 tracks the slowest single guard rather than the sum. Redaction output
is byte-identical across runs and across replicas, which matters because a
masked prompt differing between replicas would make prompt caching useless and
debugging impossible. `ApplyMutations` is pure and directly unit-testable.

Bad: a guard cannot see another guard's rewrite within the same stage. In
practice this has not been needed, and the alternative (ordered passes) would
give back the concurrency this design exists to enable.
