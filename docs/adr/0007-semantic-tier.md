# 7. A semantic tier behind the deterministic guards, not inside them

Date: 2026-10-04 · Status: accepted

## Context

The deterministic guards are fast (~0.5 ms), free and explainable, and the
held-out detector benchmark shows their limit: they match what they were
written for. A paraphrased extraction attempt, or the same attack in
Indonesian or Chinese, carries no lexical signal and scores zero.

Model classifiers close that gap: Meta's Prompt Guard 2 (an injection
classifier) and OpenAI's gpt-oss-safeguard (a policy-following safety
reasoner), both served on Groq, plus OpenAI's moderation endpoint and any chat
model used as a judge. They cost 100 ms to several seconds and real money, and
they fail: rate limits, timeouts, unparseable output.

## Decision

Classifiers form a separate **semantic tier** (`internal/judge`) that runs
after the deterministic inbound stage and, optionally, after the outbound
stage. It is not a guard in the pipeline, because the pipeline enforces a 50 ms
stage budget: a classifier inside it would either breach the budget or be cut
off by it on every call.

The tier has four modes:

| Mode | When classifiers run | Enforces | Use |
|---|---|---|---|
| `off` | never | n/a | default |
| `shadow` | every allowed request, asynchronously | no | measure before enforcing; counts disagreements |
| `cascade` | only when the deterministic score is in the suspicious band (≥ `escalate_above`) or a finding was flagged | yes | cost-sensitive traffic |
| `always` | every request the rules allowed | yes | maximum recall |

`parallel` starts the upstream call while the classifier runs and discards the
completion if the verdict is unsafe. It hides classifier latency on clean
traffic at the cost of paying for completions that end up blocked; the
response reports that waste as `wasted_cost_usd`.

The tier **fails open** by default: the deterministic tier has already run, so
a classifier outage reduces coverage rather than removing it. The degradation is
visible (`judge_calls_total{verdict="error"}`, the `SemanticTierFailing` alert).
`GUARDRAILS_JUDGE_FAIL_CLOSED=true` flips it for regulated workloads.

Classifiers see the **masked** text. The semantic tier is an upstream like any
other, and redaction exists so upstreams never see raw values.

The judge prompt fences the content and labels it as data. A judge that reads
the text under review as instructions is itself injectable.

## Consequences

- Cascade cannot escalate what the rules never saw. The detector experiment
  quantifies exactly how much recall that costs versus `always`, which is the
  number an operator needs to choose between them.
- A semantic block is recorded as a finding with guard `semantic`, so audit,
  metrics and the 422 response have one shape for both tiers.
- Groq's free tier rate-limits the classifiers; under load the tier degrades.
  This was observed in practice during the experiments and is why the
  fail-open path is tested, not assumed.
