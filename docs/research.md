# What an LLM gateway has to do: a capability map

This is the research behind the second phase of this project. It answers one
question: *what does an AI engineer have to build around a model before it is
safe, affordable and operable in production*, and then maps every answer to
the code in this repository, or says plainly that it is not here.

Sources: OWASP Top 10 for LLM Applications (2025), NIST AI RMF 1.0 and its
Generative AI Profile (NIST AI 600-1), MITRE ATLAS, the OpenTelemetry GenAI
semantic conventions, Meta's Llama Prompt Guard 2 and OpenAI gpt-oss-safeguard
model cards, and the published post-mortems of agent data-exfiltration chains
(the "lethal trifecta" pattern).

## 1. The four concerns

Every production LLM pipeline has to answer four questions, and each has its
own failure mode when ignored:

| Concern | Question | Failure when ignored |
|---|---|---|
| **Safety** | Can the model be made to do or say what the operator forbids? | Prompt injection, data leakage, unsafe actions |
| **Efficiency** | What does each answer cost, and is any of it waste? | Unbounded spend, latency the user notices |
| **Reliability** | What happens when a provider is slow or down? | Outage of the product = outage of the vendor |
| **Evidence** | How do we *know* any of the above is true? | Controls that silently stopped working |

A fifth concern, **operability** (logs, metrics, traces), is what makes the
other four visible.

## 2. Safety: OWASP LLM Top 10 (2025) coverage

| OWASP | Risk | Controls here | Where | Status |
|---|---|---|---|---|
| LLM01 | Prompt injection (direct) | 16-signal noisy-OR detector over adversarially normalised text; semantic tier (Prompt Guard 2, gpt-oss-safeguard) | `guards/inbound/injection.go`, `internal/judge` | ✅ measured: `experiment detectors` |
| LLM01 | Prompt injection (indirect, via tools) | Tool-result rails, taint tracking, lethal-trifecta invariant | `guards/toolresult`, `internal/agent` | ✅ `grctl agent` scenarios |
| LLM02 | Sensitive information disclosure | PII detection with checksums, HMAC vault redaction and restore; secrets detection with entropy | `guards/inbound/pii.go`, `secrets.go`, `core/vault.go` | ✅ measured: `experiment pii` |
| LLM03 | Supply chain | Pinned images, distroless runtime, `go.sum`; model catalog pins upstream ids | `Dockerfile`, `config/models.yaml` | ◐ partial: no SBOM/signing |
| LLM04 | Data and model poisoning | Out of scope for a gateway (training-time) | n/a | ✗ not applicable |
| LLM05 | Improper output handling | Markdown-image exfiltration blocking, JSON-schema enforcement with repair | `guards/outbound/format.go`, `schema.go` | ✅ |
| LLM06 | Excessive agency | Tool risk tiers, capabilities, dry-run, single-use call-bound approvals, egress allowlist | `internal/agent`, `guards/runtime` | ✅ |
| LLM01/06 | MCP tool poisoning, shadowing, rug pulls, lying annotations | Definition scanner, SHA-256 pinning, quarantine, operator grading (annotations only raise risk) | `internal/mcp` | ✅ tested against `grctl mcp-demo` |
| LLM07 | System prompt leakage | Canary tokens, n-gram overlap against the real system prompt | `guards/outbound/leak.go` | ✅ measured: `experiment asr` |
| LLM08 | Vector and embedding weaknesses | Semantic cache partitioned by tenant + system prompt; threshold measured for wrong-answer rate | `internal/cache/semantic.go` | ◐ cache only: no RAG store here |
| LLM09 | Misinformation | Lexical grounding check (advisory); semantic tier on outbound | `guards/outbound/grounding.go` | ◐ lexical, not entailment |
| LLM10 | Unbounded consumption | Token/cost quota per request, budget breaker per trace, rate limiting, `max_tokens` per route | `guards/inbound/quota.go`, `runtime/budget.go` | ✅ |

### Two-tier detection is the industry pattern, and why

Rules and classifiers fail differently. A rule is free, sub-millisecond,
explainable and exact on what it was written for, and blind to a paraphrase or
another language. A classifier generalises, costs 100 ms–3 s and money, and is
itself an injectable model. Production systems (Azure Prompt Shields behind
content filters, Llama Guard behind Prompt Guard, Cloudflare/Lakera-style
gateways) layer them. The design choices that matter are *when* to call the
expensive tier (`off | shadow | cascade | always`), whether to hide its latency
(`parallel`), and what happens when it fails (`fail_open`). All of them are
configurable here and measured in `experiment detectors`.

## 3. Efficiency

| Technique | What it saves | Implemented | Measured |
|---|---|---|---|
| Exact response cache (tenant-partitioned, over the masked payload) | Repeat questions: cost and latency | `internal/cache/cache.go` | `experiment efficiency` |
| Semantic cache (embedding similarity) | Paraphrased repeats | `internal/cache/semantic.go` | threshold sweep + wrong-answer rate |
| Model catalog with per-route `max_tokens` and reasoning effort | Over-generation, reasoning-token waste | `config/models.yaml` | ASR experiment latency/cost table |
| Provider prompt caching (cached-input pricing) | Long repeated system prompts | priced in `telemetry/pricing.go` | n/a |
| Cascade classification | Model calls on clean traffic | `judge.ModeCascade` | `experiment detectors` |
| Parallel (speculative) classification | Classifier latency | `GUARDRAILS_JUDGE_PARALLEL` | n/a |
| Local token estimation | A network round-trip per request | `internal/tokenize` | n/a |
| Streaming | Time-to-first-token | ✗ not implemented: streaming and outbound guards conflict (see below) | n/a |

**Streaming is a deliberate omission.** An outbound guard needs the whole
completion to decide; streaming sends tokens before the decision exists. The
production answers (buffer-then-release per sentence, or stream and retract)
each trade a guarantee for latency, and that trade deserves its own ADR rather
than a flag.

## 4. Reliability

| Technique | Implemented | Measured |
|---|---|---|
| Multi-provider routing behind stable aliases | `providers/router.go` | n/a |
| Fallback chains on retryable errors only (never on 4xx) | `Router.Complete` | `experiment resilience` |
| Circuit breaker with single-probe half-open | `providers/router.go` | `experiment resilience` |
| SDK retries with backoff (not stacked with router retries) | provider adapters | n/a |
| Per-guard timeouts, per-stage budgets, per-guard fail modes | `core/pipeline.go`, policy | `make eval` p99 gate |
| Graceful shutdown with drain | `cmd/server` | n/a |
| Rate-limit aware clients (429 back-off, TPM pacing) | `internal/experiment/env.go` | live runs |

## 5. Evidence and evaluation

| Practice | Implemented |
|---|---|
| Labelled corpus with detection *and* enforcement scoring | `internal/eval`, `make eval` |
| CI quality gates (F1, recall, FPR, p99) | `.github/workflows/ci.yml` |
| Adversarial mutation (red team) with catch-rate gate | `make redteam` |
| Agent trajectory scenarios as integration tests | `make agent` |
| **Held-out set** never used for tuning | `experiments/datasets/heldout_detection.jsonl` |
| **Public benchmarks**: deepset, Gandalf, jailbreak-classification, JailbreakBench, XSTest, NotInject, ToxicChat, InjecAgent; fetched at run time, revisions pinned, Wilson 95% CIs | `grctl experiment fetch` · `benchmarks` |
| **Objective attack success rate** (canary, no LLM judge) | `experiment asr` |
| **Cross-model comparison** on identical inputs | `experiment asr`, `pii` |
| **LLM-as-judge baselines** with the same written policy | `judge.PolicyJudge` |
| Reproducibility: call cache, recorded latency, seeds | `internal/experiment/env.go` |
| Experiment tracking: per-run JSON, trial rows, ledger, HTML | `experiments/runs/` |

## 6. Operability

| Signal | Implemented |
|---|---|
| Prometheus metrics: decisions, findings, per-guard latency, tokens, cost, upstream, fallbacks, circuits, cache, semantic tier | `telemetry/metrics.go` |
| OpenTelemetry traces exported over OTLP: HTTP → stage → guard → `chat <model>` with GenAI semantic-convention attributes | `telemetry/otel.go`, `providers/router.go` |
| Structured JSON audit log that never contains the matched value | `telemetry/audit.go` |
| Log shipping (Alloy → Loki) with trace-id ↔ log linking in Grafana | `deploy/` |
| Provisioned Grafana dashboard (generated, not hand-edited) | `deploy/grafana/gen_dashboard.py` |
| Alert rules for coverage loss, budget, latency, upstream health | `deploy/prometheus/alerts.yml` |
| Per-response attribution: route, attempts, cache, timing, cost, trace id | `server/proxy.go` |

## 7. Known gaps, ranked by what they would cost in production

1. **Streaming** (UX): see §3.
2. **Distributed cache and rate limits** (scale): both are per-process by design;
   a fleet needs Redis or the ingress layer.
3. **Entailment-based grounding** (correctness): the grounding guard is lexical.
4. **Signed session state for agents** (security): documented in ADR 0006.
5. **SBOM, image signing** (supply chain).
