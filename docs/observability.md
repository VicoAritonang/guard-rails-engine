# Observability

`make up` (or `docker compose up -d --build`) starts the gateway with the full
stack it emits into:

| Service | URL | What it holds |
|---|---|---|
| Showcase | http://localhost:8080 | Live animation, request journeys, walkthrough, MCP tool gates, experiment lab |
| Operator console | http://localhost:8080/console | Playground for every stage, live proxy to any catalog model, route table |
| Grafana | http://localhost:3000 | Dashboard **Guardrails Gateway** (home), Prometheus + Loki + Jaeger datasources |
| Prometheus | http://localhost:9090 | Metrics; alert rules at `/alerts` |
| Jaeger | http://localhost:16686 | Traces (service `guardrails-engine`) |
| Loki | via Grafana → Explore | The JSON audit log, shipped by Alloy |

`make loadgen` drives mixed traffic (FAQ repeats, PII, held-out attacks,
harmful requests) through the gateway so every panel has data.

## The three signals and how they connect

```
 request ──► X-Trace-Id header ──► Jaeger trace ──► "Logs for this span" ──► Loki
                                        ▲                                      │
                                        └──── trace_id derived field ◄─────────┘
 Prometheus panels answer "how much / how often"; traces answer "why was this
 one slow"; logs answer "what did the engine decide and which rule fired".
```

### Traces

Every proxied request produces one trace:

```
POST /v1/chat/completions                     server span, W3C traceparent honoured
├─ guardrails.pipeline.inbound
│  ├─ guardrails.guard.injection / pii / secrets / topic / quota   (concurrent)
├─ guardrails.semantic.inbound
│  └─ chat meta-llama/llama-prompt-guard-2-86m                      GenAI attributes
├─ cache.semantic_lookup                                            (when enabled)
├─ chat openai/gpt-oss-20b                                          gen_ai.usage.*, fallback flag
│  └─ (a second chat span per fallback attempt)
└─ guardrails.pipeline.outbound
   └─ guardrails.guard.leak / format / restore / grounding
```

Upstream spans follow the OpenTelemetry GenAI semantic conventions
(`gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.model`,
`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`), so they render as
LLM calls in any backend that understands them.

### Metrics (selected)

| Series | Answers |
|---|---|
| `guardrails_requests_total{stage,action}` | Block / redact / allow rate per stage |
| `guardrails_findings_total{guard,category,severity}` | Which rules fire |
| `guardrails_stage_duration_seconds` · `guard_duration_seconds` | Guard overhead against the 50 ms budget |
| `guardrails_upstream_requests_total{provider,route,outcome,status}` | Provider health |
| `guardrails_upstream_duration_seconds{provider,route}` | Model latency |
| `guardrails_upstream_fallbacks_total` · `guardrails_circuit_open` | Resilience in action |
| `guardrails_proxy_duration_seconds{outcome}` | End-to-end latency: served / cached / blocked_* |
| `guardrails_cost_usd_total{model}` · `guardrails_tokens_total` | Spend |
| `guardrails_cache_lookups_total` · `cache_saved_usd_total` | Cache value |
| `guardrails_judge_calls_total{classifier,verdict}` · `judge_duration_seconds` | Semantic tier |
| `guardrails_semantic_tier_disagreements_total{direction}` | Where rules and classifiers disagree |
| `guardrails_guard_errors_total` · `degraded_decisions_total` | Coverage silently lost |

Labels are bounded by construction: routes come from the catalog (a
`provider:model` request is labelled `direct`), and nothing per-request ever
becomes a label.

### Logs

JSON on stdout, with an identical copy in `GUARDRAILS_LOG_FILE` that Alloy
tails into Loki. Events: `guardrail.decision`, `guardrail.semantic`,
`guardrail.usage`, `guardrail.tool_execution`, plus `http request` lines. Every
line inside a request carries `trace_id`. Findings are logged as category,
severity, offsets and an HMAC fingerprint, never the matched value.

Useful LogQL:

```logql
{job="guardrails", event="guardrail.decision", action="block"} | json
{job="guardrails", event="guardrail.semantic"} | json | disagreement != ""
{job="guardrails"} |= "upstream call failed"
```

### Alerts (`deploy/prometheus/alerts.yml`)

`GuardrailErrors`, `DegradedDecisions`, `InboundLatencyBudget`,
`BlockRateSpike`, `UpstreamErrorRate`, `CircuitOpen`, `SemanticTierFailing`,
`SpendRate`. During the first load test, `UpstreamErrorRate` and
`SemanticTierFailing` went to pending within minutes because the Groq free tier
was rate-limiting Prompt Guard while an experiment shared the quota; the alerts
caught a real degradation, which is the only kind of test that counts.

## Experiment tracking

Experiments are tracked separately from runtime telemetry, as files:

```
experiments/
├─ datasets/            versioned inputs (held-out detection set, ASR, PII, cache workload)
├─ runs/
│  ├─ index.jsonl       append-only ledger: run id, version, headline metrics, cost
│  └─ <run-id>-<name>/  result.json · trials.jsonl · report.md · report.html
├─ index.html           ledger page with the latest result of each experiment
└─ .callcache/          recorded model calls (gitignored)
```
