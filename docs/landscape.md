# How this engine compares (November 2026)

This page maps the guardrail products and open-weight guard models teams
actually deploy onto this engine: what it covers natively, what it reaches by
calling the model in question, and what it does not do. "Native" means
deterministic code in this repository; "via tier" means the semantic tier
calls that model (ADR 0007, ADR 0012).

## OpenAI Guardrails (openai-guardrails-python / -js)

OpenAI's framework ships nine checks across pre-flight, input and output
stages, configured as JSON pipelines.

| OpenAI check | Here | How |
|---|---|---|
| Contains PII (Presidio; mask or block) | ✅ native | `pii`: regex plus checksums (Luhn, IBAN mod-97, NIK dates), reversible vault masking and outbound restore |
| Moderation (omni-moderation, 13 categories) | ✅ via tier | `moderation` classifier, text **and images** |
| Jailbreak (LLM, multi-turn) | ✅ native + tier | `injection` (16-signal ensemble, adversarial normalisation) plus Prompt Guard 2, gpt-oss-safeguard, Llama Guard 4, Qwen3Guard |
| Prompt injection detection on tool calls/outputs | ✅ native + tier | tool control plane (tiers, taint, approvals), tool-result rails, and the runtime `AlignmentPolicy` judge |
| URL filter (allow list, schemes, userinfo, subdomains) | ✅ native | `url_filter`, `url_filter_outbound` (also private addresses and raw IPs) |
| Off-topic prompts / custom prompt check | ✅ native + tier | `topic`, `custom_rules`, and a policy judge with your own written policy |
| NSFW text | ✅ via tier | Llama Guard S12, Qwen3Guard, moderation |
| Hallucination detection (vector store) | ◐ | `grounding` is lexical; no entailment model yet |

What this engine adds beyond it: a deterministic tier that costs nothing and
answers in under a millisecond, attachments (documents, images, audio), an
MCP gateway (definition poisoning, rug pulls, lying annotations), human
approval for irreversible tools, secret detection, system-prompt leak
detection, markdown-image exfiltration blocking, budget and loop breakers, and
an evaluation harness that gates CI.

## Guard models

| Model | Vendor | Size | Modalities | Here |
|---|---|---|---|---|
| Llama Guard 4 | Meta | 12B | text, multi-image | `llama_guard` format; image classifier for attachments |
| Llama Prompt Guard 2 | Meta | 22M / 86M | text | `prompt_guard` route or `tei:` sidecar |
| gpt-oss-safeguard | OpenAI | 20B / 120B | text | `policy` format with this repo's written policy |
| Qwen3Guard-Gen | Alibaba | 0.6B–8B | text | `qwen3guard` format (Controversial counted as unsafe) |
| Granite Guardian 3.x | IBM | 2B–8B | text | `granite_guardian` format with a named risk |
| Nemotron Content Safety | NVIDIA | 4B / 8B | text | `nemotron` format |
| PIGuard, DeBERTa injection models | community | <1B | text | `tei:` sidecar |
| OpenAI Privacy Filter | OpenAI | 1.5B MoE | text | not wired yet (the `pii` guard is deterministic) |
| OmniGuard, GuardReasoner-Omni | research | 3B–7B | text, image, audio, video | not wired; any OpenAI-compatible deployment can be added as a `policy` route |

Published recall on a 79k-prompt NIST-category benchmark (arXiv 2605.28830,
2026) ranges from 84% (Qwen3Guard-4B) to 25% (gpt-oss-safeguard-20B), with
model size uncorrelated with recall. That is why the default is a cascade —
rules first, then a classifier on the suspicious band — and why
`grctl experiment detectors` exists: measure a model on your traffic before
trusting its model card.

## Frameworks and gateways

| | NeMo Guardrails | LLM Guard | Bedrock / Azure guardrails | This engine |
|---|---|---|---|---|
| Deployment | Python library / server | Python library / API | managed cloud | single static binary, container, Helm, Go library, SDKs |
| Proxy (OpenAI API) | partial | no | vendor-locked | yes, any provider, with fallbacks |
| Tool-call control | dialog rails | no | limited | tiered control plane, approvals, MCP gateway |
| Attachments | no | no | images (vendor models) | documents, images, audio, video audio track |
| Self-hosted models | yes | yes | no | yes (`local` provider, `tei:` sidecars) |
| Measured, CI-gated | no | no | no | yes |

## Sources

- OpenAI Guardrails documentation: https://openai.github.io/openai-guardrails-python/
- mozilla-ai any-guardrail, June 2026 model sweep: https://github.com/mozilla-ai/any-guardrail/issues/179
- Benchmarking Open-Source Safety Guard Models (2026): https://arxiv.org/html/2605.28830v1
- Llama Guard 4 model card: https://build.nvidia.com/meta/llama-guard-4-12b/modelcard
- OmniGuard (2025): https://arxiv.org/html/2512.02306
- GuardReasoner-Omni (2026): https://arxiv.org/pdf/2602.03328
