# 12. Open-weight guard models are catalog routes with an output format

Date: 2026-11-13 · Status: accepted

## Context

The semantic tier (ADR 0007) shipped with Prompt Guard 2, gpt-oss-safeguard
and OpenAI moderation. By late 2026 the open-weight field had moved:
Llama Guard 4 (12B, text and images), Qwen3Guard (0.6–8B, Safe / Unsafe /
Controversial), Granite Guardian 3.x (risk named at inference time),
Nemotron Content Safety (Aegis taxonomy), and a long tail tracked by
mozilla-ai's any-guardrail. A 2026 benchmark of 14 open guard models
(arXiv 2605.28830) found recall ranging from 84% (Qwen3Guard-4B) to 25%
(gpt-oss-safeguard-20B), and no correlation between size and recall.

Each model answers in its own dialect, and each is served by many runtimes
(Groq, vLLM, Ollama, TGI, NIM).

## Decision

A guard model is an ordinary catalog route with a `guard:` field naming its
output format: `llama_guard`, `qwen3guard`, `granite_guardian`, `nemotron`,
`prompt_guard` or `policy`. The format is detected from the model id when
omitted, so `local:llama-guard3:8b` works with no catalog entry at all.
`judge.GuardModel` builds the right chat shape per stage (a user turn for
prompts, a user+assistant pair for responses), parses the answer into a
`Verdict`, and windows long input (head and tail first, where payloads sit).

Two further shapes:

- **`tei:` classifiers.** Sequence classifiers (Prompt Guard 2, PIGuard,
  DeBERTa injection models) run on Hugging Face text-embeddings-inference as a
  sidecar at 5–30 ms on CPU: `tei:http://promptguard:80?unsafe=MALICIOUS`.
- **A `local` provider** for any OpenAI-compatible server, which never falls
  back to the ambient OpenAI key.

Classifiers declare the stages they make sense on (`StageAware`). The tier now
runs on all four stages, and on `/v1/guard/*` as well as the proxy
(`GUARDRAILS_JUDGE_VALIDATE`). On the runtime stage, policy judges apply
`AlignmentPolicy`: does this tool call serve what the user asked? That is the
semantic counterpart of the deterministic tool control plane, and the
equivalent of OpenAI Guardrails' tool-level prompt-injection check.

Qwen3Guard's "Controversial" label counts as unsafe by default: the benchmark
attributes most of its recall to it.

## Consequences

- Adding a new guard model with a known format is a YAML edit.
- A new format is one parser function and one constant.
- Recall numbers for these models come from published benchmarks, not from
  this repository's experiments yet; `grctl experiment detectors` can measure
  any of them on the held-out set once its route is configured.
