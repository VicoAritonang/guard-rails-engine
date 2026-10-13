# PII redaction round-trip across models

**Question.** Does redact-and-restore keep personal data away from model providers, and what does it cost in task success on each model?

Run `20261004-102831` · version `dev` · 2026-10-04 10:28 UTC · 144 upstream calls, 0 replayed from the call cache · $0.0062

| | |
|---|---|
| PII exposed to providers, no gateway | **100%** 14 values per model sent verbatim |
| PII exposed with redaction | **0.0%** 0/84 values |
| Task success cost of redaction | **-16.7 pts** redacted minus raw, all models |

## Findings

- Redaction kept all 84 personal values in this set away from the providers.
- Task success went from 94.4% with raw prompts to 77.8% with redact-and-restore across all models.
- Placeholder preservation is a model property: models that copy the opaque token verbatim lose nothing to redaction; models that rewrite, drop or 'helpfully' replace it with an invented value lose the task. That makes it a model-selection criterion for any PII-sensitive workload.

## Redaction round-trip by model

| Model | Tasks | Task success, raw | Task success, redacted | Placeholders preserved | Refusals, raw | Refusals, redacted | Values exposed to provider (redacted) | Errors |
|---|---|---|---|---|---|---|---|---|
| gpt-5-nano | 12 | 91.7% | 50.0% | 57.1% | 0 | 0 | 0/14 | 0 |
| gpt-5-mini | 12 | 91.7% | 91.7% | 92.9% | 0 | 0 | 0/14 | 0 |
| gpt-4.1-nano | 12 | 100.0% | 58.3% | 57.1% | 0 | 0 | 0/14 | 0 |
| gpt-oss-20b | 12 | 100.0% | 83.3% | 85.7% | 0 | 0 | 0/14 | 0 |
| gpt-oss-120b | 12 | 91.7% | 100.0% | 100.0% | 0 | 0 | 0/14 | 0 |
| qwen3-27b | 12 | 91.7% | 83.3% | 85.7% | 0 | 0 | 0/14 | 0 |

## Method notes

- Values are compared after removing spaces, hyphens and brackets, so a phone number reformatted by the model still counts as correct.
- The system prompt tells the model what a placeholder is. Without that line preservation drops further; the instruction is part of a correct deployment.
- Exposure is measured on the payload actually sent upstream after the inbound stage.

<details><summary>Configuration</summary>

```json
{
  "models": [
    "gpt-5-nano",
    "gpt-5-mini",
    "gpt-4.1-nano",
    "gpt-oss-20b",
    "gpt-oss-120b",
    "qwen3-27b"
  ],
  "policy": "balanced",
  "policy_version": "1.0.0",
  "workers": 6
}
```
</details>
