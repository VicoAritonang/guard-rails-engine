# Deploying

The engine ships the way Grafana does: one container that is useful on its
own, configured by environment variables and mounted files, with a Helm chart
for Kubernetes. It is also a Go library for programs that want no network hop.

| Shape | When | How |
|---|---|---|
| Standalone container | one gateway for many apps | `docker run`, `deploy/compose/docker-compose.yml` |
| Sidecar | one gateway per app pod, on localhost | Helm `sidecars`, or add the container to your pod |
| Kubernetes service | shared, scaled, observed | `deploy/helm/guard-rails-engine` |
| Library | a Go program that owns its model calls | `pkg/guardrails` |
| Self-hosted models | no data leaves the network | `deploy/compose/docker-compose.local-models.yml`, `LOCAL_BASE_URL` |

## Container

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e GUARDRAILS_SECRET=$(openssl rand -hex 32) \
  -e GUARDRAILS_API_KEYS=$(openssl rand -hex 24) \
  -e GUARDRAILS_PROVIDER=openai -e OPENAI_API_KEY=sk-... \
  -v $PWD/my-policy.yaml:/etc/guardrails/custom/policy.yaml:ro \
  -e GUARDRAILS_POLICY=/etc/guardrails/custom/policy.yaml \
  ghcr.io/vicoaritonang/guard-rails-engine:latest
```

Files the image reads (override any by mounting and pointing the variable at it):

| File | Variable |
|---|---|
| `/etc/guardrails/policies/{balanced,strict}.yaml` | `GUARDRAILS_POLICY` |
| `/etc/guardrails/models.yaml` | `GUARDRAILS_MODELS` |
| `/etc/guardrails/mcp.yaml` | `GUARDRAILS_MCP` |
| `/etc/guardrails/pricing.yaml` | `GUARDRAILS_PRICING` |

The web page at `/` is a visualisation of the gateway's live traffic and can
be turned off with `GUARDRAILS_DASHBOARD=false`; the API does not depend on it.

## Helm

```bash
helm install guardrails deploy/helm/guard-rails-engine \
  --set secret.create=true \
  --set-string secret.values.OPENAI_API_KEY=sk-... \
  --set-string secret.values.GUARDRAILS_API_KEYS=$(openssl rand -hex 24) \
  --set serviceMonitor.enabled=true
```

Policy, model catalog and MCP config can be written inline in values
(`policy.inline`, `models.inline`, `mcp.inline`); the chart renders them into
a ConfigMap, mounts it, and rolls the pods when it changes. Self-hosted
classifiers go in `sidecars` and are reached on localhost. `GUARDRAILS_SECRET`
is generated once and kept across upgrades; every replica must share it.

## Self-hosted guard models

```bash
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.local-models.yml up -d
```

adds Ollama (Llama Guard 3, Granite Guardian, a vision model for OCR),
speaches (Whisper speech-to-text) and Prompt Guard 2 on
text-embeddings-inference, and points the gateway at them. Use vLLM instead of
Ollama for the Hugging Face ids in `config/models.yaml` (Qwen3Guard, Llama
Guard 4, Nemotron, gpt-oss-safeguard).

## Sizing

The deterministic guards need little (the inbound stage measures well under a
millisecond on a typical prompt; see `docs/eval-report.md`), so start at 100m
CPU and 128 Mi and scale on CPU. Attachments are held in memory while
they are read: budget about `concurrency × max_part_bytes × 3` above that,
which is why the chart's default limit is 512 Mi.

Before exposing a gateway to a network, read the
[deployment checklist](../SECURITY.md#deploying-safely).
