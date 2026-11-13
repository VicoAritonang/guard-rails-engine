# Integrations

There are four ways in, from least to most code. All of them run the same guards.

| You have | Use | Code change |
|---|---|---|
| Anything that speaks the OpenAI API | [The proxy](#the-proxy) | Change the base URL |
| An MCP client (Claude, Cursor, an agent) | [The MCP gateway](#the-mcp-gateway) | Change the server URL |
| Your own model calls, in any language | [A client](#clients) | Two calls around your model call |
| A Go service | [The library](#the-go-library) | Two calls, and no gateway to run |

Start a gateway for the examples below. With no provider key it answers from a
free mock model:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/vicoaritonang/guard-rails-engine:latest
```

## The proxy

`POST /v1/chat/completions` and `GET /v1/models` follow the OpenAI API. Point a
client at the gateway and it enforces the policy on every call: prompts are scanned,
personal data is masked before the provider sees it and restored in the answer, and
a refused request comes back as HTTP 422.

**OpenAI SDK, Python**

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="your-gateway-key")
reply = client.chat.completions.create(
    model="gpt-5-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

**OpenAI SDK, JavaScript**

```ts
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "http://localhost:8080/v1", apiKey: "your-gateway-key" });
```

**LangChain**

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-5-mini", base_url="http://localhost:8080/v1", api_key="your-gateway-key")
```

**LlamaIndex**

```python
from llama_index.llms.openai_like import OpenAILike

llm = OpenAILike(model="gpt-5-mini", api_base="http://localhost:8080/v1", api_key="your-gateway-key", is_chat_model=True)
```

**Vercel AI SDK**

```ts
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

const gateway = createOpenAICompatible({
  name: "guardrails",
  baseURL: "http://localhost:8080/v1",
  apiKey: "your-gateway-key",
});
```

The `api_key` here is a gateway key from `GUARDRAILS_API_KEYS`. Your provider key
stays on the gateway, so applications never hold it.

### Handling a refusal

```python
import openai

try:
    reply = client.chat.completions.create(model="gpt-5-mini", messages=messages)
except openai.UnprocessableEntityError as refused:
    print(refused.body["message"])   # safe to show to the user
```

### What the proxy does differently

| Feature | Behaviour |
|---|---|
| `stream: true` | Works, but the answer arrives all at once after the guards finish. The outbound stage judges the whole completion, and streamed tokens cannot be withdrawn. |
| Sampling (`temperature`, `top_p`, ...) | Accepted and not forwarded, because reasoning models reject them. |
| Other unknown parameters | Accepted and not acted on, including `response_format`. Each one is listed in `guardrails.ignored_params`. |
| `tools`, tool turns | Refused with a 400. Forwarding them would let a model use tools outside the control plane. Use the MCP gateway, `/v1/agent/execute`, or check each call with `/v1/guard/runtime`. |
| Images and files | Refused with a 400: the guards read text, and a file would reach the provider unscanned. |
| `n` above 1 | Refused with a 400. |

Every response also carries a `guardrails` object saying what the engine did, with
the findings, redactions, cache result, timing and cost.

### Choosing the upstream

The gateway routes each `model` through `config/models.yaml`, with fallbacks and
circuit breakers. `OPENAI_BASE_URL` points the OpenAI adapter at anything that speaks
the same API, such as Ollama, vLLM, Azure OpenAI or OpenRouter:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e GUARDRAILS_INSECURE_DEV=true \
  -e GUARDRAILS_PROVIDER=openai \
  -e OPENAI_API_KEY=unused \
  -e OPENAI_BASE_URL=http://host.docker.internal:11434/v1 \
  -e GUARDRAILS_DEFAULT_MODEL=llama3.2 \
  ghcr.io/vicoaritonang/guard-rails-engine:latest
```

## The MCP gateway

`POST /mcp` is an MCP server (Streamable HTTP) in front of your MCP servers. It scans
tool definitions for poisoning and pins them by hash, and runs every `tools/call`
through the tool control plane. Results are scanned before the agent sees them.

List your upstream servers in a config file and set `GUARDRAILS_MCP` to its path; see
the comments in `config/mcp.yaml`. Then point a client at the gateway.

**Claude Code**

```bash
claude mcp add --transport http guardrails http://localhost:8080/mcp \
  --header "Authorization: Bearer your-gateway-key"
```

**Cursor and other clients with a JSON config**

```json
{
  "mcpServers": {
    "guardrails": {
      "url": "http://localhost:8080/mcp",
      "headers": { "Authorization": "Bearer your-gateway-key" }
    }
  }
}
```

Upstream servers must speak Streamable HTTP. A stdio server needs a bridge in front of
it.

## Clients

Sidecar mode keeps your provider code as it is. You call the gateway before and after
your model call, and it tells you what to send. This also suits frameworks the proxy
cannot serve, such as agents with tools.

| Language | Install | Docs |
|---|---|---|
| Python | `pip install guard-rails-engine` | [sdks/python](../sdks/python/README.md) |
| JavaScript, TypeScript | `npm install guard-rails-engine` | [sdks/js](../sdks/js/README.md) |
| Go | `go get github.com/VicoAritonang/guard-rails-engine/pkg/sdk` | [pkg/sdk](../pkg/sdk/client.go) |
| Anything else | HTTP | Below |

```bash
curl -X POST localhost:8080/v1/guard/inbound \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Email andi@nusantara.co.id the invoice"}]}'
```

A validate call always returns 200 and the verdict is in the body. Send the returned
`messages` to your provider, then pass the returned `vault_token` to
`/v1/guard/outbound` with the completion to restore the masked values.

For an agent loop, call `/v1/guard/runtime` with the proposed tool calls and
`/v1/guard/tool_result` with what they returned, passing `session` back on each step.

## The Go library

`pkg/guardrails` runs the engine inside your process, with no network hop.

```bash
go get github.com/VicoAritonang/guard-rails-engine/pkg/guardrails
```

```go
g, err := guardrails.New(guardrails.Options{})
if err != nil {
	return err
}

in, err := g.Inbound(ctx, guardrails.Request{
	Messages: []guardrails.Message{{Role: guardrails.RoleUser, Content: prompt}},
})
if errors.Is(err, guardrails.ErrBlocked) {
	return refuse(in.Reason)
}

answer := callYourModel(in.Messages) // the rewritten payload, not your original

out, err := g.Outbound(ctx, guardrails.Request{Completion: answer, Vault: in.Vault})
if errors.Is(err, guardrails.ErrBlocked) {
	return refuse(out.Reason)
}
return out.Completion
```

Pass `Options.Policy` to change the policy: `config.StrictPolicy()`, or
`config.LoadPolicy("policy.yaml")` for your own.

## Deploying

| Target | Start from |
|---|---|
| A single host | [`deploy/compose/docker-compose.yml`](../deploy/compose/docker-compose.yml) |
| Kubernetes | [`deploy/kubernetes/guardrails.yaml`](../deploy/kubernetes/guardrails.yaml) |
| Local development with dashboards | The root [`docker-compose.yml`](../docker-compose.yml) |
| No Docker | Binaries on the [releases page](https://github.com/VicoAritonang/guard-rails-engine/releases), or `go install github.com/VicoAritonang/guard-rails-engine/cmd/server@latest` |

Metrics, traces and logs are standard: Prometheus at `/metrics`, OTLP/HTTP with
`GUARDRAILS_OTLP_ENDPOINT`, and JSON on stdout. See [observability](observability.md).

Read the deployment checklist in [SECURITY.md](../SECURITY.md) before exposing a
gateway to a network.
