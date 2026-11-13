# guard-rails-engine (Python)

Client for a [Guardrails Engine](https://github.com/VicoAritonang/guard-rails-engine)
gateway. It uses the standard library only and needs Python 3.9 or newer.

```bash
pip install guard-rails-engine
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/vicoaritonang/guard-rails-engine:latest
```

## Check a model call

Keep your own provider code and check what goes in and what comes out:

```python
from guard_rails_engine import Client, Blocked

gr = Client("http://localhost:8080", api_key="...")

try:
    inbound = gr.inbound(messages=[{"role": "user", "content": prompt}])

    # Send inbound.messages, the rewritten payload, not your originals.
    answer = call_your_model(inbound.messages)

    # vault_token is what lets the gateway restore the values it masked.
    outbound = gr.outbound(completion=answer, vault_token=inbound.vault_token)
    print(outbound.completion)
except Blocked as refused:
    print("refused:", refused.reason)
```

## Check an agent step

```python
step = gr.runtime(
    tool_calls=[{"name": "send_email", "arguments": {"to": "a@b.co"}}],
    session={"granted": ["mail:send"]},
)
checked = gr.tool_result(
    tool_results=[{"name": "web_fetch", "content": page, "origin": "web"}],
    session=step.session,  # the state travels with the caller, step to step
)
```

`AsyncClient` has the same methods for asyncio code.

## When the gateway is down

`Client` raises `GatewayError` by default, which is right when the guardrail is a
compliance control. `Client(..., fail_open=True)` passes the payload through
unchecked and sets `result.degraded`, so you can log every request that was not
checked.

## No code changes at all

The gateway also speaks the OpenAI API, so any OpenAI client works by changing
its base URL. See the [integration guide](https://github.com/VicoAritonang/guard-rails-engine/blob/main/docs/integrations.md).
