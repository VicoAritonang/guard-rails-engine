# guard-rails-engine (JavaScript and TypeScript)

Client for a [Guardrails Engine](https://github.com/VicoAritonang/guard-rails-engine)
gateway. It has no dependencies, ships its own types, and runs anywhere with
`fetch`: Node 18+, Bun, Deno and edge runtimes.

```bash
npm install guard-rails-engine
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/vicoaritonang/guard-rails-engine:latest
```

## Check a model call

```ts
import { Client, Blocked } from "guard-rails-engine";

const gr = new Client("http://localhost:8080", { apiKey: process.env.GUARDRAILS_KEY });

try {
  const inbound = await gr.inbound({ messages: [{ role: "user", content: prompt }] });

  // Send inbound.messages, the rewritten payload, not your originals.
  const answer = await callYourModel(inbound.messages);

  // vaultToken is what lets the gateway restore the values it masked.
  const outbound = await gr.outbound({ completion: answer, vaultToken: inbound.vaultToken });
  console.log(outbound.completion);
} catch (err) {
  if (err instanceof Blocked) console.log("refused:", err.reason);
  else throw err;
}
```

## Check an agent step

```ts
const step = await gr.runtime({
  toolCalls: [{ name: "send_email", arguments: { to: "a@b.co" } }],
  session: { granted: ["mail:send"] },
});
await gr.toolResult({
  toolResults: [{ name: "web_fetch", content: page, origin: "web" }],
  session: step.session, // the state travels with the caller, step to step
});
```

## When the gateway is down

The client throws `GatewayError` by default, which is right when the guardrail is
a compliance control. `new Client(url, { failOpen: true })` passes the payload
through unchecked and sets `result.degraded`, so you can log every request that
was not checked.

Call it from your backend, never from browser code: an API key in a browser is a
published key.

## No code changes at all

The gateway also speaks the OpenAI API, so any OpenAI client works by changing
its base URL. See the [integration guide](https://github.com/VicoAritonang/guard-rails-engine/blob/main/docs/integrations.md).
