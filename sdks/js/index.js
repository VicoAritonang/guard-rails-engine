// Client for a Guardrails Engine gateway. It runs on anything with fetch
// (Node 18+, Bun, Deno, edge runtimes) and has no dependencies.
//
// Call it from your backend. An API key in browser code is a published key, and
// the gateway refuses cross-origin browser requests anyway.

/** The gateway could not be reached, or refused the request itself. */
export class GatewayError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "GatewayError";
    this.status = status;
  }
}

/** Policy refused the payload. `reason` is safe to show to a user. */
export class Blocked extends Error {
  constructor(reason, result) {
    super(`blocked by policy: ${reason}`);
    this.name = "Blocked";
    this.reason = reason;
    this.result = result;
  }
}

export class Client {
  constructor(baseUrl = "http://localhost:8080", { apiKey, timeoutMs = 10000, failOpen = false, fetch: fetchImpl } = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.failOpen = failOpen;
    this.fetch = fetchImpl ?? globalThis.fetch;
  }

  /** Check a prompt before it reaches a provider. */
  inbound(request) {
    return this.#guard("inbound", request);
  }

  /** Check proposed tool calls inside an agent loop. */
  runtime(request) {
    return this.#guard("runtime", request);
  }

  /** Check what a tool returned, before the model reads it. */
  toolResult(request) {
    return this.#guard("tool_result", request);
  }

  /** Check a completion before it reaches the user. */
  outbound(request) {
    return this.#guard("outbound", request);
  }

  /** Report whether the gateway is serving. */
  async health() {
    try {
      await this.#request("GET", "/healthz");
      return true;
    } catch (err) {
      if (err instanceof GatewayError) return false;
      throw err;
    }
  }

  async #guard(stage, request) {
    let data;
    try {
      data = await this.#request("POST", `/v1/guard/${stage}`, wire(request));
    } catch (err) {
      const unreachable = err instanceof GatewayError && (err.status === undefined || err.status >= 500);
      if (this.failOpen && unreachable) return passthrough(stage, request);
      throw err;
    }
    const result = {
      decision: data.decision ?? {},
      blocked: Boolean(data.blocked),
      reason: data.reason ?? "",
      system: data.system ?? "",
      messages: data.messages ?? [],
      completion: data.completion ?? "",
      toolResults: data.tool_results ?? [],
      vaultToken: data.vault_token ?? "",
      session: data.session,
      degraded: false,
    };
    if (result.blocked) throw new Blocked(result.reason, result);
    return result;
  }

  async #request(method, path, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;

    let response;
    try {
      response = await this.fetch(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new GatewayError(`gateway unreachable: ${err.message}`);
    }
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 300);
      throw new GatewayError(`gateway returned ${response.status}: ${detail}`, response.status);
    }
    return response.json();
  }
}

// wire translates the camelCase request into the gateway's field names.
function wire({ toolCalls, toolResults, vaultToken, costUsd, ...rest }) {
  const body = { ...rest };
  if (toolCalls !== undefined) body.tool_calls = toolCalls;
  if (toolResults !== undefined) body.tool_results = toolResults;
  if (vaultToken !== undefined) body.vault_token = vaultToken;
  if (costUsd !== undefined) body.cost_usd = costUsd;
  return body;
}

function passthrough(stage, request) {
  return {
    decision: { stage, action: "allow", degraded: true },
    blocked: false,
    reason: "",
    system: request.system ?? "",
    messages: request.messages ?? [],
    completion: request.completion ?? "",
    toolResults: request.toolResults ?? [],
    vaultToken: request.vaultToken ?? "",
    session: request.session,
    degraded: true,
  };
}
