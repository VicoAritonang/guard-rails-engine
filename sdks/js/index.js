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

  /**
   * Upload a file to /v1/guard/media. `data` is a Blob, File, ArrayBuffer or
   * Uint8Array. Use stage "tool_result" for retrieved content (RAG, web,
   * email), which applies the indirect-injection prior.
   */
  async scanFile(data, { name = "upload.bin", mime, stage = "inbound", text, origin, tool, tenant } = {}) {
    const form = new FormData();
    const blob = data instanceof Blob ? data : new Blob([data], mime ? { type: mime } : {});
    form.append("file", blob, name);
    for (const [k, v] of Object.entries({ stage, text, origin, tool, tenant })) {
      if (v) form.append(k, v);
    }
    const reply = await this.#request("POST", "/v1/guard/media", form);
    const result = toResult(reply);
    if (result.blocked) throw new Blocked(result.reason, result);
    return result;
  }

  /** What this gateway can read: formats, OCR, speech-to-text, image classifiers. */
  mediaInfo() {
    return this.#request("GET", "/v1/media");
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
    const result = toResult(data);
    if (result.blocked) throw new Blocked(result.reason, result);
    return result;
  }

  async #request(method, path, body) {
    const headers = { Accept: "application/json" };
    const isForm = typeof FormData !== "undefined" && body instanceof FormData;
    // FormData sets its own multipart boundary header.
    if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;

    let response;
    try {
      response = await this.fetch(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
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

/**
 * Build a message part from bytes. The gateway identifies the format from the
 * bytes; `mime` is a hint.
 */
export function attachment(data, { name, mime } = {}) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  const part = { data: btoa(binary) };
  if (name) part.name = name;
  if (mime) part.mime = mime;
  return part;
}

function toResult(data) {
  const messages = data.messages ?? [];
  const toolResults = data.tool_results ?? [];
  const extractions = [];
  for (const item of [...messages, ...toolResults]) {
    for (const part of item.parts ?? []) {
      if (part.extraction) extractions.push({ name: part.name ?? "", type: part.type ?? "", ...part.extraction });
    }
  }
  return {
    decision: data.decision ?? {},
    blocked: Boolean(data.blocked),
    reason: data.reason ?? "",
    system: data.system ?? "",
    messages,
    completion: data.completion ?? "",
    toolResults,
    vaultToken: data.vault_token ?? "",
    session: data.session,
    semantic: data.semantic,
    extractions,
    degraded: false,
  };
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
