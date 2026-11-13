export interface Message {
  role: "system" | "user" | "assistant" | "tool" | (string & {});
  content: string;
  name?: string;
}

export interface ToolCall {
  id?: string;
  name: string;
  arguments?: Record<string, unknown>;
  raw?: string;
}

export interface ToolResult {
  call_id?: string;
  name: string;
  content: string;
  error?: string;
  /** Who could have written the content, such as "web" for a fetch tool. */
  origin?: string;
}

export interface GuardRequest {
  tenant?: string;
  model?: string;
  system?: string;
  messages?: Message[];
  completion?: string;
  /** Retrieved documents the groundedness guard compares the answer against. */
  context?: string[];
  toolCalls?: ToolCall[];
  history?: ToolCall[];
  toolResults?: ToolResult[];
  step?: number;
  costUsd?: number;
  /** The agent's state, passed back unchanged on each step. */
  session?: unknown;
  /** The token from the inbound result. Outbound needs it to restore masked values. */
  vaultToken?: string;
  meta?: Record<string, unknown>;
}

export interface Finding {
  guard: string;
  rule: string;
  category: string;
  severity: string;
  score: number;
  message: string;
  [key: string]: unknown;
}

export interface Decision {
  transaction_id?: string;
  stage?: string;
  action?: "allow" | "flag" | "redact" | "block" | (string & {});
  findings?: Finding[];
  degraded?: boolean;
  [key: string]: unknown;
}

export interface GuardResult {
  decision: Decision;
  blocked: boolean;
  reason: string;
  system: string;
  /** The rewritten payload. Send this onward, not your originals. */
  messages: Message[];
  completion: string;
  toolResults: ToolResult[];
  vaultToken: string;
  /** The agent state as this stage left it. Pass it back on the next step. */
  session?: unknown;
  /** True when failOpen passed the payload through unchecked. */
  degraded: boolean;
}

export interface ClientOptions {
  apiKey?: string;
  timeoutMs?: number;
  /** Pass the payload through unchecked when the gateway is unreachable. */
  failOpen?: boolean;
  fetch?: typeof globalThis.fetch;
}

export class GatewayError extends Error {
  status?: number;
  constructor(message: string, status?: number);
}

export class Blocked extends Error {
  reason: string;
  result: GuardResult;
  constructor(reason: string, result: GuardResult);
}

export class Client {
  constructor(baseUrl?: string, options?: ClientOptions);
  inbound(request: GuardRequest): Promise<GuardResult>;
  runtime(request: GuardRequest): Promise<GuardResult>;
  toolResult(request: GuardRequest): Promise<GuardResult>;
  outbound(request: GuardRequest): Promise<GuardResult>;
  health(): Promise<boolean>;
}
