/** How much of an attachment the guards actually read. */
export interface Extraction {
  methods?: string[];
  coverage: "full" | "partial" | "none";
  bytes?: number;
  chars?: number;
  pages?: number;
  width?: number;
  height?: number;
  seconds?: number;
  truncated?: boolean;
  duration_ms: number;
  findings?: Finding[];
  warnings?: string[];
  /** native | text | dropped: what went upstream. */
  forwarded?: string;
}

/** An attachment: image, document, audio or video. */
export interface Part {
  type?: "text" | "image" | "audio" | "video" | "document";
  mime?: string;
  name?: string;
  /** Base64 bytes. */
  data?: string;
  /** A data: URI, or a remote URL when the gateway allows fetching. */
  url?: string;
  format?: string;
  /** The extracted (and possibly redacted) text, set by the gateway. */
  text?: string;
  extraction?: Extraction;
}

export interface Message {
  role: "system" | "user" | "assistant" | "tool" | (string & {});
  content: string;
  name?: string;
  parts?: Part[];
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
  parts?: Part[];
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
  /** The semantic-tier outcome, when model classifiers ran on this stage. */
  semantic?: Record<string, unknown>;
  /** The ingest report of every attachment. */
  extractions?: Array<Extraction & { name: string; type: string }>;
}

export interface ScanFileOptions {
  name?: string;
  mime?: string;
  /** inbound (default) or tool_result for retrieved content. */
  stage?: "inbound" | "tool_result";
  text?: string;
  origin?: "tool" | "web";
  tool?: string;
  tenant?: string;
}

export function attachment(data: ArrayBuffer | Uint8Array, options?: { name?: string; mime?: string }): Part;

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
  scanFile(data: Blob | ArrayBuffer | Uint8Array, options?: ScanFileOptions): Promise<GuardResult>;
  mediaInfo(): Promise<Record<string, unknown>>;
  health(): Promise<boolean>;
}
