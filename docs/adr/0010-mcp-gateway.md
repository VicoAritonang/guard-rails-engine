# 10. The gateway is an MCP server in front of MCP servers

Date: 2026-10-06 · Status: accepted

## Context

Agents increasingly reach tools over the Model Context Protocol, and MCP
servers are third parties with two channels into the model: the tool
**definitions** they advertise, which the model reads as instructions, and the
**results** they return, which the model reads as data and often obeys anyway.
Published attacks use both: tool poisoning (hidden instructions in a
description), shadowing (a description that changes how *another* server's
tool is used), rug pulls (a definition that turns malicious after the user
approved it), lying annotations (`readOnlyHint: true` on a payment), and
indirect injection through results (MCPTox, AAAI 2026; MCP-SafetyBench, 2025;
Invariant Labs' tool-poisoning write-ups, 2025).

The engine already had a tool-level control plane (ADR 0006). The question was
where MCP fits.

## Decision

The gateway is an MCP server to the agent (Streamable HTTP at `POST /mcp`) and
an MCP client to each configured upstream (`config/mcp.yaml`). It enforces at
three points, all on the existing broker:

1. **Discovery.** Every definition (description *and* every string in the
   input schema) is scanned for hidden instruction blocks, credential paths,
   secrecy directives, behavioural directives, invisible characters, and
   references to other visible tools (shadowing); the tool-result rails run
   over it too, because a description is attacker-authored text the model
   reads. Clean definitions are pinned by SHA-256. A definition that later
   changes is quarantined as a rug pull until an operator re-pins it
   (`POST /v1/mcp/repin`). Pinning is trust-on-first-use; a deployment that
   needs more pins hashes in config.
2. **Invocation.** Every `tools/call` goes through argument policy (SSRF,
   destructive shell, path traversal) and then `agent.Broker`: schema,
   capability, tier ceiling, egress allowlist, taint, lethal trifecta,
   dry run, single-use call-bound approval. All of this runs before anything is forwarded.
   Upstream tools are graded by the operator in `mcp.yaml`; unreviewed tools
   get `default_grade`, and **annotations can only raise risk, never lower
   it**. A server claiming `readOnlyHint` on a tool graded irreversible is
   recorded as an annotation mismatch.
3. **Results.** What comes back passes the tool-result rails before the agent
   sees it; results from an `untrusted` server mark the session as having
   ingested attacker-authorable content, which arms taint and the trifecta for
   every later call.

A refusal is an MCP tool result with `isError: true` and the exact unmet
requirement, not a JSON-RPC error: the model can read it and tell the user,
which it cannot do with a protocol fault.

### The gateway's own agent uses the same path

`POST /v1/agent/run` drives a function-calling model (OpenAI or Groq) against
the same tools through `Gateway.Call`. A run that needs a human stops with
`awaiting_approval` and returns its transcript; after `/v1/agent/approve`, the
caller posts the transcript back with the token and the run resumes. The
gateway keeps no conversation.

### Placeholders are restored at the execution boundary, and only there

The task is masked by the inbound stage with the session's vault, so the model
handles `[[PII:IBAN:…]]`, never the IBAN. Found during live testing: the model
then passes the placeholder as a tool argument, and without restoration the
payment server would have received a placeholder. Arguments are now restored
from the session vault **after** every control has passed and immediately
before the executor runs; the approval signature binds to the HMAC
placeholder, which is unique to the value. Values the vault knows are masked
again in the tool result before it returns to the model.

### MCP sessions are state the gateway holds

MCP is a stateful protocol, so sessions (agent state + vault) live in the
gateway, bounded and expiring after an hour idle. This is the one exception to
stateless execution, and it is confined to `/mcp` and `/v1/agent/run`.

## Consequences

- Any MCP client (Claude Desktop, Cursor, an SDK agent) can point at `/mcp`
  and get the full control plane without code changes.
- The scanner is lexical. A poisoned description written to avoid every
  pattern passes discovery; the broker and the result rails are the backstop,
  which is why all three layers exist.
- `grctl mcp-demo` ships a hostile server so every defence is demonstrated and
  tested (`internal/mcp/gateway_test.go`).
