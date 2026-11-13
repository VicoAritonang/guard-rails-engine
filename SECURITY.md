# Security policy

## Reporting a vulnerability

Please report privately, through
[GitHub private vulnerability reporting](https://github.com/VicoAritonang/guard-rails-engine/security/advisories/new).
Do not open a public issue for a vulnerability.

Include what you did, what happened, and the version or commit. You should get a
first response within a week. Once a fix ships, you will be credited in the
advisory unless you ask not to be.

**A detection miss is usually not a vulnerability.** A prompt that gets past the
injection rules, or a clean prompt that gets flagged, is expected of any
heuristic and belongs in a public
[detection report](https://github.com/VicoAritonang/guard-rails-engine/issues/new?template=detection_report.yml),
where it can become a test case. Report it privately if it bypasses a control
that should be deterministic: authentication, an approval, the egress allowlist,
the tool tiers, redaction of a value the guard recognised, or the audit trail.

## Supported versions

Only the latest release receives fixes. Before 1.0, a minor version may include
breaking changes, listed in the [changelog](CHANGELOG.md).

## Deploying safely

The gateway refuses to start on a network address while holding provider
credentials with no API keys, or while using a secret published in this
repository. Beyond that, a production deployment should:

- Set `GUARDRAILS_SECRET` to the output of `openssl rand -hex 32`. It signs
  approvals and encrypts vault tokens, so anyone who has it can forge both.
- Set `GUARDRAILS_API_KEYS`, and set `GUARDRAILS_ADMIN_KEYS` to different keys.
  Without admin keys, any API key can approve a tool call, including the key held
  by the agent making the call.
- Terminate TLS in front of the gateway. It serves plain HTTP.
- Keep `/metrics` on an internal network. It is unauthenticated, and it reveals
  tenant names when `GUARDRAILS_TENANT_METRICS` is on.
- Set `GUARDRAILS_DASHBOARD=false` unless people need the pages.
- Leave `GUARDRAILS_EXPERIMENTS_RUN` off. Those runs spend provider quota.
- Treat the root `docker-compose.yml` as a development stack. It has no
  authentication and relies on publishing every port on loopback only. Use
  `deploy/compose/docker-compose.yml` or `deploy/kubernetes/guardrails.yaml`.

## What the engine trusts

These are design boundaries rather than bugs, and they decide where it is safe to
put the gateway.

- **The caller of `/v1/guard/*` and `/v1/agent/*` is trusted.** The agent session,
  including its granted capabilities and taint ledger, travels in the request. A
  caller can claim capabilities or omit its history, so the tool controls protect
  against a manipulated *model*, not a malicious *caller*. Put these routes behind
  your agent runtime, never directly in front of end users. The MCP gateway keeps
  sessions on the server and does not have this limit.
- **`tenant` is a label, not an identity.** It comes from the request body and is
  not tied to the API key, so one key can claim any tenant, which reaches the
  cache partitions and the per-tenant metrics. Use a separate deployment where
  tenants do not trust each other, and leave `GUARDRAILS_TENANT_METRICS` off when
  tenant values are not under your control.
- **Single use for an approval is per replica.** A spent grant is remembered in
  the session and in the memory of the replica that used it. A caller that drops
  the session and reaches another replica can replay a grant until it expires, 10
  minutes by default.
- **Rate limits are per replica.** Set global limits at your ingress.
- **Egress checks read the address, not DNS.** A public hostname that resolves to
  a private address passes `HostScope`. The executor that makes the request has to
  enforce this at connection time.
- **Cross-origin browser requests are refused, DNS rebinding is not.** A local
  gateway with no API keys can be reached by a page that rebinds its own hostname
  to 127.0.0.1. Set API keys if that matters on your machine.
- **Guards read text.** The proxy refuses images and files rather than forwarding
  them unscanned. Text inside an image sent directly to a provider never reaches
  this engine at all.

Detection quality and its known gaps are measured, not promised: see
[Honest limitations](README.md#honest-limitations).
