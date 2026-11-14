# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a minor
version may contain breaking changes.

## Unreleased

First public distribution.

### Breaking

- The Go module path is now `go.vicoworks.com/guard-rails-engine`, a vanity import
  path served by a Cloudflare Worker (`deploy/cloudflare/go-vanity`) that points the
  Go toolchain at the GitHub repository. Imports of `github.com/VicoAritonang/...`
  must be rewritten; the source, issues, CI and images stay on GitHub.
- Go 1.26 is the minimum version, required by the patched `golang.org/x/net`.
- `GUARDRAILS_ADDR` defaults to `127.0.0.1:8080`. The Docker image still sets `:8080`.
- The gateway refuses to start on a network address with provider credentials and
  no `GUARDRAILS_API_KEYS`, or with a secret published in this repository. Set
  `GUARDRAILS_INSECURE_DEV=true` for a container published on loopback only.
- With API keys set, `/events`, `/playground` and `/showcase/experiments/` now
  require a key. The pages stay open and fall back to their labelled simulation.
- The development compose stack publishes every port on loopback only, gives
  anonymous Grafana visitors the Viewer role instead of Admin, no longer ships a
  default `GUARDRAILS_SECRET`, and leaves `GUARDRAILS_EXPERIMENTS_RUN` off.
- `tools`, tool turns, `file_id` references, unknown content parts and `n > 1` on
  `/v1/chat/completions` now return 400 with a clear message. Image, audio and
  inline file parts are scanned and accepted.

### Added

- Multimodal ingest (`internal/media`): PDF, DOCX/XLSX/PPTX, ODF, HTML, SVG, RTF,
  ZIP listings, image metadata, OCR (vision route or HTTP sidecar), speech-to-text
  (OpenAI, Groq, local Whisper) and image safety (Llama Guard 4, omni-moderation).
  New guards `media` and `media_result`; `POST /v1/guard/media` (multipart) and
  `GET /v1/media`. Image, audio and file content parts are now accepted on
  `/v1/chat/completions` and MCP image/audio/resource blocks are scanned.
- Guard-model classifiers: Llama Guard 3/4, Qwen3Guard, Granite Guardian, Nemotron
  safety, and `tei:` self-hosted sequence classifiers; `local` provider for vLLM/Ollama.
- Tool-call alignment judging on the runtime stage; semantic tier on `/v1/guard/*`.
- `custom_rules*` (keyword/regex rules in policy) and `url_filter*` guards.
- Helm chart (`deploy/helm`) and a local-models compose overlay.
- `pkg/guardrails`: `ExecuteTool` runs the application's own tools under the
  tool control plane and records their effects (dry runs, approvals, idempotency,
  taint); `Approve` mints single-use approvals; `Request.ApprovalToken`,
  `IdempotencyKey`, `DryRun`; `Options.ToolCatalogFile`; `ScanFile`;
  `DefaultPolicy`, `StrictPolicy`, `LoadPolicy`; pluggable OCR and speech backends.
- `deploy/cloudflare/go-vanity`: the Worker serving the `go.vicoworks.com` import path.
- `docs/go-library.md`: the guide to importing the engine from another Go project.
- `pkg/guardrails`: a public Go library that runs the engine in process.
- Python (`guard-rails-engine`) and JavaScript (`guard-rails-engine`) clients.
- OpenAI compatibility on `/v1/chat/completions` and `/v1/models`: the `choices`
  response, `stream`, content parts, `max_completion_tokens`, system turns, and
  `guardrails.ignored_params` for settings the gateway did not act on.
- `vault_token` on `/v1/guard/*`, so a sidecar can restore masked values across two
  stateless calls. `session` now comes back from those routes too.
- `GUARDRAILS_ADMIN_KEYS`, separating who can approve a tool call from who can make
  one.
- `headers` on MCP upstream servers, with `${ENV_VAR}` expansion.
- `GUARDRAILS_OTLP_INSECURE`, for trace backends over TLS.
- Multi-architecture images, signed, with an SBOM and provenance; release binaries
  for Linux, macOS and Windows; `grctl healthcheck` and an image `HEALTHCHECK`.
- `deploy/compose` and `deploy/kubernetes`.
- LICENSE, SECURITY, CONTRIBUTING, a code of conduct and issue templates.

### Fixed

- `golang.org/x/net` updated to clear 4 reachable vulnerabilities, and the toolchain
  moved off Go 1.25, which no longer receives security patches.
- Addresses such as `127.1`, `2130706433` and `0x7f.0.0.1` were classified as public,
  bypassing the private-network check. `0.0.0.0/8` and `100.64.0.0/10` are now private.
- URLs with schemes other than HTTP skipped the egress host checks.
- A spent approval could be replayed by dropping the session; replicas now remember
  spent grants.
- Cross-site browser requests could reach a local gateway. They are now refused.
- The rate limit could be reset by sending a new `X-Api-Key` when auth was off, and
  `/playground` had no rate or body limit.
- `.callcache` was readable through `/showcase/experiments/`, and reports were served
  with the API's origin. Dot paths are now hidden and reports are sandboxed.
- An upstream 401 or 403 was passed to the caller, who would read it as their own key
  being wrong. It is now a 502.
- Event streams are capped, and `X-Request-Id` is validated before it is logged.
- The MCP client no longer follows redirects from upstream servers.
- The Go SDK applies `FailOpen` to a 5xx, as it does to a refused connection.
- `docs/` was gitignored, so README links were dead and CI could not find
  `docs/tool-matrix.md`.
