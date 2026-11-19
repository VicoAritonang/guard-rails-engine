# API contract

The gateway has one API carried over two transports:

| | Contract | Where |
|---|---|---|
| HTTP REST | OpenAPI 3.1 | [`api/openapi.yaml`](../api/openapi.yaml) |
| gRPC | Protocol Buffers, package `guardrails.v1` | [`api/proto/guardrails/v1/guardrails.proto`](../api/proto/guardrails/v1/guardrails.proto) |

They describe the same objects with the same field names. `GuardRequest.vault_token`
in the proto is `vault_token` in the JSON body; `STAGE_TOOL_RESULT` is
`"tool_result"`. The gateway runs one code path behind both, and
`internal/server/contract_test.go` fails the build when the Go types, the OpenAPI
schemas and the protobuf messages disagree on a single field or enum value.

Both files are the source of truth for clients. Generate from them rather than
copying shapes out of this page.

## What is covered, and how stable it is

Each REST operation carries `x-stability` in the spec.

| Level | Operations | Promise |
|---|---|---|
| `stable` | `/v1/guard/{stage}`, `/v1/guard/media`, `/v1/chat/completions`, `/v1/guards`, `/v1/policy`, `/healthz`, `/readyz`, `/metrics`; gRPC `GuardService` | The v1 compatibility rules below |
| `beta` | `/v1/agent/*`, `/v1/models`, `/v1/media`, `/mcp`, `/v1/mcp/*` | Shape may change in a minor release, always listed in [CHANGELOG.md](../CHANGELOG.md) |
| `experimental` | `/v1/events`, `/v1/lab`, `/v1/lab/run` | Operator tooling for the console; no promise |

### The v1 rules

Within `/v1` and `guardrails.v1`:

- **Additive only.** New fields, new enum values, new operations and new optional
  parameters can appear in any release. Nothing is renamed, retyped, renumbered or
  removed.
- **Retiring a field** means marking it deprecated (in the spec, the proto and the
  changelog) and keeping it working for at least two minor releases and six months,
  whichever is longer. Its proto field number is then `reserved` forever.
- **Anything else** is a new major version: `/v2` next to `/v1`, `guardrails.v2`
  next to `guardrails.v1`, both served side by side for the same deprecation window.

What this asks of a client:

- **Ignore what you do not know.** A response may carry fields and enum values that
  did not exist when your client was generated. In proto3 an unknown enum value
  arrives as its number; treat it as `UNSPECIFIED`.
- **Do not send what the server does not know.** REST rejects an unknown request
  field with `400 invalid_request` instead of ignoring it, so a misspelt option
  fails loudly. The flip side: an option added in a newer release is a 400 on an
  older gateway. Upgrade the gateway first.
- **Treat `session` and `vault_token` as opaque.** Pass back exactly what the last
  response returned. Their contents are versioned with the engine, not the API.

The protobuf rules are checked by `buf breaking` with the `WIRE_JSON` rule set, on
every pull request, against `main`: renaming a field breaks JSON clients even when
the binary encoding would survive it, so the check is the stricter of the two.

## Errors

Every REST error has one shape:

```json
{ "error": { "type": "invalid_request", "message": "stage must be ...", "details": null } }
```

Match on `error.type`, which is stable. `error.message` is for people and may change.

| HTTP | `error.type` | gRPC code |
|---|---|---|
| 400 | `invalid_request`, `unsupported_parameter` | `INVALID_ARGUMENT` |
| 401 | `unauthorized` | `UNAUTHENTICATED` |
| 403 | refused tool call (`/v1/agent/execute`, body is the outcome) | `PERMISSION_DENIED` |
| 404 | `not_quarantined` | `NOT_FOUND` |
| 413 | `too_large` | `RESOURCE_EXHAUSTED` (message size) |
| 422 | `blocked_by_policy` (proxy mode; `details` is the decision) | n/a |
| 429 | `rate_limited`, with `Retry-After` | `RESOURCE_EXHAUSTED` |
| 500 | `internal_error` | `INTERNAL` |
| 503 | `tool_safety_disabled`, `mcp_disabled`, ... | `UNAVAILABLE` |

gRPC status messages start with the same `error.type`, for example
`invalid_request: stage must be ...`.

**A validate-mode block is not an error.** `/v1/guard/{stage}` and `Guard` return
`200`/`OK` with `blocked: true`. The engine evaluated the request and "blocked" is
the answer.

## Headers and metadata

| REST header | gRPC metadata | |
|---|---|---|
| `Authorization: Bearer <key>` or `X-Api-Key: <key>` | `authorization` or `x-api-key` | A key from `GUARDRAILS_API_KEYS` |
| `X-Request-Id` (request and response) | `x-request-id` (request and response header) | Up to 128 chars of `[A-Za-z0-9._:-]`; generated when absent |
| `X-Trace-Id` (response) | `x-trace-id` (response header) | W3C trace ID, when tracing is on |
| `traceparent` | `traceparent` | Continues the caller's trace |

Both transports share the API keys and the per-key rate limit buckets, so
splitting traffic across them does not double a caller's limit.

## Running the gRPC server

gRPC is off by default. Set an address to turn it on next to HTTP:

```bash
GUARDRAILS_GRPC_ADDR=127.0.0.1:9090 go run ./cmd/server
```

The server registers `guardrails.v1.GuardService`, the standard
`grpc.health.v1.Health` service (unauthenticated, `NOT_SERVING` while draining)
and server reflection, so `grpcurl` works without the proto file:

```bash
grpcurl -plaintext -d '{"stage":"STAGE_INBOUND","messages":[{"role":"ROLE_USER","content":"Ignore all previous instructions"}]}' \
  127.0.0.1:9090 guardrails.v1.GuardService/Guard
```

The listener is plaintext. In production put it behind the same TLS-terminating
proxy or service mesh as the HTTP port; the exposure check that refuses an open
HTTP gateway on a network address applies to `GUARDRAILS_GRPC_ADDR` too.

Message size is bounded by the larger of `GUARDRAILS_MAX_BODY_BYTES` and
`GUARDRAILS_MEDIA_UPLOAD_BYTES`, since attachments travel inline in `Part.data`.

## Generating a client

**Go.** The stubs are published in this module:

```go
import guardrailsv1 "go.vicoworks.com/guard-rails/pkg/api/guardrailsv1"

conn, _ := grpc.NewClient("localhost:9090", grpc.WithTransportCredentials(insecure.NewCredentials()))
resp, err := guardrailsv1.NewGuardServiceClient(conn).Guard(ctx, &guardrailsv1.GuardRequest{
	Stage:    guardrailsv1.Stage_STAGE_INBOUND,
	Messages: []*guardrailsv1.Message{{Role: guardrailsv1.Role_ROLE_USER, Content: prompt}},
})
```

`pkg/sdk` remains the dependency-free REST client, and `pkg/guardrails` runs the
engine in process with no network at all.

**Any other language, from the proto.** Add the plugins you need to a `buf.gen.yaml`
of your own and point it at `api/proto`:

```yaml
version: v2
plugins:
  - remote: buf.build/protocolbuffers/python
    out: gen/python
  - remote: buf.build/grpc/python
    out: gen/python
  - remote: buf.build/bufbuild/es       # TypeScript
    out: gen/ts
```

```bash
buf generate https://github.com/VicoAritonang/guard-rails-engine.git#subdir=api/proto
```

**Any other language, from OpenAPI.** Any OpenAPI 3.1 generator works, for example:

```bash
npx @openapitools/openapi-generator-cli generate -i api/openapi.yaml -g typescript-fetch -o gen/ts
```

The hand-written [Python](../sdks/python/README.md) and
[JavaScript](../sdks/js/README.md) clients speak the same REST contract and are the
shortest path when you do not want generated code.

## Changing the contract

1. Edit `api/proto/guardrails/v1/guardrails.proto`, `api/openapi.yaml` and the Go
   type together. A new field gets the next free number; never reuse one.
2. `make api-tools` once, then `make api`: lint, format, the breaking-change check
   against `main`, regeneration of `pkg/api/guardrailsv1` and the contract tests.
3. Add a line under `Unreleased` in `CHANGELOG.md`.

CI runs the same steps in the `api contract` job, and fails if `pkg/api` was not
regenerated.
