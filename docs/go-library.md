# Using the engine as a Go library

```bash
go get go.vicoworks.com/guard-rails-engine@latest
```

Two packages are public, and you need one of them:

| Package | Use it when | Network |
|---|---|---|
| `go.vicoworks.com/guard-rails-engine/pkg/guardrails` | your program should run the guards itself, in process | none |
| `go.vicoworks.com/guard-rails-engine/pkg/sdk` | a gateway container already runs, and your service calls it | HTTP to the gateway |

Both return the same decisions, because they run the same pipelines. The
library needs Go 1.26 or newer and adds no cgo. Everything under `internal/`
is an implementation detail; the types you need are re-exported from
`pkg/guardrails`. API reference: https://pkg.go.dev/go.vicoworks.com/guard-rails-engine/pkg/guardrails

Versions are git tags (`v0.1.0`, `v0.2.0`, ...). Pin one in `go.mod`; before
v1.0 a minor version may contain breaking changes, and the CHANGELOG lists
them.

## 1. Guard a model call

```go
import "go.vicoworks.com/guard-rails-engine/pkg/guardrails"

g, err := guardrails.New(guardrails.Options{}) // balanced policy
if err != nil {
	return err
}

in, err := g.Inbound(ctx, guardrails.Request{
	System:   systemPrompt,
	Messages: []guardrails.Message{{Role: guardrails.RoleUser, Content: userText}},
})
if errors.Is(err, guardrails.ErrBlocked) {
	return refuse(in.Reason) // safe to show the user
}

// Send in.Messages, the rewritten payload: personal data is replaced by
// placeholders such as [[PII:EMAIL:3f2a91c0]]. Sending your originals
// silently undoes the redaction.
answer := callYourModel(in.System, in.Messages)

out, err := g.Outbound(ctx, guardrails.Request{
	System:     systemPrompt, // lets the leak guard catch a system prompt in the answer
	Completion: answer,
	Vault:      in.Vault,     // restores the placeholders
})
if errors.Is(err, guardrails.ErrBlocked) {
	return refuse(out.Reason)
}
return out.Completion
```

`Result.Decision` holds every finding (`Category`, `SeverityName`, `Score`,
`Spans`) and the timing of every guard, for logs and metrics. An `Engine` is
safe for concurrent use: build one at startup and share it.

## 2. Attachments: documents, images, audio

```go
res, err := g.ScanFile(ctx, "contract.pdf", data) // an upload form
```

or put parts on a message, next to its text:

```go
in, err := g.Inbound(ctx, guardrails.Request{Messages: []guardrails.Message{{
	Role:    guardrails.RoleUser,
	Content: "What does this invoice say?",
	Parts:   []guardrails.Part{{Name: "invoice.png", Data: png}},
}}})
part := in.Messages[0].Parts[0]
part.Extraction.Coverage // full | partial | none: how much the guards read
part.Type                // "text" if a guard redacted it: send part.Text instead of the file
```

PDF, Office, ODF, HTML, SVG, RTF and image metadata are read with no setup.
Pixels and speech need a backend; without one the part is reported as
`media.partial_coverage` or `media.unscannable` and the policy decides:

```go
g, err := guardrails.New(guardrails.Options{Media: guardrails.MediaBackends{
	OCR:         guardrails.NewHTTPOCR("http://ocr:8000/ocr", ""),               // or guardrails.OCRFunc(...)
	Transcriber: guardrails.NewOpenAITranscriber(baseURL, key, "whisper-large-v3-turbo"),
}})
```

Any OCR library fits `guardrails.OCRFunc("name", func(ctx, data, mime) (string, error))`,
and any speech engine fits `guardrails.TranscribeFunc`. Details: [multimodal.md](multimodal.md).

## 3. Retrieved content (RAG, web, email)

Text your system fetched is not the user's, and instructions in it are an
attack. Check it at the tool-result stage before it enters the prompt:

```go
res, err := g.ToolResult(ctx, guardrails.Request{ToolResults: []guardrails.ToolResult{{
	Name: "search_docs", Origin: "web", Content: chunk, // or Parts: []guardrails.Part{...}
}}})
if errors.Is(err, guardrails.ErrBlocked) {
	// drop this chunk
}
safe := res.ToolResults[0].Content
```

`Origin: "web"` applies the stricter prior; use `"tool"` for your own systems
of record.

## 4. Agents and tools

The runtime stage refuses any tool it cannot grade, so describe your tools in
a catalog first:

```yaml
# tools.yaml
version: "1"
extends: builtin        # keep the 29 built-in gradings
tools:
  - name: lookup_order
    reversibility: none          # none | compensable | irreversible
    radius: workspace            # self | workspace | org | external | critical
    capability: orders:read
    exposure: [private]          # it returns customer data: arms the exfiltration checks
    params:
      - { name: order_id, type: string, required: true }
  - name: refund_order
    reversibility: irreversible
    radius: external
    capability: orders:refund
    amount_limit_usd: 200
    params:
      - { name: order_id, type: string, required: true }
      - { name: amount, type: number, required: true, amount: true }
```

The two axes decide the tier, and the tier decides the controls: a read is
allowed once its capability is granted; an irreversible external call needs a
dry run, an idempotency key and a person's approval. `grctl tools --verbose`
prints the matrix.

**When your code executes the tools, use `ExecuteTool`.** It assesses the
call, runs your function only if every control passed, records the effect in
the session (dry runs, spent approvals, idempotency claims, taint), and runs
the tool-result rails on what came back:

```go
g, err := guardrails.New(guardrails.Options{ToolCatalogFile: "tools.yaml"})

exec := guardrails.ToolFuncs{
	PreviewFunc: func(ctx context.Context, c guardrails.ToolCall) (string, error) {
		return fmt.Sprintf("refund %v USD on %v", c.Arguments["amount"], c.Arguments["order_id"]), nil
	},
	ExecuteFunc: func(ctx context.Context, c guardrails.ToolCall) (guardrails.ToolResult, error) {
		return callYourAPI(ctx, c) // the real side effect
	},
}

// One session per conversation; the caller owns it and passes it back.
sess := &guardrails.Session{Granted: []string{"orders:read", "orders:refund"}}

out, err := g.ExecuteTool(ctx, guardrails.ToolRun{
	Call: call, Session: sess, IdempotencyKey: "refund-" + orderID,
}, exec)
sess = out.Session

var refused *guardrails.ToolRefusedError
switch {
case errors.As(err, &refused):
	// What is missing, and how to supply it:
	//   dry_run_required    → call again with DryRun: true, show out.Preview to a person
	//   approval_required   → token, _ := g.Approve(call, "alice@example.com", "reason")
	//                         then call again with ApprovalToken: token
	//   capability_missing  → the session was not granted the tool's capability
	for _, r := range refused.Assessment.Requirements {
		log.Println(r.Control, r.Remedy)
	}
case errors.Is(err, guardrails.ErrBlocked):
	// The tool ran, but its result carried an injection and was withheld.
	// Tell the model the tool failed; do not show it the result.
case err != nil:
	// Your function failed. The call still counts as made: a payment that
	// timed out may have gone through, so a retry with the same
	// IdempotencyKey is answered rather than executed again.
default:
	feedToModel(out.Result.Content)
}
```

Approval tokens are bound to the exact call (tool and arguments), expire
after `tool_safety.params.approval_ttl_seconds`, and are spent on first use.
`Approve` is the step a human performs: put it behind your own admin UI, not
in the agent loop. Tokens verify on any engine built with the same
`Options.Secret`.

If a framework executes the tools for you and you only need a verdict, call
`g.Runtime(ctx, guardrails.Request{ToolCalls: calls, Session: sess})` before
running them. It assesses without recording effects, so dry runs and
approvals do not advance; for those flows use `ExecuteTool`.

## 5. Policy

```go
pol, err := guardrails.LoadPolicy("guardrails.yaml") // layered over the balanced defaults
// or: pol := guardrails.StrictPolicy()
g, err := guardrails.New(guardrails.Options{Policy: pol, Secret: []byte(os.Getenv("GUARDRAILS_SECRET"))})
```

A policy file only needs what it changes:

```yaml
version: "1.0.0-myapp"
name: myapp
guards:
  injection:
    threshold: 0.5
  url_filter_outbound:
    enabled: true
    params: { allow: ["myapp.com"] }
  custom_rules:
    enabled: true
    params:
      rules:
        - { id: competitor, keywords: ["globex"], severity: medium, action: redact }
  media:
    categories:
      media.unscannable: { action: block }
```

`config/policies/balanced.yaml` documents every guard and parameter. Unknown
fields fail at load time, so a typo cannot silently disable a guard.

Set `Secret` (16+ bytes, the same in every process) whenever more than one
process is involved: it keys the PII vault and signs approvals. Without it
each engine generates its own, which is right for a single process.

## 6. The model-based tier

The library runs the deterministic guards: sub-millisecond, no API key, no
network. The semantic tier (Llama Guard 4, Qwen3Guard, gpt-oss-safeguard,
Prompt Guard, ...) and the OpenAI-compatible proxy live in the gateway. To
use them from Go, run the container and call it with `pkg/sdk`:

```go
import "go.vicoworks.com/guard-rails-engine/pkg/sdk"

c, _ := sdk.New("http://guardrails:8080", sdk.WithAPIKey(os.Getenv("GUARDRAILS_API_KEY")))
in, err := c.Inbound(ctx, sdk.Request{Messages: []sdk.Message{{Role: "user", Content: prompt}}})
rep, err := c.ScanFile(ctx, sdk.FileScan{Name: "contract.pdf", Data: data})
```

`sdk.FailOpen(true)` keeps your service answering when the gateway is down;
the default refuses.

## Errors at a glance

| Error | Meaning | Result returned? |
|---|---|---|
| `guardrails.ErrBlocked` (`*BlockedError`) | policy refused the payload | yes, with `Reason` and `Decision` |
| `guardrails.ErrToolRefused` (`*ToolRefusedError`) | a tool call is not allowed yet | yes, `ToolOutcome` with the assessment |
| `guardrails.ErrApprovalsUnavailable` | `tool_safety` is disabled | no |
| anything else | a bug or your executor's error | see the doc comment |
