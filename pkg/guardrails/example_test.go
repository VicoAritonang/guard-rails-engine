package guardrails_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"go.vicoworks.com/guard-rails-engine/pkg/guardrails"
)

// These examples render on pkg.go.dev. They have no Output comments, so go
// test compiles them without running them: their job is to keep the
// documented API building.

// A policy from a YAML file, or a built-in profile changed in Go.
func ExampleNew_policy() {
	pol, err := guardrails.LoadPolicy("guardrails.yaml") // layered over the balanced defaults
	if err != nil {
		pol = guardrails.StrictPolicy()
	}
	g, err := guardrails.New(guardrails.Options{
		Policy: pol,
		// Share the secret across replicas so vault placeholders and
		// approvals survive a request landing on another process.
		Secret: []byte(os.Getenv("GUARDRAILS_SECRET")),
	})
	if err != nil {
		panic(err)
	}
	_ = g
}

// Check an upload before indexing or forwarding it.
func ExampleEngine_ScanFile() {
	g, _ := guardrails.New(guardrails.Options{})
	data, _ := os.ReadFile("contract.pdf")

	res, err := g.ScanFile(context.Background(), "contract.pdf", data)
	if errors.Is(err, guardrails.ErrBlocked) {
		fmt.Println("refused:", res.Reason)
		return
	}
	part := res.Messages[0].Parts[0]
	fmt.Println("coverage:", part.Extraction.Coverage) // full | partial | none
	fmt.Println("text the guards read:", len(part.Text), "chars")
}

// Retrieved content (RAG, web pages, email) goes through the tool-result
// stage, which treats instructions addressed to the model as an attack.
func ExampleEngine_ToolResult() {
	g, _ := guardrails.New(guardrails.Options{})
	page := "<html>…fetched page…</html>"

	res, err := g.ToolResult(context.Background(), guardrails.Request{ToolResults: []guardrails.ToolResult{{
		Name: "fetch_page", Origin: "web", Content: page,
	}}})
	if errors.Is(err, guardrails.ErrBlocked) {
		fmt.Println("withheld from the model:", res.Reason)
		return
	}
	fmt.Println(res.ToolResults[0].Content) // possibly truncated or redacted
}

// Run your own tools under the tool control plane: capabilities, taint,
// dry runs, human approval, idempotency, and rails on what comes back.
func ExampleEngine_ExecuteTool() {
	ctx := context.Background()
	g, err := guardrails.New(guardrails.Options{ToolCatalogFile: "tools.yaml"})
	if err != nil {
		panic(err)
	}
	exec := guardrails.ToolFuncs{
		PreviewFunc: func(_ context.Context, c guardrails.ToolCall) (string, error) {
			return fmt.Sprintf("refund %v USD on order %v", c.Arguments["amount"], c.Arguments["order_id"]), nil
		},
		ExecuteFunc: func(_ context.Context, c guardrails.ToolCall) (guardrails.ToolResult, error) {
			return guardrails.ToolResult{Content: "refund issued"}, nil // your real side effect
		},
	}
	call := guardrails.ToolCall{Name: "refund_order", Arguments: map[string]any{"order_id": "A-1", "amount": 50.0}}
	run := guardrails.ToolRun{Call: call, IdempotencyKey: "refund-A-1",
		Session: &guardrails.Session{Granted: []string{"orders:refund"}}}

	// 1. Dry run: show the person what will happen.
	run.DryRun = true
	out, _ := g.ExecuteTool(ctx, run, exec)
	fmt.Println("needs approval:", out.Preview)

	// 2. A person approves this exact call.
	token, _ := g.Approve(call, "ops@example.com", "customer ticket 991")

	// 3. Execute, carrying the session forward.
	run.DryRun, run.Session, run.ApprovalToken = false, out.Session, token
	out, err = g.ExecuteTool(ctx, run, exec)
	var refused *guardrails.ToolRefusedError
	switch {
	case errors.As(err, &refused):
		for _, r := range refused.Assessment.Requirements {
			fmt.Println("still needed:", r.Control, "-", r.Remedy)
		}
	case errors.Is(err, guardrails.ErrBlocked):
		fmt.Println("the tool ran, but its result was withheld from the model")
	case err == nil:
		fmt.Println(out.Result.Content, "· receipt", out.Receipt.Hash)
	}
}

// Plug in OCR and speech-to-text so images, scanned PDFs and audio are read
// rather than reported as unscannable.
func ExampleOptions_media() {
	g, err := guardrails.New(guardrails.Options{Media: guardrails.MediaBackends{
		OCR: guardrails.NewHTTPOCR("http://ocr:8000/ocr", ""),
		Transcriber: guardrails.NewOpenAITranscriber("https://api.groq.com/openai/v1",
			os.Getenv("GROQ_API_KEY"), "whisper-large-v3-turbo"),
	}})
	if err != nil {
		panic(err)
	}
	_ = g
}
