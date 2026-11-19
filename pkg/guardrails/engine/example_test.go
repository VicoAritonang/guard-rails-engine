package engine_test

import (
	"context"
	"errors"
	"fmt"

	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/engine"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/mediaguard"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/textguard"
	"go.vicoworks.com/guard-rails-engine/pkg/guardrails/toolguard"
)

// These examples render on pkg.go.dev. They have no Output comments, so go
// test compiles them without running them.

// A chat feature: the text guards, nothing else compiled in.
func ExampleNew() {
	ctx := context.Background()
	g, err := engine.New(engine.Options{}, textguard.Module())
	if err != nil {
		panic(err)
	}
	in, err := g.Inbound(ctx, engine.Request{Messages: []engine.Message{
		{Role: engine.RoleUser, Content: "My email is andi@nusantara.co.id"},
	}})
	if errors.Is(err, engine.ErrBlocked) {
		fmt.Println("refused:", in.Reason)
		return
	}
	answer := "Done." // your model call goes here, given in.Messages
	out, _ := g.Outbound(ctx, engine.Request{Completion: answer, Vault: in.Vault})
	fmt.Println(out.Completion)
}

// Only some guards of a module.
func ExampleNew_selectGuards() {
	g, err := engine.New(engine.Options{}, textguard.Module(textguard.PII, textguard.Secrets, textguard.Restore))
	if err != nil {
		panic(err)
	}
	fmt.Println(g.Guards()) // [pii restore secrets]
}

// An agent with its own tools and file uploads.
func ExampleNew_agent() {
	g, err := engine.New(engine.Options{ToolCatalogFile: "tools.yaml"},
		textguard.Module(), toolguard.Module(), mediaguard.Module(mediaguard.Backends{}))
	if err != nil {
		panic(err)
	}
	_, _ = toolguard.Execute(context.Background(), g, toolguard.Run{Call: engine.ToolCall{Name: "lookup_order"}},
		toolguard.Funcs{ExecuteFunc: func(context.Context, engine.ToolCall) (engine.ToolResult, error) {
			return engine.ToolResult{Content: "order A-1: shipped"}, nil
		}})
}
