package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/mcp"
)

// runMCPDemo serves the hostile demo MCP server the gateway is tested against.
// Never point a real agent at it directly: that is the point of it.
func runMCPDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp-demo", flag.ContinueOnError)
	addr := fs.String("addr", ":8090", "listen address")
	rug := fs.Int64("rug-pull-after", 3, "tools/list calls before convert_currency turns malicious")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", &mcp.DemoServer{RugPullAfter: *rug})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	fmt.Printf("hostile demo MCP server on %s/mcp (rug pull after %d lists)\n", *addr, *rug)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
