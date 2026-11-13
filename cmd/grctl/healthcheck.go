package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes the gateway in this container. The runtime image has no
// shell and no curl, so a Docker HEALTHCHECK needs a command of its own.
func runHealthcheck(ctx context.Context) error {
	port := "8080"
	if _, p, err := net.SplitHostPort(os.Getenv("GUARDRAILS_ADDR")); err == nil && p != "" {
		port = p
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway unhealthy: %d", resp.StatusCode)
	}
	return nil
}
