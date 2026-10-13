package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client speaks MCP over Streamable HTTP to one upstream server.
//
// It accepts both response shapes the transport allows -- a plain JSON body
// or an SSE stream carrying the response -- because servers pick either, and a
// gateway that only handled one would be a gateway that works with some
// servers.
type Client struct {
	Name string
	URL  string

	http    *http.Client
	mu      sync.Mutex
	session string
	ready   bool
	nextID  atomic.Int64
}

// NewClient builds a client; the handshake happens on first use.
func NewClient(name, url string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Client{Name: name, URL: url, http: &http.Client{Timeout: timeout}}
}

// ListTools returns the upstream's current tool definitions.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	raw, err := c.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: tools/list: %w", c.Name, err)
	}
	return out.Tools, nil
}

// CallTool invokes one upstream tool.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*CallResult, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	raw, err := c.rpc(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var out CallResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: tools/call: %w", c.Name, err)
	}
	return &out, nil
}

func (c *Client) ensure(ctx context.Context) error {
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if ready {
		return nil
	}
	if _, err := c.rpc(ctx, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "guardrails-mcp-gateway", "version": "1"},
	}); err != nil {
		return err
	}
	_ = c.notify(ctx, "notifications/initialized")
	c.mu.Lock()
	c.ready = true
	c.mu.Unlock()
	return nil
}

func (c *Client) post(ctx context.Context, body any) (*http.Response, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", ProtocolVersion)
	c.mu.Lock()
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	c.mu.Unlock()
	return c.http.Do(req)
}

func (c *Client) notify(ctx context.Context, method string) error {
	resp, err := c.post(ctx, Request{JSONRPC: "2.0", Method: method})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	p, _ := json.Marshal(params)
	resp, err := c.post(ctx, Request{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprint(id)), Method: method, Params: p})
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", c.Name, method, err)
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.mu.Lock()
		c.session = sid
		c.mu.Unlock()
	}
	if resp.StatusCode == http.StatusNotFound && method != "initialize" {
		// The upstream expired our session; the spec says start a new one.
		c.mu.Lock()
		c.ready, c.session = false, ""
		c.mu.Unlock()
		return nil, fmt.Errorf("%s: session expired", c.Name)
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%s: %s: HTTP %d: %s", c.Name, method, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		// Read events until the one carrying our response.
		sc := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			if json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &r) == nil && (r.Result != nil || r.Error != nil) {
				break
			}
		}
	} else if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("%s: %s: decode: %w", c.Name, method, err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("%s: %s: %w", c.Name, method, r.Error)
	}
	return r.Result, nil
}
