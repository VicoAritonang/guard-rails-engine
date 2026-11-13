// Package sdk is the Go client for a guardrails-engine deployment.
//
// It exists for the sidecar pattern: an application that already owns its
// provider integration calls Inbound before sending a prompt and Outbound
// before returning a completion, keeping the model call entirely in its own
// process. That is usually the right first step -- it adds a check without
// putting a new hop in the critical path.
//
// The client is safe for concurrent use and holds no per-request state.
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to a guardrails gateway.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client

	// failOpen decides what happens when the GATEWAY itself is unreachable.
	//
	// This is the same question the engine asks about an individual guard, one
	// level up, and it has the same answer: it depends on the workload, so the
	// caller must choose rather than inherit a silent default. FailOpen(true)
	// keeps a consumer product serving when the sidecar is down; the default
	// (false) refuses, which is correct when the guardrail is a compliance
	// control rather than a nicety.
	failOpen bool
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the bearer token.
func WithAPIKey(key string) Option { return func(c *Client) { c.apiKey = key } }

// WithHTTPClient supplies a custom transport (timeouts, tracing, mTLS).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// WithTimeout sets the per-request timeout on the default transport.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// FailOpen makes an unreachable gateway allow the request instead of failing
// it. Read the note on Client.failOpen before enabling this.
func FailOpen(v bool) Option { return func(c *Client) { c.failOpen = v } }

// New creates a client for the gateway at baseURL.
func New(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("sdk: baseURL is required")
	}
	c := &Client{
		baseURL: trimSlash(baseURL),
		http: &http.Client{
			Timeout: 10 * time.Second,
			// The engine's own budget is tens of milliseconds; a ten-second
			// ceiling here is for network pathology, not for the engine.
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ToolCall is a proposed tool invocation.
type ToolCall struct {
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Raw       string         `json:"raw,omitempty"`
}

// Usage carries token accounting for the budget breaker.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_input_tokens,omitempty"`
	CacheWriteTokens int `json:"cache_creation_input_tokens,omitempty"`
}

// ToolResult is what a tool returned, submitted before the model reads it.
type ToolResult struct {
	CallID  string `json:"call_id,omitempty"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
	// Origin says who could have written the content, such as "web" for a fetch
	// tool. The stricter origins get the stricter rails.
	Origin string `json:"origin,omitempty"`
}

// Request is the payload submitted for a decision.
type Request struct {
	Tenant      string         `json:"tenant,omitempty"`
	Model       string         `json:"model,omitempty"`
	System      string         `json:"system,omitempty"`
	Messages    []Message      `json:"messages,omitempty"`
	Completion  string         `json:"completion,omitempty"`
	Context     []string       `json:"context,omitempty"`
	ToolCalls   []ToolCall     `json:"tool_calls,omitempty"`
	History     []ToolCall     `json:"history,omitempty"`
	ToolResults []ToolResult   `json:"tool_results,omitempty"`
	Step        int            `json:"step,omitempty"`
	Usage       Usage          `json:"usage,omitzero"`
	CostUSD     float64        `json:"cost_usd,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`

	// Session is the agent's state, passed back unchanged on each step.
	Session json.RawMessage `json:"session,omitempty"`

	// VaultToken is Response.VaultToken from the inbound call. Without it the
	// outbound stage cannot restore the values inbound masked.
	VaultToken string `json:"vault_token,omitempty"`
}

// Span locates a finding in the original payload.
type Span struct {
	Field   string `json:"field"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Excerpt string `json:"excerpt,omitempty"`
}

// Finding is one detection.
type Finding struct {
	Guard    string            `json:"guard"`
	Rule     string            `json:"rule"`
	Category string            `json:"category"`
	Severity string            `json:"severity"`
	Score    float64           `json:"score"`
	Message  string            `json:"message"`
	Spans    []Span            `json:"spans,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// Decision is the engine's verdict.
type Decision struct {
	TransactionID string    `json:"transaction_id"`
	Stage         string    `json:"stage"`
	Action        string    `json:"action"`
	Findings      []Finding `json:"findings,omitempty"`
	DurationNS    int64     `json:"duration_ns"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	Degraded      bool      `json:"degraded,omitempty"`
}

// Response is a decision plus the payload as the engine left it.
type Response struct {
	Decision *Decision `json:"decision"`
	// System and Messages come back REWRITTEN when the engine redacted. Send
	// these to the provider, not your originals -- forwarding the originals
	// silently defeats the redaction you just paid for.
	System      string       `json:"system,omitempty"`
	Messages    []Message    `json:"messages,omitempty"`
	Completion  string       `json:"completion,omitempty"`
	ToolResults []ToolResult `json:"tool_results,omitempty"`
	Blocked     bool         `json:"blocked"`
	Reason      string       `json:"reason,omitempty"`

	// Session is the agent state as this stage left it. Pass it back unchanged
	// on the next step.
	Session json.RawMessage `json:"session,omitempty"`

	// VaultToken carries the placeholders of this exchange, encrypted. Pass it
	// to Outbound. It is empty when nothing was masked.
	VaultToken string `json:"vault_token,omitempty"`
}

// ErrBlocked is returned when policy refuses the payload. Callers should
// present Reason to the user and stop.
var ErrBlocked = errors.New("guardrails: blocked by policy")

// BlockedError carries the full decision alongside ErrBlocked.
type BlockedError struct {
	Reason   string
	Decision *Decision
}

func (e *BlockedError) Error() string { return "guardrails: blocked by policy: " + e.Reason }
func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Inbound checks a prompt before it reaches a provider.
func (c *Client) Inbound(ctx context.Context, req Request) (*Response, error) {
	return c.guard(ctx, "inbound", req)
}

// Runtime checks proposed tool calls inside an agent loop.
func (c *Client) Runtime(ctx context.Context, req Request) (*Response, error) {
	return c.guard(ctx, "runtime", req)
}

// ToolResult checks what a tool returned, before the model reads it.
func (c *Client) ToolResult(ctx context.Context, req Request) (*Response, error) {
	return c.guard(ctx, "tool_result", req)
}

// Outbound checks a model completion before it reaches the caller.
func (c *Client) Outbound(ctx context.Context, req Request) (*Response, error) {
	return c.guard(ctx, "outbound", req)
}

func (c *Client) guard(ctx context.Context, stage string, req Request) (*Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sdk: marshal request: %w", err)
	}

	url := c.baseURL + "/v1/guard/" + stage
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sdk: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return c.unreachable(stage, req, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return c.unreachable(stage, req, err)
	}

	// A 5xx from a load balancer in front of a dead gateway is the same event
	// as a refused connection, so the configured fail mode applies to it too.
	if resp.StatusCode >= http.StatusInternalServerError {
		return c.unreachable(stage, req, fmt.Errorf("gateway returned %d", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sdk: gateway returned %d: %s",
			resp.StatusCode, truncate(string(payload), 300))
	}

	var out Response
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("sdk: decode response: %w", err)
	}
	if out.Blocked {
		return &out, &BlockedError{Reason: out.Reason, Decision: out.Decision}
	}
	return &out, nil
}

// unreachable applies the configured fail mode when the gateway cannot be
// reached at all.
func (c *Client) unreachable(stage string, req Request, cause error) (*Response, error) {
	if !c.failOpen {
		return nil, fmt.Errorf("sdk: gateway unreachable (fail-closed): %w", cause)
	}
	// Echo the payload back unchanged so the caller's code path is identical
	// whether the gateway answered or not, and mark the decision degraded so
	// the caller can log or meter it.
	return &Response{
		Decision: &Decision{
			Stage:    stage,
			Action:   "allow",
			Degraded: true,
		},
		System:      req.System,
		Messages:    req.Messages,
		Completion:  req.Completion,
		ToolResults: req.ToolResults,
		Session:     req.Session,
		VaultToken:  req.VaultToken,
	}, nil
}

// Health reports whether the gateway is serving.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sdk: gateway unhealthy: %d", resp.StatusCode)
	}
	return nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
