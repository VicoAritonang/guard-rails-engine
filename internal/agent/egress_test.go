package agent

import (
	"testing"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// TestHostScopeSeesThroughAddressEncodings: an HTTP client resolves every one of
// these to a real address, so a classifier that reads them as hostnames calls
// the loopback public and the egress control waves it through.
func TestHostScopeSeesThroughAddressEncodings(t *testing.T) {
	cases := map[string]string{
		"127.1":                  "private",
		"2130706433":             "private",
		"0x7f.0.0.1":             "private",
		"0177.0.0.1":             "private",
		"0.1.2.3":                "private",
		"100.64.0.1":             "private",
		"::ffff:127.0.0.1":       "private",
		"2852039166":             "metadata",
		"0xa9fea9fe":             "metadata",
		"::ffff:169.254.169.254": "metadata",
		"8.8.8.8":                "public",
		"134744072":              "public",
		"example.com":            "public",
	}
	for host, want := range cases {
		if got := HostScope(host); got != want {
			t.Errorf("HostScope(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestParseDestinationKeepsEveryURLAURL: the opaque path skips the host checks,
// so a non-HTTP scheme or a malformed URL must not fall into it.
func TestParseDestinationKeepsEveryURLAURL(t *testing.T) {
	if d := ParseDestination("gopher://169.254.169.254/x"); d.Kind != "url" || d.Scope != "metadata" {
		t.Errorf("gopher URL parsed as %+v", d)
	}
	d := ParseDestination(`http://127.0.0.1\@evil.example`)
	if d.Kind != "url" || d.Host == "evil.example" {
		t.Errorf("a malformed URL must not take its host from after the @: %+v", d)
	}
	if d := ParseDestination("ID9900123"); d.Kind != "opaque" {
		t.Errorf("an account number is not a URL: %+v", d)
	}
}

// TestApprovalCannotBeReplayedWithAFreshSession: the session is caller-supplied,
// so the spent list inside it cannot be what makes an approval single-use.
func TestApprovalCannotBeReplayedWithAFreshSession(t *testing.T) {
	ev := testEvaluator(t)
	refund := call("issue_refund", map[string]any{"order_id": "ord_1", "amount": 12.40})
	sig := core.CallSignature(refund)

	token, _, err := ev.Options().Approver.Issue("trace-1", "issue_refund", sig, "ops@corp.example", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	session := func() *core.SessionState {
		s := &core.SessionState{Granted: []string{"finance:refund"}}
		s.RecordSimulation(sig)
		return s
	}

	first := Request{Trace: "trace-1", Call: refund, Session: session(), IdempotencyKey: "k1", ApprovalToken: token}
	a := ev.Assess(first)
	if !a.Allowed() {
		t.Fatalf("the approved call should proceed: %+v", a.Findings)
	}
	ev.Commit(first, &a)

	replay := ev.Assess(Request{Trace: "trace-1", Call: refund, Session: session(), IdempotencyKey: "k2", ApprovalToken: token})
	if replay.Allowed() || !hasCategory(replay, "tool.approval_reused") {
		t.Errorf("a spent approval must not work under a new session: %+v", replay.Findings)
	}
}
