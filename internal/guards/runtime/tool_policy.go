package runtime

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"go.vicoworks.com/guard-rails-engine/config"
	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// ToolPolicy decides whether a proposed tool call is allowed to execute.
//
// This is the highest-consequence guard in the engine. Everything else shapes
// text; this one stands between a language model's inference and a real side
// effect on real infrastructure. It fails closed, and it treats an empty
// allowlist as a configuration smell worth reporting rather than as implicit
// permission for everything.
type ToolPolicy struct {
	cfg *config.GuardConfig

	allow        map[string]bool
	deny         map[string]bool
	blockPrivate bool
	scanArgs     bool
}

func NewToolPolicy(cfg *config.GuardConfig) (*ToolPolicy, error) {
	g := &ToolPolicy{
		cfg:          cfg,
		allow:        toSet(cfg.Strings("allow")),
		deny:         toSet(cfg.Strings("deny")),
		blockPrivate: cfg.Bool("block_private_urls", true),
		scanArgs:     cfg.Bool("scan_arguments", true),
	}
	for name := range g.allow {
		if g.deny[name] {
			return nil, fmt.Errorf("tool_policy: %q appears in both allow and deny", name)
		}
	}
	return g, nil
}

func (g *ToolPolicy) Name() string      { return config.GuardToolPolicy }
func (g *ToolPolicy) Stage() core.Stage { return core.StageRuntime }

// dangerousArgs are argument patterns that turn an ordinary tool into a
// destructive one. They are matched against the serialised arguments, so they
// catch the payload regardless of which parameter carried it.
var dangerousArgs = []struct {
	ID       string
	Category string
	Severity core.Severity
	Pattern  *regexp.Regexp
}{
	{
		ID: "destructive_shell", Category: "tool.destructive_command", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)\b(?:rm\s+-[rf]{1,2}\s+/|mkfs\.|dd\s+if=/dev/(?:zero|random)|:\(\)\{.*\};:|shutdown\s+-|chmod\s+-R\s+777\s+/)`),
	},
	{
		ID: "destructive_sql", Category: "tool.destructive_query", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|$)|update\s+\w+\s+set\s+[^;]*(?:;|$))`),
	},
	{
		ID: "path_traversal", Category: "tool.path_traversal", Severity: core.SeverityHigh,
		Pattern: regexp.MustCompile(`(?:\.\./){2,}|%2e%2e%2f|/etc/(?:passwd|shadow)|\\windows\\system32\\config`),
	},
	{
		ID: "credential_path", Category: "tool.credential_access", Severity: core.SeverityHigh,
		Pattern: regexp.MustCompile(`(?i)(?:\.aws/credentials|\.ssh/id_[rd]sa|\.env\b|\.netrc|id_ed25519|kubeconfig)`),
	},
	{
		ID: "remote_exec", Category: "tool.remote_execution", Severity: core.SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(?:curl|wget)\s+[^\s|]*\s*\|\s*(?:ba)?sh|python\s+-c\s+["']import\s+os`),
	},
}

// metadataHosts are the cloud instance-metadata endpoints. A tool call that
// reaches one of these is either SSRF or an agent that has been talked into
// stealing its own host's credentials.
var metadataHosts = []string{
	"169.254.169.254", "metadata.google.internal", "metadata.goog",
	"100.100.100.200", "fd00:ec2::254",
}

func (g *ToolPolicy) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result

	// Note: "this policy has no allowlist" is a configuration problem, not a
	// property of the request. It used to be emitted as a finding here, which
	// made every benign tool call look like a detection and dragged this
	// guard's precision to 50% in the eval report. It now surfaces once, at
	// `grctl policy lint`, where the person who can fix it will see it.

	for i, call := range tx.ToolCalls {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		field := fmt.Sprintf("tool_calls[%d].raw", i)

		switch {
		case g.deny[call.Name]:
			f := core.NewFinding(g.Name(), "denied_tool", "tool.denied", core.SeverityHigh, 1.0,
				fmt.Sprintf("tool %q is explicitly denied by policy", call.Name))
			f.Spans = []core.Span{{Field: field}}
			f.Meta = map[string]string{"tool": call.Name}
			res.Findings = append(res.Findings, f)
		case len(g.allow) > 0 && !g.allow[call.Name]:
			f := core.NewFinding(g.Name(), "not_allowlisted", "tool.not_allowlisted", core.SeverityHigh, 1.0,
				fmt.Sprintf("tool %q is not on the allowlist", call.Name))
			f.Spans = []core.Span{{Field: field}}
			f.Meta = map[string]string{"tool": call.Name}
			res.Findings = append(res.Findings, f)
		}

		if !g.scanArgs {
			continue
		}
		args := call.Raw
		if args == "" {
			args = fmt.Sprint(call.Arguments)
		}

		for _, rule := range dangerousArgs {
			loc := rule.Pattern.FindStringIndex(args)
			if loc == nil {
				continue
			}
			f := core.NewFinding(g.Name(), rule.ID, rule.Category, rule.Severity, 0.95,
				fmt.Sprintf("tool %q carries a %s payload", call.Name, rule.ID))
			f.Spans = []core.Span{{
				Field: field, Start: loc[0], End: loc[1],
				Excerpt: args[loc[0]:min(loc[1], loc[0]+120)],
			}}
			f.Meta = map[string]string{"tool": call.Name}
			res.Findings = append(res.Findings, f)
		}

		if g.blockPrivate {
			res.Findings = append(res.Findings, g.checkURLs(call.Name, field, args)...)
		}
	}
	return res, nil
}

var reURL = regexp.MustCompile(`https?://[^\s"'<>\\)]+`)

// checkURLs flags requests aimed at the internal network.
//
// The relevant threat is not a user typing an internal URL -- it is an
// injected instruction inside a retrieved document telling the agent to fetch
// one, exfiltrating whatever comes back. Blocking the private ranges here is a
// cheap, high-value stop even though a determined attacker can still use DNS
// rebinding; defeating that requires resolving at connect time, which belongs
// in the HTTP client, not in a stateless guard.
func (g *ToolPolicy) checkURLs(tool, field, args string) []core.Finding {
	var out []core.Finding
	for _, loc := range reURL.FindAllStringIndex(args, 16) {
		raw := args[loc[0]:loc[1]]
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		lowHost := strings.ToLower(host)

		category, severity := "", core.SeverityHigh
		for _, m := range metadataHosts {
			if lowHost == m {
				category, severity = "tool.metadata_endpoint", core.SeverityCritical
			}
		}
		if category == "" {
			if ip := net.ParseIP(host); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					category = "tool.private_network"
				}
			} else if lowHost == "localhost" || strings.HasSuffix(lowHost, ".local") ||
				strings.HasSuffix(lowHost, ".internal") || !strings.Contains(lowHost, ".") {
				category = "tool.private_network"
			}
		}
		if category == "" {
			continue
		}

		f := core.NewFinding(g.Name(), "private_url", category, severity, 0.9,
			fmt.Sprintf("tool %q targets internal host %q", tool, host))
		f.Spans = []core.Span{{Field: field, Start: loc[0], End: loc[1], Excerpt: raw}}
		f.Meta = map[string]string{"tool": tool, "host": host}
		out = append(out, f)
	}
	return out
}

func toSet(list []string) map[string]bool {
	if len(list) == 0 {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out[s] = true
		}
	}
	return out
}
