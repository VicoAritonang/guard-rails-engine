package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
)

func runPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy: expected a subcommand (show | lint | explain)")
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "show":
		return policyShow(rest)
	case "lint":
		return policyLint(rest)
	case "explain":
		return policyExplain(rest)
	default:
		return fmt.Errorf("policy: unknown subcommand %q (want show | lint | explain)", sub)
	}
}

func policyShow(args []string) error {
	fs := flag.NewFlagSet("policy show", flag.ExitOnError)
	path := fs.String("policy", "", "policy YAML")
	strict := fs.Bool("strict", false, "show the built-in strict policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pol, err := loadPolicy(*path, *strict)
	if err != nil {
		return err
	}
	// The merged, effective policy is what an operator needs when debugging a
	// decision -- not the short overlay file they wrote.
	out, err := pol.Marshal()
	if err != nil {
		return err
	}
	fmt.Printf("# effective policy (source: %s)\n%s", pol.Path(), out)
	return nil
}

// policyLint validates a policy AND proves every enabled guard can actually be
// constructed. Validation alone would pass a policy whose parameters blow up at
// startup, which is the failure an operator least wants to discover during a
// deploy.
func policyLint(args []string) error {
	fs := flag.NewFlagSet("policy lint", flag.ExitOnError)
	path := fs.String("policy", "", "policy YAML")
	strict := fs.Bool("strict", false, "lint the built-in strict policy")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadPolicy(*path, *strict)
	if err != nil {
		return fmt.Errorf("policy is invalid: %w", err)
	}
	engine, err := guards.Build(pol, guards.Deps{Secret: []byte("lint-secret-32-bytes-for-hmac-ok")})
	if err != nil {
		return fmt.Errorf("policy fails to build: %w", err)
	}

	fmt.Printf("%s: OK (version %s, %d guards enabled)\n",
		pol.Path(), pol.Version, len(pol.EnabledGuards()))

	// Warnings are advisory: things that are legal but usually a mistake.
	var warnings []string
	if tp := pol.Guard(config.GuardToolPolicy); tp.Enabled &&
		len(tp.Strings("allow")) == 0 && len(tp.Strings("deny")) == 0 {
		warnings = append(warnings,
			"tool_policy has neither allow nor deny: every tool the model proposes will be permitted")
	}
	for _, name := range pol.EnabledGuards() {
		if pol.EffectiveFailMode(name) == config.FailOpen {
			switch name {
			case config.GuardSecrets, config.GuardToolPolicy, config.GuardBudget, config.GuardQuota:
				warnings = append(warnings, fmt.Sprintf(
					"%s is fail-open: a guard failure there has unbounded downside (credentials, spend, or infrastructure)", name))
			}
		}
	}
	for _, name := range config.KnownGuards() {
		if !pol.Guard(name).Enabled {
			warnings = append(warnings, fmt.Sprintf("%s is disabled", name))
		}
	}

	// The tool-level control plane reports its own configuration gaps. They
	// belong here rather than in per-request findings: "no egress allowlist is
	// configured" describes the deployment, not the call, and emitting it on
	// every request turns a fixable warning into background noise that also
	// shows up as a false positive in the eval report.
	if ev := engine.ToolEvaluator(); ev != nil {
		warnings = append(warnings, ev.Lint()...)
	}

	if len(warnings) > 0 {
		fmt.Println("\nwarnings:")
		sort.Strings(warnings)
		for _, w := range warnings {
			fmt.Println("  -", w)
		}
	}
	return nil
}

// policyExplain prints the severity-to-action matrix each guard resolves to.
//
// "Why was this blocked?" is answered by three layered lookups (category
// override, guard action map, policy default) and reading a YAML file will not
// tell you the result. Printing the resolved matrix does.
func policyExplain(args []string) error {
	fs := flag.NewFlagSet("policy explain", flag.ExitOnError)
	path := fs.String("policy", "", "policy YAML")
	strict := fs.Bool("strict", false, "explain the built-in strict policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pol, err := loadPolicy(*path, *strict)
	if err != nil {
		return err
	}

	fmt.Printf("policy %q version %s (%s)\n\n", pol.Name, pol.Version, pol.Path())

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "GUARD\tSTAGE\tENABLED\tFAIL\tTIMEOUT\tTHRESH\tINFO\tLOW\tMEDIUM\tHIGH\tCRITICAL")

	names := config.KnownGuards()
	sort.Slice(names, func(i, j int) bool {
		si, _ := config.GuardStage(names[i])
		sj, _ := config.GuardStage(names[j])
		if si != sj {
			return stageOrder(si) < stageOrder(sj)
		}
		return names[i] < names[j]
	})

	for _, name := range names {
		g := pol.Guard(name)
		stage, _ := config.GuardStage(name)
		thresh := "-"
		if g.Threshold > 0 {
			thresh = fmt.Sprintf("%.2f", g.Threshold)
		}
		row := []string{
			name, stage, boolStr(g.Enabled),
			string(pol.EffectiveFailMode(name)),
			pol.EffectiveTimeout(name).String(),
			thresh,
		}
		for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
			row = append(row, pol.ActionFor(name, "", sev))
		}
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Println("\nstage budgets:")
	for _, s := range []string{"inbound", "runtime", "outbound"} {
		fmt.Printf("  %-9s %s\n", s, pol.Budget(s))
	}

	// Category overrides are the layer people forget exists; print them last
	// so the matrix above is not silently wrong for those categories.
	var overrides []string
	for _, name := range config.KnownGuards() {
		for cat, ov := range pol.Guard(name).Categories {
			parts := []string{}
			if ov.Action != "" {
				parts = append(parts, "action="+ov.Action)
			}
			if ov.Severity != "" {
				parts = append(parts, "severity="+ov.Severity)
			}
			if ov.Disabled {
				parts = append(parts, "disabled")
			}
			if ov.Threshold > 0 {
				parts = append(parts, fmt.Sprintf("threshold=%.2f", ov.Threshold))
			}
			overrides = append(overrides, fmt.Sprintf("  %-16s %-32s %s", name, cat, strings.Join(parts, " ")))
		}
	}
	if len(overrides) > 0 {
		sort.Strings(overrides)
		fmt.Println("\ncategory overrides (these win over the matrix above):")
		for _, o := range overrides {
			fmt.Println(o)
		}
	}
	return nil
}

func stageOrder(s string) int {
	switch s {
	case "inbound":
		return 0
	case "runtime":
		return 1
	default:
		return 2
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
