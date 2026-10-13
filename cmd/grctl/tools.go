package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vicoaritonang/guardrails-engine/internal/agent"
)

// runTools prints the tool risk matrix.
//
// This is the document a security reviewer asks for and almost never gets: for
// every action the agent can take, what it costs to undo, how far it reaches,
// and which controls stand in front of it. Generating it from the catalog
// rather than maintaining it by hand is the only way it stays true -- a matrix
// in a wiki is out of date the first time someone adds a tool.
func runTools(args []string) error {
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "YAML catalog to load instead of the built-in one")
	format := fs.String("format", "table", "table | markdown | json")
	tierFilter := fs.String("tier", "", "show only this tier (T0..T4)")
	verbose := fs.Bool("verbose", false, "include the risk rationale for each tool")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cat, err := agent.DefaultCatalog()
	if err != nil {
		return err
	}
	if *catalogPath != "" {
		if cat, err = agent.LoadCatalog(*catalogPath); err != nil {
			return err
		}
	}

	var only *agent.Tier
	if *tierFilter != "" {
		t, err := agent.ParseTier(*tierFilter)
		if err != nil {
			return err
		}
		only = &t
	}

	switch *format {
	case "json":
		return writeJSONOut(os.Stdout, cat.Tools())
	case "markdown":
		printToolMatrix(cat, only, *verbose, true)
	default:
		printToolMatrix(cat, only, *verbose, false)
	}
	return nil
}

func printToolMatrix(cat *agent.Catalog, only *agent.Tier, verbose, markdown bool) {
	if markdown {
		fmt.Println("# Tool risk matrix")
		fmt.Println()
		fmt.Println("Tier is derived from two axes: how hard the effect is to undo, and how")
		fmt.Println("far it reaches. Exposure is tracked separately because it measures a")
		fmt.Println("different thing -- not what a call can break, but what it can leak or")
		fmt.Println("let in.")
		fmt.Println()
	}

	byTier := cat.ByTier()
	for _, tier := range agent.Tiers() {
		if only != nil && tier != *only {
			continue
		}
		tools := byTier[tier]
		if len(tools) == 0 {
			continue
		}

		if markdown {
			fmt.Printf("\n## %s\n\n", tier)
			// The rationale goes in its own column rather than in a blockquote
			// between rows: anything other than a row breaks the table.
			header := "| Tool | Reversibility | Radius | Exposure | Capability | Controls |"
			rule := "|---|---|---|---|---|---|"
			if verbose {
				header = "| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |"
				rule = "|---|---|---|---|---|---|---|"
			}
			fmt.Println(header)
			fmt.Println(rule)
		} else {
			fmt.Printf("\n%s  (%d tools)\n", strings.ToUpper(tier.String()), len(tools))
			fmt.Println(strings.Repeat("-", 100))
		}

		for _, t := range tools {
			controls := strings.Join(t.Controls().Names(), ", ")
			if markdown {
				if verbose {
					why := t.Rationale
					if t.Undo != "" {
						why += " **Undo:** " + t.Undo
					} else if t.Reversibility == agent.RevIrreversible {
						why += " **Undo:** none."
					}
					fmt.Printf("| `%s` | %s | %s | %s | `%s` | %s | %s |\n",
						t.Name, t.Reversibility, t.Radius, t.Exposure,
						orDash(t.Capability), controls, cellSafe(why))
				} else {
					fmt.Printf("| `%s` | %s | %s | %s | `%s` | %s |\n",
						t.Name, t.Reversibility, t.Radius, t.Exposure,
						orDash(t.Capability), controls)
				}
			} else {
				fmt.Printf("  %-22s %-13s %-10s %-18s %s\n",
					t.Name, t.Reversibility, t.Radius, t.Exposure, orDash(t.Capability))
				fmt.Printf("  %-22s controls: %s\n", "", controls)
			}
			if !markdown && verbose {
				if t.Rationale != "" {
					fmt.Println(wrapText(t.Rationale, "  "+strings.Repeat(" ", 22)+"why: ", 100))
				}
				if t.Undo != "" {
					fmt.Printf("  %-22s undo: %s\n", "", t.Undo)
				}
			}
		}
	}

	if !markdown {
		fmt.Println()
		fmt.Println("Capabilities (grant the smallest set that does the job):")
		for _, tier := range agent.Tiers() {
			caps := cat.CapabilitiesUpTo(tier)
			if len(caps) == 0 {
				continue
			}
			fmt.Printf("  up to %-18s %s\n", tier.String()+":", strings.Join(caps, " "))
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// wrapText reflows a sentence under a prefix, so a long rationale stays
// readable in a terminal.
func wrapText(s, prefix string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var out []string
	line := prefix
	indent := strings.Repeat(" ", len(prefix))
	for _, w := range words {
		if len(line)+len(w)+1 > width && strings.TrimSpace(line) != strings.TrimSpace(prefix) {
			out = append(out, line)
			line = indent
		}
		if strings.TrimSpace(line) == "" || strings.HasSuffix(line, " ") {
			line += w
		} else {
			line += " " + w
		}
	}
	return strings.Join(append(out, line), "\n")
}

// cellSafe keeps a rationale inside one markdown table cell.
func cellSafe(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.Join(strings.Fields(s), " ")
}
