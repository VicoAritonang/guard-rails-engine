package guardrails_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencyBudget holds each public package to the third-party code it
// may link. The library is meant to be cheap to import, and one stray import
// in a guard package is enough to undo that: when the quota guard reached its
// price table through internal/telemetry, every importer compiled Prometheus,
// OpenTelemetry, gRPC and two provider SDKs (29 MB for a hello world).
func TestDependencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}

	const mod = "go.vicoworks.com/guard-rails-engine/"
	light := []string{"gopkg.in/yaml.v3"}
	withMedia := append([]string{"github.com/ledongthuc/pdf", "golang.org/x/net/html"}, light...)

	budget := []struct {
		pkg     string
		allowed []string
		netHTTP bool
	}{
		{"pkg/guardrails/engine", light, false},
		{"pkg/guardrails/textguard", light, false},
		{"pkg/guardrails/ruleguard", light, false},
		{"pkg/guardrails/toolguard", light, false},
		{"pkg/guardrails/mediaguard", withMedia, true},
		{"pkg/guardrails", withMedia, true},
		{"pkg/sdk", nil, true},
	}
	for _, b := range budget {
		t.Run(b.pkg, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-deps", mod+b.pkg).Output()
			if err != nil {
				t.Fatalf("go list: %v", err)
			}
			for _, dep := range strings.Fields(string(out)) {
				if dep == "net/http" && !b.netHTTP {
					t.Errorf("links net/http")
				}
				// Standard library paths have no dot in their first element.
				first, _, _ := strings.Cut(dep, "/")
				if !strings.Contains(first, ".") || strings.HasPrefix(dep, mod) {
					continue
				}
				ok := false
				for _, a := range b.allowed {
					if dep == a || strings.HasPrefix(dep, a+"/") {
						ok = true
					}
				}
				if !ok {
					t.Errorf("links %s, which is outside its budget %v", dep, b.allowed)
				}
			}
		})
	}
}
