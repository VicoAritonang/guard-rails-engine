package eval

import (
	"context"
	"fmt"
	"math"

	"github.com/vicoaritonang/guardrails-engine/config"
)

// SweepPoint is one threshold setting and what it costs.
type SweepPoint struct {
	Threshold float64 `json:"threshold"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	FPR       float64 `json:"fpr"`
	BenignFPR float64 `json:"benign_fpr"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	TN        int     `json:"tn"`
}

// Sweep is a precision/recall curve for one guard.
type Sweep struct {
	Guard     string       `json:"guard"`
	Family    string       `json:"family"`
	Points    []SweepPoint `json:"points"`
	BestF1    SweepPoint   `json:"best_f1"`
	Current   float64      `json:"current_threshold"`
	Suggested float64      `json:"suggested_threshold"`
}

// RunSweep re-runs the corpus at each threshold for a score-based guard.
//
// This is the single most useful artefact this package produces. A threshold
// is not a constant to be guessed once in a config file -- it is the knob that
// trades false negatives against false positives, and the only honest way to
// choose it is to see the whole curve on your own traffic. Shipping a default
// without publishing the curve behind it is asking operators to trust a magic
// number.
//
// Note what this does NOT claim: the suggested threshold maximises F1 on this
// corpus. F1 weights a missed attack and a blocked customer equally, which is
// almost never the real trade. Operators should pick the point that matches
// their own cost ratio; the curve is what makes that possible.
func RunSweep(ctx context.Context, base *config.Policy, ds *Dataset, guard, family string, steps int, secret []byte) (*Sweep, error) {
	if _, ok := base.Guards[guard]; !ok {
		return nil, fmt.Errorf("sweep: policy has no guard %q", guard)
	}
	if steps < 2 {
		steps = 19 // 0.05 .. 0.95
	}

	sw := &Sweep{
		Guard:   guard,
		Family:  family,
		Current: base.Guard(guard).Threshold,
	}

	bestF1 := math.Inf(-1)
	for i := 1; i <= steps; i++ {
		th := float64(i) / float64(steps+1)

		// Clone the policy so each point is independent. Mutating a shared
		// policy would make the curve depend on iteration order.
		pol := clonePolicyWithThreshold(base, guard, th)
		h, err := NewHarnessFromPolicy(pol, secret)
		if err != nil {
			return nil, fmt.Errorf("sweep: threshold %.2f: %w", th, err)
		}
		rep, err := h.Run(ctx, ds)
		if err != nil {
			return nil, err
		}

		c := rep.ByFamily[family]
		p := SweepPoint{
			Threshold: round3(th),
			Precision: nanTo(c.Precision(), 0),
			Recall:    nanTo(c.Recall(), 0),
			F1:        nanTo(c.F1(), 0),
			FPR:       nanTo(c.FPR(), 0),
			BenignFPR: rep.BenignFPR,
			TP:        c.TP, FP: c.FP, FN: c.FN, TN: c.TN,
		}
		sw.Points = append(sw.Points, p)

		if p.F1 > bestF1 {
			bestF1, sw.BestF1 = p.F1, p
		}
	}
	sw.Suggested = sw.BestF1.Threshold
	return sw, nil
}

// clonePolicyWithThreshold deep-copies just enough of the policy to change one
// guard's threshold safely.
func clonePolicyWithThreshold(base *config.Policy, guard string, th float64) *config.Policy {
	out := *base
	out.Guards = make(map[string]*config.GuardConfig, len(base.Guards))
	for name, g := range base.Guards {
		cp := *g
		out.Guards[name] = &cp
	}
	out.Guards[guard].Threshold = th
	return &out
}

func nanTo(f, def float64) float64 {
	if math.IsNaN(f) {
		return def
	}
	return round3(f)
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
