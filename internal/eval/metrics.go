package eval

import (
	"math"
	"sort"
	"time"
)

// Confusion is a binary confusion matrix for one detection family.
type Confusion struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

func (c Confusion) Total() int { return c.TP + c.FP + c.FN + c.TN }

// Precision: of everything we flagged, how much was real.
//
// This is the metric that decides whether a guardrail stays enabled. A
// detector with 99% recall and 40% precision will be switched off within a
// week, because the team drowns in false positives and stops trusting it.
func (c Confusion) Precision() float64 {
	if c.TP+c.FP == 0 {
		return math.NaN() // nothing was flagged: precision is undefined, not 0
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall: of everything real, how much did we catch.
func (c Confusion) Recall() float64 {
	if c.TP+c.FN == 0 {
		return math.NaN() // no positives in the corpus
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// F1 is the harmonic mean of precision and recall.
func (c Confusion) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if math.IsNaN(p) || math.IsNaN(r) || p+r == 0 {
		return math.NaN()
	}
	return 2 * p * r / (p + r)
}

// FPR is the false-positive rate on negatives: the fraction of benign traffic
// this family would disrupt.
func (c Confusion) FPR() float64 {
	if c.FP+c.TN == 0 {
		return math.NaN()
	}
	return float64(c.FP) / float64(c.FP+c.TN)
}

// Accuracy is reported for completeness and should mostly be ignored: on a
// corpus that is 90% benign, a detector that never fires scores 90%.
func (c Confusion) Accuracy() float64 {
	if c.Total() == 0 {
		return math.NaN()
	}
	return float64(c.TP+c.TN) / float64(c.Total())
}

// Add accumulates another matrix.
func (c *Confusion) Add(o Confusion) {
	c.TP += o.TP
	c.FP += o.FP
	c.FN += o.FN
	c.TN += o.TN
}

// Observe records one prediction.
func (c *Confusion) Observe(predicted, actual bool) {
	switch {
	case predicted && actual:
		c.TP++
	case predicted && !actual:
		c.FP++
	case !predicted && actual:
		c.FN++
	default:
		c.TN++
	}
}

// Latency holds a sorted sample of durations.
type Latency struct {
	samples []time.Duration
	sorted  bool
}

func (l *Latency) Add(d time.Duration) {
	l.samples = append(l.samples, d)
	l.sorted = false
}

func (l *Latency) ensure() {
	if !l.sorted {
		sort.Slice(l.samples, func(i, j int) bool { return l.samples[i] < l.samples[j] })
		l.sorted = true
	}
}

func (l *Latency) Count() int { return len(l.samples) }

// Quantile returns the q-th percentile using nearest-rank, which is the right
// choice for a small sample: interpolating between two measurements invents a
// latency that was never observed.
func (l *Latency) Quantile(q float64) time.Duration {
	if len(l.samples) == 0 {
		return 0
	}
	l.ensure()
	idx := int(math.Ceil(q*float64(len(l.samples)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(l.samples) {
		idx = len(l.samples) - 1
	}
	return l.samples[idx]
}

func (l *Latency) Mean() time.Duration {
	if len(l.samples) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range l.samples {
		total += d
	}
	return total / time.Duration(len(l.samples))
}

func (l *Latency) Max() time.Duration {
	if len(l.samples) == 0 {
		return 0
	}
	l.ensure()
	return l.samples[len(l.samples)-1]
}

// LatencySummary is the serialisable projection.
type LatencySummary struct {
	Count  int           `json:"count"`
	Mean   time.Duration `json:"mean_ns"`
	P50    time.Duration `json:"p50_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	Max    time.Duration `json:"max_ns"`
	Budget time.Duration `json:"budget_ns,omitempty"`
	// OverBudget counts samples that breached the stage budget. A p99 inside
	// budget with a non-zero breach count is a meaningfully different story
	// from a clean run, and the percentile alone hides it.
	OverBudget int `json:"over_budget"`
}

func (l *Latency) Summary(budget time.Duration) LatencySummary {
	s := LatencySummary{
		Count: l.Count(), Mean: l.Mean(),
		P50: l.Quantile(0.50), P95: l.Quantile(0.95), P99: l.Quantile(0.99),
		Max: l.Max(), Budget: budget,
	}
	if budget > 0 {
		for _, d := range l.samples {
			if d > budget {
				s.OverBudget++
			}
		}
	}
	return s
}

// MacroF1 averages F1 across families, ignoring undefined entries.
//
// Macro rather than micro on purpose: micro-averaging lets a large, easy
// family (benign PII) mask total failure on a small, hard one (encoding-based
// injection), and the small hard one is usually the reason the guardrail
// exists.
func MacroF1(byFamily map[string]Confusion) float64 {
	var sum float64
	var n int
	for _, c := range byFamily {
		if f := c.F1(); !math.IsNaN(f) {
			sum += f
			n++
		}
	}
	if n == 0 {
		return math.NaN()
	}
	return sum / float64(n)
}
