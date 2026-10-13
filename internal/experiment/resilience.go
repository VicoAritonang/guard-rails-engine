package experiment

import (
	"context"
	"fmt"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
	"github.com/vicoaritonang/guardrails-engine/internal/providers"
)

// ResilienceOptions configures the fault-injection experiment.
type ResilienceOptions struct {
	Requests      int
	Interval      time.Duration
	OutageStart   time.Duration
	OutageEnd     time.Duration
	PrimaryErrors float64
	Seed          int64
}

// vclock is a virtual clock. Faulty providers "sleep" by advancing it, so a
// 60-second outage scenario runs in milliseconds and is exactly reproducible.
type vclock struct{ t time.Time }

func (c *vclock) Now() time.Time { return c.t }
func (c *vclock) Sleep(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

type resTrial struct {
	Config    string  `json:"config"`
	Seq       int     `json:"seq"`
	AtS       float64 `json:"at_s"`
	OK        bool    `json:"ok"`
	ServedBy  string  `json:"served_by,omitempty"`
	LatencyMS float64 `json:"latency_ms"`
	Attempts  int     `json:"attempts"`
	Skipped   int     `json:"skipped_by_breaker"`
	InOutage  bool    `json:"in_outage"`
}

// RunResilience replays one traffic trace against three gateway
// configurations while the primary provider fails randomly and then goes down
// completely for a window. It uses the production Router and circuit breaker;
// only the providers are simulated.
func RunResilience(ctx context.Context, env *Env, opts ResilienceOptions) (*Result, error) {
	if opts.Requests <= 0 {
		opts.Requests = 600
	}
	if opts.Interval <= 0 {
		opts.Interval = 100 * time.Millisecond
	}
	if opts.OutageEnd <= opts.OutageStart {
		opts.OutageStart, opts.OutageEnd = 20*time.Second, 40*time.Second
	}
	if opts.PrimaryErrors <= 0 {
		opts.PrimaryErrors = 0.05
	}

	type cfgT struct {
		name     string
		fallback bool
		breaker  bool
	}
	configs := []cfgT{
		{"Single provider", false, false},
		{"Fallback chain", true, false},
		{"Fallback + circuit breaker", true, true},
	}
	res := &Result{}
	tbl := Table{Title: "Outcome by configuration", Columns: []string{"Configuration", "Success rate", "Success during outage", "p50", "p95", "p99", "Calls to the dead primary during outage", "Served by backup"}}
	succ := Chart{Title: "Requests served successfully", Format: "pct", Series: []string{"Whole run", "During the outage"}}
	lat := Chart{Title: "Latency percentiles", Format: "ms", Series: []string{"p50", "p95", "p99"}, LowerIsBetter: true,
		Note: "Virtual-clock latency: a failed primary call costs its full 2 s timeout before the fallback fires."}
	succ.Values, lat.Values = [][]float64{{}, {}}, [][]float64{{}, {}, {}}
	type sum struct {
		ok, okOut, out, dead, backup int
		p50, p95, p99                time.Duration
	}
	sums := map[string]sum{}
	for _, c := range configs {
		clk := &vclock{t: time.Unix(1_700_000_000, 0)}
		start := clk.t
		outage := func(now time.Time) bool {
			d := now.Sub(start)
			return d >= opts.OutageStart && d < opts.OutageEnd
		}
		primary := providers.NewFaulty(providers.NewMock(providers.MockOptions{}), providers.FaultOptions{
			Name: "primary", ErrorRate: opts.PrimaryErrors, Status: 503,
			Latency: 400 * time.Millisecond, Jitter: 400 * time.Millisecond, FailureLatency: 2 * time.Second,
			Outage: outage, Seed: opts.Seed, Sleep: clk.Sleep, Now: clk.Now,
		})
		backup := providers.NewFaulty(providers.NewMock(providers.MockOptions{}), providers.FaultOptions{
			Name: "backup", ErrorRate: 0.02, Status: 503,
			Latency: 700 * time.Millisecond, Jitter: 500 * time.Millisecond, FailureLatency: 2 * time.Second,
			Seed: opts.Seed + 1, Sleep: clk.Sleep, Now: clk.Now,
		})
		cat := &providers.Catalog{Default: "chat", Models: map[string]*providers.Route{
			"chat":   {Alias: "chat", Provider: "primary", Model: "p"},
			"backup": {Alias: "backup", Provider: "backup", Model: "b"},
		}}
		if c.fallback {
			cat.Models["chat"].Fallbacks = []string{"backup"}
		}
		r, err := providers.NewRouter(providers.RouterOptions{
			Providers: map[string]providers.Provider{"primary": primary, "backup": backup},
			Catalog:   cat, DefaultProvider: "primary",
			Breaker: providers.BreakerOptions{Disabled: !c.breaker, FailureThreshold: 3, Cooldown: 5 * time.Second, Now: clk.Now},
		})
		if err != nil {
			return nil, err
		}
		var s sum
		var lats []time.Duration
		for i := range opts.Requests {
			// Each request starts at its own scheduled arrival, which models
			// concurrent traffic in a sequential replay: one slow request does
			// not delay the ones behind it.
			arrival := start.Add(time.Duration(i) * opts.Interval)
			clk.t = arrival
			before := clk.t
			inOut := outage(before)
			resp, err := r.Complete(ctx, providers.Request{Model: "chat", Messages: []core.Message{{Role: core.RoleUser, Content: fmt.Sprintf("request %d", i)}}})
			d := clk.t.Sub(before)
			t := resTrial{Config: c.name, Seq: i, AtS: before.Sub(start).Seconds(), OK: err == nil, LatencyMS: float64(d.Milliseconds()), InOutage: inOut}
			var atts []providers.Attempt
			if err == nil {
				t.ServedBy = resp.Provider
				atts = resp.Attempts
			} else if re, ok := err.(*providers.RouteError); ok {
				atts = re.Attempts
			}
			for _, a := range atts {
				if a.Skipped {
					t.Skipped++
				} else {
					t.Attempts++
					if inOut && a.Provider == "primary" {
						s.dead++
					}
				}
			}
			if inOut {
				s.out++
				if t.OK {
					s.okOut++
				}
			}
			if t.OK {
				s.ok++
				if t.ServedBy == "backup" {
					s.backup++
				}
			}
			lats = append(lats, d)
			res.Trials = append(res.Trials, t)
		}
		s.p50, s.p95, s.p99 = Percentile(lats, 0.5), Percentile(lats, 0.95), Percentile(lats, 0.99)
		sums[c.name] = s
		tbl.Rows = append(tbl.Rows, []string{c.name, Pct(Ratio(s.ok, opts.Requests)), Pct(Ratio(s.okOut, s.out)),
			Ms(s.p50), Ms(s.p95), Ms(s.p99), fmt.Sprintf("%d", s.dead), fmt.Sprintf("%d", s.backup)})
		succ.Categories = append(succ.Categories, c.name)
		succ.Values[0] = append(succ.Values[0], Ratio(s.ok, opts.Requests))
		succ.Values[1] = append(succ.Values[1], Ratio(s.okOut, s.out))
		lat.Categories = append(lat.Categories, c.name)
		lat.Values[0] = append(lat.Values[0], float64(s.p50.Milliseconds()))
		lat.Values[1] = append(lat.Values[1], float64(s.p95.Milliseconds()))
		lat.Values[2] = append(lat.Values[2], float64(s.p99.Milliseconds()))
	}
	single, fb, cb := sums["Single provider"], sums["Fallback chain"], sums["Fallback + circuit breaker"]
	res.Headline = []Metric{
		{"Availability, single provider", Pct(Ratio(single.ok, opts.Requests)), "primary down for 20 s of 60 s"},
		{"Availability, fallback + breaker", Pct(Ratio(cb.ok, opts.Requests)), fmt.Sprintf("p95 %s", Ms(cb.p95))},
		{"Dead-primary calls avoided by the breaker", fmt.Sprintf("%d → %d", fb.dead, cb.dead), "during the outage window"},
	}
	res.Findings = []string{
		fmt.Sprintf("A single provider serves %s of traffic through a 20-second outage; a fallback chain serves %s.", Pct(Ratio(single.ok, opts.Requests)), Pct(Ratio(fb.ok, opts.Requests))),
		fmt.Sprintf("Fallback alone still sends every outage request to the dead primary first (%d calls), so each one pays the 2 s timeout: p95 is %s. The circuit breaker stops trying after 3 failures and probes once per cooldown, cutting dead calls to %d and p95 to %s.", fb.dead, Ms(fb.p95), cb.dead, Ms(cb.p95)),
		"The breaker never refuses a request; it only reorders where the request is sent. Availability is the fallback chain's job, latency during an outage is the breaker's.",
	}
	res.Tables = []Table{tbl}
	res.Charts = []Chart{succ, lat}
	res.Notes = []string{
		fmt.Sprintf("%d requests at one per %s (virtual clock); primary has %.0f%% random 503s and is fully down from %s to %s; backup has 2%% random 503s and is slower.", opts.Requests, opts.Interval, opts.PrimaryErrors*100, opts.OutageStart, opts.OutageEnd),
		"The router and circuit breaker are the production implementation; only the providers are simulated (seeded, reproducible).",
		"Breaker: opens after 3 consecutive failures, half-opens after 5 s with a single probe.",
	}
	_ = env
	return res, nil
}
