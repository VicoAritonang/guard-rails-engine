package providers

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// FaultOptions describes how a Faulty provider misbehaves.
type FaultOptions struct {
	Name string
	// ErrorRate is the probability that a call fails with a retryable error.
	ErrorRate float64
	// Status is the HTTP status the simulated failure carries (429 or 5xx).
	Status int
	// FailureLatency is how long a failing call takes before it errors. Real
	// outages are rarely fast: a timeout costs its full duration, and that
	// cost is exactly what the circuit breaker exists to stop paying.
	FailureLatency time.Duration
	// Latency is the base latency of a successful call; Jitter is added
	// uniformly on top.
	Latency time.Duration
	Jitter  time.Duration
	// Outage, when set, makes every call fail while it returns true. It takes
	// the virtual-clock time so experiments can script a brown-out window.
	Outage func(now time.Time) bool
	Seed   int64
	// Sleep is injectable so experiments can run on a virtual clock without
	// waiting in real time. Defaults to a context-aware real sleep.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time
}

// Faulty wraps a provider with seeded, reproducible failures. It is the chaos
// half of the resilience experiment: the same seed yields the same failure
// sequence, so "the fallback chain recovers 99% of requests" is a number that
// can be re-derived, not a lucky run.
type Faulty struct {
	inner Provider
	opts  FaultOptions
	mu    sync.Mutex
	rng   *rand.Rand
	Calls int
}

func NewFaulty(inner Provider, opts FaultOptions) *Faulty {
	if opts.Status == 0 {
		opts.Status = 503
	}
	if opts.Sleep == nil {
		opts.Sleep = func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return nil
			}
			select {
			case <-time.After(d):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Faulty{inner: inner, opts: opts, rng: rand.New(rand.NewSource(opts.Seed))}
}

func (f *Faulty) Name() string {
	if f.opts.Name != "" {
		return f.opts.Name
	}
	return f.inner.Name()
}

func (f *Faulty) Complete(ctx context.Context, req Request) (*Response, error) {
	f.mu.Lock()
	f.Calls++
	fail := f.rng.Float64() < f.opts.ErrorRate
	jitter := time.Duration(0)
	if f.opts.Jitter > 0 {
		jitter = time.Duration(f.rng.Int63n(int64(f.opts.Jitter)))
	}
	f.mu.Unlock()

	if f.opts.Outage != nil && f.opts.Outage(f.opts.Now()) {
		fail = true
	}
	if fail {
		if err := f.opts.Sleep(ctx, f.opts.FailureLatency); err != nil {
			return nil, err
		}
		return nil, &UpstreamError{StatusCode: f.opts.Status, Retryable: true,
			Err: errors.New("injected fault")}
	}
	if err := f.opts.Sleep(ctx, f.opts.Latency+jitter); err != nil {
		return nil, err
	}
	return f.inner.Complete(ctx, req)
}
