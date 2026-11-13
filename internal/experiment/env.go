// Package experiment runs the evidence suite: reproducible experiments that
// measure what each layer of the gateway buys, on real models, and write the
// numbers down.
//
// Three rules shape the package:
//
//  1. Experiments use the production code paths. The router, the guard
//     engine, the semantic tier and the caches are built by the same
//     constructors the server uses. An experiment against a re-implementation
//     measures something nobody deploys.
//  2. Every model call is recorded. A call cache on disk (keyed by everything
//     that can change the answer) makes a re-run free and deterministic, and
//     lets the analysis change without re-paying for the data. The recorded
//     upstream latency is replayed with the response, so a re-run reports the
//     latency that was actually measured rather than a disk read.
//  3. Every run is tracked: results, per-trial rows, the configuration and
//     the code version go to experiments/runs/<run-id>/, and a ledger line is
//     appended to experiments/runs/index.jsonl.
package experiment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/config"
	"github.com/VicoAritonang/guard-rails-engine/internal/core"
	"github.com/VicoAritonang/guard-rails-engine/internal/guards"
	"github.com/VicoAritonang/guard-rails-engine/internal/providers"
	"github.com/VicoAritonang/guard-rails-engine/internal/telemetry"
	"github.com/VicoAritonang/guard-rails-engine/internal/tokenize"
)

// Env is what every experiment runs against.
type Env struct {
	Cfg     *config.Config
	Router  *providers.Router
	Pricing *telemetry.Pricing
	Policy  *config.Policy
	Engine  *guards.Engine
	Secret  []byte

	// LLM is the router wrapped with the call cache and rate limiter. Pass it
	// anywhere a providers.Provider is expected, classifiers included.
	LLM *Recorder

	Log io.Writer
}

// NewEnv builds the engine from the balanced policy (or cfg's policy).
func NewEnv(cfg *config.Config, router *providers.Router, pricing *telemetry.Pricing, cacheDir string, fresh bool, log io.Writer) (*Env, error) {
	pol := config.DefaultPolicy()
	if cfg.PolicyPath != "" {
		p, err := config.LoadPolicy(cfg.PolicyPath)
		if err != nil {
			return nil, err
		}
		pol = p
	}
	secret := []byte("experiment-fixed-secret-key")
	eng, err := guards.Build(pol, guards.Deps{Secret: secret, Pricing: pricing})
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = io.Discard
	}
	rec := &Recorder{inner: router, dir: cacheDir, fresh: fresh, limits: map[string]*tokenBucket{}, log: log, pricing: pricing}
	return &Env{Cfg: cfg, Router: router, Pricing: pricing, Policy: pol, Engine: eng, Secret: secret, LLM: rec, Log: log}, nil
}

// Logf writes a progress line.
func (e *Env) Logf(format string, args ...any) {
	fmt.Fprintf(e.Log, format+"\n", args...)
}

// --- recorder ------------------------------------------------------------------

// Recorder wraps the router with a disk call cache, per-upstream rate limiting
// and 429 back-off. It implements providers.Provider.
type Recorder struct {
	inner *providers.Router
	dir   string
	fresh bool
	log   io.Writer

	mu     sync.Mutex
	limits map[string]*tokenBucket

	Calls     int
	CacheHits int
	// CostUSD is spend on calls actually made in this run (replays are free).
	CostUSD float64
	pricing *telemetry.Pricing
}

func (r *Recorder) Name() string { return "recorder" }

type recorded struct {
	Resp      providers.Response `json:"response"`
	LatencyNS int64              `json:"latency_ns"`
	At        time.Time          `json:"recorded_at"`
}

// latencyKey lets a classifier call made through the recorder report the
// recorded upstream latency back to the experiment that issued it.
type latencyKey struct{}

// LatencySink accumulates recorded upstream latency within one context.
type LatencySink struct {
	mu  sync.Mutex
	max time.Duration
	sum time.Duration
}

// WithLatencySink returns a context whose recorder calls report into s.
func WithLatencySink(ctx context.Context, s *LatencySink) context.Context {
	return context.WithValue(ctx, latencyKey{}, s)
}

// Max is the slowest single call, which is the latency of a set of calls
// issued in parallel.
func (s *LatencySink) Max() time.Duration { s.mu.Lock(); defer s.mu.Unlock(); return s.max }

func (r *Recorder) key(req providers.Request) string {
	raw, _ := json.Marshal(struct {
		Model, System, Effort string
		Messages              []core.Message
		MaxTokens             int
		V                     int
	}{req.Model, req.System, req.Effort, req.Messages, req.MaxTokens, 1})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r *Recorder) Complete(ctx context.Context, req providers.Request) (*providers.Response, error) {
	k := r.key(req)
	path := filepath.Join(r.dir, k[:2], k+".json")

	if !r.fresh && r.dir != "" {
		if raw, err := os.ReadFile(path); err == nil {
			var rec recorded
			if json.Unmarshal(raw, &rec) == nil {
				r.mu.Lock()
				r.CacheHits++
				r.mu.Unlock()
				resp := rec.Resp
				resp.Latency = time.Duration(rec.LatencyNS)
				report(ctx, resp.Latency)
				return &resp, nil
			}
		}
	}

	chain, err := r.inner.Resolve(req.Model)
	if err != nil {
		return nil, err
	}
	limitKey := chain[0].Provider + ":" + chain[0].Model
	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = chain[0].MaxTokens
	}
	cost := tokenize.Estimate(req.System) + maxTok + 16
	for _, m := range req.Messages {
		cost += tokenize.Estimate(m.Content) + 4
	}

	var resp *providers.Response
	for attempt := 0; ; attempt++ {
		r.bucket(limitKey, chain[0].Provider).wait(ctx, cost)
		resp, err = r.inner.Complete(ctx, req)
		var ue *providers.UpstreamError
		if err == nil || attempt >= 6 || !errors.As(err, &ue) || !ue.Retryable {
			break
		}
		backoff := time.Duration(10*(attempt+1)) * time.Second
		fmt.Fprintf(r.log, "  rate limited on %s; backing off %s\n", limitKey, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.Calls++
	if r.pricing != nil {
		r.CostUSD += r.pricing.Cost(resp.Model, resp.Usage)
	}
	r.mu.Unlock()
	report(ctx, resp.Latency)

	if r.dir != "" {
		if raw, err := json.Marshal(recorded{Resp: *resp, LatencyNS: int64(resp.Latency), At: time.Now().UTC()}); err == nil {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			_ = os.WriteFile(path, raw, 0o644)
		}
	}
	return resp, nil
}

func report(ctx context.Context, d time.Duration) {
	if s, ok := ctx.Value(latencyKey{}).(*LatencySink); ok {
		s.mu.Lock()
		s.sum += d
		if d > s.max {
			s.max = d
		}
		s.mu.Unlock()
	}
}

// bucket returns the tokens-per-minute limiter for one upstream model.
//
// Groq's free tier allows 8,000 tokens per minute per model and counts the
// requested max_completion_tokens against it before generating, so the
// limiter charges the same estimate. OpenAI's limits are orders of magnitude
// higher and get a generous bucket that only smooths bursts.
func (r *Recorder) bucket(key, provider string) *tokenBucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.limits[key]
	if !ok {
		perMin := 200_000.0
		if provider == "groq" {
			perMin = 7_000
			if strings.Contains(key, "prompt-guard") {
				perMin = 14_000 // Prompt Guard's Groq limit is 15k tokens/min
			}
		}
		b = &tokenBucket{rate: perMin / 60, capacity: perMin, tokens: perMin, last: time.Now()}
		r.limits[key] = b
	}
	return b
}

type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	capacity float64
	tokens   float64
	last     time.Time
}

func (b *tokenBucket) wait(ctx context.Context, cost int) {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens = min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
		c := min(float64(cost), b.capacity)
		if b.tokens >= c {
			b.tokens -= c
			b.mu.Unlock()
			return
		}
		need := time.Duration((c - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()
		select {
		case <-time.After(need):
		case <-ctx.Done():
			return
		}
	}
}

// --- helpers --------------------------------------------------------------------

// ReadJSONL decodes one value per line.
func ReadJSONL[T any](path string) ([]T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []T
	for i, line := range splitLines(string(raw)) {
		if line == "" {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ParallelDo runs fn over n items with bounded concurrency, preserving order.
func ParallelDo(ctx context.Context, n, workers int, fn func(ctx context.Context, i int)) {
	if workers <= 0 {
		workers = 4
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(ctx, i)
		}(i)
	}
	wg.Wait()
}
