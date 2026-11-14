package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.vicoworks.com/guard-rails-engine/internal/experiment"
)

// runLoadgen drives realistic mixed traffic through a running gateway so the
// dashboards, traces and logs have something to show: support questions (many
// repeated, so the cache earns its keep), PII that must be masked, and attacks
// from the held-out and ASR sets.
func runLoadgen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("loadgen", flag.ContinueOnError)
	target := fs.String("target", "http://localhost:8080", "gateway base URL")
	n := fs.Int("requests", 150, "total requests")
	rps := fs.Float64("rps", 1, "requests per second")
	models := fs.String("models", "gpt-4.1-nano,gpt-oss-20b", "catalog aliases to spread traffic across")
	data := fs.String("datasets", "experiments/datasets", "dataset directory")
	key := fs.String("api-key", "", "gateway API key, if auth is enabled")
	seed := fs.Int64("seed", 1, "random seed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type item struct{ kind, text string }
	var pool []item
	faq, err := experiment.ReadJSONL[experiment.FAQGroup](filepath.Join(*data, "cache_workload.jsonl"))
	if err != nil {
		return err
	}
	for _, g := range faq {
		for range 4 { // weight: repeated questions dominate real support traffic
			pool = append(pool, item{"faq", g.Canonical})
		}
		for _, p := range g.Paraphrases {
			pool = append(pool, item{"faq", p})
		}
	}
	det, _ := experiment.ReadJSONL[experiment.DetectionCase](filepath.Join(*data, "heldout_detection.jsonl"))
	for _, c := range det {
		pool = append(pool, item{c.Label, c.Text})
	}
	asr, _ := experiment.ReadJSONL[experiment.ASRCase](filepath.Join(*data, "asr.jsonl"))
	for _, c := range asr {
		pool = append(pool, item{c.Kind, c.Text})
	}
	pii, _ := experiment.ReadJSONL[experiment.PIICase](filepath.Join(*data, "pii_tasks.jsonl"))
	for _, c := range pii {
		pool = append(pool, item{"pii", c.Text})
	}

	ms := splitList(*models)
	rng := rand.New(rand.NewSource(*seed))
	client := &http.Client{Timeout: 90 * time.Second}
	tick := time.NewTicker(time.Duration(float64(time.Second) / *rps))
	defer tick.Stop()

	var mu sync.Mutex
	counts := map[string]int{}
	var wg sync.WaitGroup
	fmt.Printf("loadgen: %d requests at %.1f rps to %s (%d prompts in pool)\n", *n, *rps, *target, len(pool))
	for i := 0; i < *n; i++ {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case <-tick.C:
		}
		it := pool[rng.Intn(len(pool))]
		model := ms[rng.Intn(len(ms))]
		tenant := []string{"acme", "globex", "initech"}[rng.Intn(3)]
		wg.Add(1)
		go func(i int, it item, model, tenant string) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{
				"model": model, "tenant": tenant, "system": experiment.TargetSystemPrompt, "max_tokens": 300,
				"messages": []map[string]string{{"role": "user", "content": it.text}},
				"meta":     map[string]any{"canary_token": experiment.Canary},
			})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(*target, "/")+"/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if *key != "" {
				req.Header.Set("Authorization", "Bearer "+*key)
			}
			outcome := "error"
			resp, err := client.Do(req)
			if err == nil {
				var out struct {
					Guardrails struct {
						Cache string `json:"cache"`
					} `json:"guardrails"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&out)
				resp.Body.Close()
				switch {
				case resp.StatusCode == 200 && strings.HasPrefix(out.Guardrails.Cache, "hit"):
					outcome = "200 cached"
				case resp.StatusCode == 200:
					outcome = "200 served"
				case resp.StatusCode == 422:
					outcome = "422 blocked"
				default:
					outcome = fmt.Sprintf("%d", resp.StatusCode)
				}
			}
			mu.Lock()
			counts[it.kind+" → "+outcome]++
			mu.Unlock()
			if (i+1)%25 == 0 {
				fmt.Printf("  %d sent\n", i+1)
			}
		}(i, it, model, tenant)
	}
	wg.Wait()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("outcomes by traffic type:")
	for _, k := range keys {
		fmt.Printf("  %-32s %d\n", k, counts[k])
	}
	return nil
}
