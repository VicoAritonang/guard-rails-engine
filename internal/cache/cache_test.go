package cache

import (
	"context"
	"testing"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/core"
)

func TestKeyPartitionsByTenant(t *testing.T) {
	msgs := []core.Message{{Role: core.RoleUser, Content: "what are your opening hours?"}}
	a := Key(KeyInput{Tenant: "acme", Model: "m", Messages: msgs})
	b := Key(KeyInput{Tenant: "globex", Model: "m", Messages: msgs})
	if a == b {
		t.Fatal("two tenants must never share a cache entry")
	}
	if a != Key(KeyInput{Tenant: "acme", Model: "m", Messages: msgs}) {
		t.Fatal("key must be deterministic")
	}
}

func TestExactLRUAndTTL(t *testing.T) {
	c := NewExact(2, time.Minute)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.Put("a", Entry{Text: "A"})
	c.Put("b", Entry{Text: "B"})
	c.Get("a") // a is now most recent
	c.Put("c", Entry{Text: "C"})
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted as least recently used")
	}
	if e, ok := c.Get("a"); !ok || e.Text != "A" {
		t.Fatal("a should survive")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entries must not be served")
	}
}

func TestDisabledCacheIsInert(t *testing.T) {
	var c *Exact
	c.Put("k", Entry{})
	if _, ok := c.Get("k"); ok {
		t.Fatal("nil cache served an entry")
	}
	if NewExact(0, 0).Enabled() {
		t.Fatal("size 0 must disable the cache")
	}
}

type fakeEmb map[string][]float32

func (f fakeEmb) Model() string { return "fake" }
func (f fakeEmb) Embed(_ context.Context, texts []string) ([][]float32, int, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = f[t]
	}
	return out, len(texts), nil
}

func TestSemanticThreshold(t *testing.T) {
	emb := fakeEmb{
		"how do I reset my password": {1, 0, 0},
		"password reset steps?":      {0.98, 0.2, 0},
		"how do I delete my account": {0.6, 0.8, 0},
	}
	s := NewSemantic(emb, SemanticOptions{Threshold: 0.95})
	_, v, _, _ := s.Lookup(context.Background(), "b", "how do I reset my password")
	s.Store("b", "how do I reset my password", v, Entry{Text: "go to settings"})

	if m, _, _, _ := s.Lookup(context.Background(), "b", "password reset steps?"); m == nil {
		t.Fatal("paraphrase above threshold should hit")
	}
	if m, _, _, _ := s.Lookup(context.Background(), "b", "how do I delete my account"); m != nil {
		t.Fatal("a different question must not be served the stored answer")
	}
	if m, _, _, _ := s.Lookup(context.Background(), "other", "password reset steps?"); m != nil {
		t.Fatal("buckets must not leak across tenants or system prompts")
	}
}
