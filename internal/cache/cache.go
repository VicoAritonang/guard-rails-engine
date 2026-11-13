// Package cache stores upstream completions so a repeated question is not paid
// for twice.
//
// Three properties make this safe to put in a guardrail gateway, and each is a
// mistake a naive response cache makes:
//
//  1. Keys are computed over the MASKED payload. The inbound stage has already
//     replaced PII with vault placeholders, and those placeholders are an HMAC
//     of the value, so the same email produces the same key -- but the cache
//     never holds the email. A cache keyed on raw prompts is a second copy of
//     every secret users ever typed.
//  2. Entries hold the RAW upstream completion, before the outbound stage. A
//     hit is replayed through the outbound guards with the current policy and
//     the current request's vault, so a rule tightened after the entry was
//     written still applies, and placeholders restore against this caller's
//     values rather than whoever asked first.
//  3. Keys are partitioned by tenant. Two tenants asking the same question get
//     two entries, because a shared entry would let one tenant observe whether
//     another had asked it -- a cross-tenant side channel.
package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// Entry is a cached upstream completion.
type Entry struct {
	Text       string     `json:"text"`
	Model      string     `json:"model"`
	Provider   string     `json:"provider,omitempty"`
	Route      string     `json:"route,omitempty"`
	StopReason string     `json:"stop_reason,omitempty"`
	Usage      core.Usage `json:"usage"`
	// CostUSD is what the original call cost: the amount a hit saves.
	CostUSD float64 `json:"cost_usd"`
	// LatencyMS is how long the original call took: the time a hit saves.
	LatencyMS int64     `json:"latency_ms"`
	StoredAt  time.Time `json:"stored_at"`
}

// KeyInput is everything that can change a completion. Anything left out of
// the key is a way for two different questions to share an answer.
type KeyInput struct {
	Tenant    string         `json:"tenant"`
	Model     string         `json:"model"`
	System    string         `json:"system"`
	Messages  []core.Message `json:"messages"`
	MaxTokens int            `json:"max_tokens"`
}

// Key hashes a KeyInput. JSON encoding of a struct is field-ordered, so the
// hash is stable across processes and replicas.
func Key(in KeyInput) string {
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Exact is a TTL-bounded LRU keyed by Key.
//
// It is per-process on purpose. A shared cache (Redis) is the obvious next
// step for a fleet, but it reintroduces a network dependency into the request
// path and a datastore of model output that must itself be secured. For a
// single replica, or a fleet with sticky routing, in-process gets most of the
// hit rate for none of that.
type Exact struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	ll      *list.List
	items   map[string]*list.Element
	now     func() time.Time
	hits    uint64
	misses  uint64
	evicted uint64
}

type item struct {
	key   string
	entry Entry
}

// NewExact builds a cache. A non-positive size disables it.
func NewExact(maxEntries int, ttl time.Duration) *Exact {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Exact{ttl: ttl, max: maxEntries, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

// Enabled reports whether the cache will store anything.
func (c *Exact) Enabled() bool { return c != nil && c.max > 0 }

// Get returns a live entry and refreshes its recency.
func (c *Exact) Get(key string) (Entry, bool) {
	if !c.Enabled() {
		return Entry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return Entry{}, false
	}
	it := el.Value.(*item)
	if c.now().Sub(it.entry.StoredAt) > c.ttl {
		c.ll.Remove(el)
		delete(c.items, key)
		c.misses++
		return Entry{}, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	return it.entry, true
}

// Put stores an entry, evicting the least recently used one when full.
func (c *Exact) Put(key string, e Entry) {
	if !c.Enabled() {
		return
	}
	if e.StoredAt.IsZero() {
		e.StoredAt = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*item).entry = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&item{key: key, entry: e})
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.items, old.Value.(*item).key)
		c.evicted++
	}
}

// Stats is a point-in-time snapshot.
type Stats struct {
	Entries int    `json:"entries"`
	Hits    uint64 `json:"hits"`
	Misses  uint64 `json:"misses"`
	Evicted uint64 `json:"evicted"`
}

func (c *Exact) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Entries: c.ll.Len(), Hits: c.hits, Misses: c.misses, Evicted: c.evicted}
}
