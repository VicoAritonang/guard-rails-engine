package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"
	"time"
)

// Embedder turns text into vectors. Implemented by providers.OpenAIEmbedder;
// declared here so this package does not depend on any vendor SDK.
type Embedder interface {
	Embed(ctx context.Context, texts []string) (vectors [][]float32, tokens int, err error)
	Model() string
}

// Semantic answers a question with the stored answer to a sufficiently similar
// one.
//
// This is the cache with a correctness cost, and the reason it is a separate
// type with its own switch rather than a mode of Exact: "how do I cancel my
// order" and "how do I place my order" are close in embedding space and have
// opposite answers. The threshold trades hit rate against serving a wrong
// answer, and the efficiency experiment measures both sides of that trade on
// near-miss pairs written to collide. Defaults are therefore conservative.
//
// Scope is limited to single-turn requests. A follow-up such as "and in
// Python?" means something different in every conversation, and an embedding
// of the last message alone cannot see that.
type Semantic struct {
	emb       Embedder
	threshold float64
	perBucket int
	ttl       time.Duration
	now       func() time.Time

	mu      sync.RWMutex
	buckets map[string][]semEntry
}

type semEntry struct {
	vec   []float32
	norm  float64
	query string
	entry Entry
}

// SemanticOptions configures a Semantic cache.
type SemanticOptions struct {
	Threshold float64
	PerBucket int
	TTL       time.Duration
}

// NewSemantic returns nil when emb is nil, which every method treats as off.
func NewSemantic(emb Embedder, opts SemanticOptions) *Semantic {
	if emb == nil {
		return nil
	}
	if opts.Threshold <= 0 || opts.Threshold > 1 {
		opts.Threshold = 0.95
	}
	if opts.PerBucket <= 0 {
		opts.PerBucket = 512
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}
	return &Semantic{emb: emb, threshold: opts.Threshold, perBucket: opts.PerBucket, ttl: opts.TTL,
		now: time.Now, buckets: map[string][]semEntry{}}
}

// Bucket partitions entries so similarity is only ever compared within one
// tenant, one model and one system prompt.
func Bucket(tenant, model, system string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + model + "\x00" + system))
	return hex.EncodeToString(sum[:12])
}

// Threshold reports the configured similarity floor.
func (s *Semantic) Threshold() float64 {
	if s == nil {
		return 0
	}
	return s.threshold
}

// Lookup embeds query and returns the most similar live entry above threshold.
// The vector is returned so a miss can be stored without embedding twice.
type Match struct {
	Entry      Entry
	Similarity float64
	Query      string
}

func (s *Semantic) Lookup(ctx context.Context, bucket, query string) (*Match, []float32, int, error) {
	if s == nil {
		return nil, nil, 0, nil
	}
	vecs, tokens, err := s.emb.Embed(ctx, []string{query})
	if err != nil || len(vecs) == 0 {
		return nil, nil, tokens, err
	}
	v := vecs[0]
	m := s.nearest(bucket, v)
	if m != nil && m.Similarity >= s.threshold {
		return m, v, tokens, nil
	}
	return nil, v, tokens, nil
}

// Nearest returns the best candidate regardless of threshold, for experiments
// that sweep the threshold over one set of embeddings.
func (s *Semantic) nearest(bucket string, v []float32) *Match {
	n := norm(v)
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *Match
	for _, e := range s.buckets[bucket] {
		if now.Sub(e.entry.StoredAt) > s.ttl {
			continue
		}
		sim := Cosine(v, n, e.vec, e.norm)
		if best == nil || sim > best.Similarity {
			best = &Match{Entry: e.entry, Similarity: sim, Query: e.query}
		}
	}
	return best
}

// Store records an entry under a precomputed vector.
func (s *Semantic) Store(bucket, query string, vec []float32, e Entry) {
	if s == nil || len(vec) == 0 {
		return
	}
	if e.StoredAt.IsZero() {
		e.StoredAt = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := append(s.buckets[bucket], semEntry{vec: vec, norm: norm(vec), query: query, entry: e})
	if len(list) > s.perBucket {
		list = list[len(list)-s.perBucket:]
	}
	s.buckets[bucket] = list
}

// Cosine similarity with precomputed norms.
func Cosine(a []float32, na float64, b []float32, nb float64) float64 {
	if len(a) != len(b) || na == 0 || nb == 0 {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot / (na * nb)
}

func norm(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	return math.Sqrt(s)
}

// Norm is exported for experiments that compute similarities directly.
func Norm(v []float32) float64 { return norm(v) }
