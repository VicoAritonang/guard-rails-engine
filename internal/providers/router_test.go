package providers

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stub struct {
	name string
	err  error
	n    int
}

func (s *stub) Name() string { return s.name }
func (s *stub) Complete(_ context.Context, req Request) (*Response, error) {
	s.n++
	if s.err != nil {
		return nil, s.err
	}
	return &Response{Model: req.Model, Text: s.name + ":" + req.Model}, nil
}

func catalog() *Catalog {
	return &Catalog{Default: "primary", Models: map[string]*Route{
		"primary":   {Alias: "primary", Provider: "a", Model: "m-a", Fallbacks: []string{"secondary"}},
		"secondary": {Alias: "secondary", Provider: "b", Model: "m-b"},
		"orphan":    {Alias: "orphan", Provider: "missing", Model: "x"},
	}}
}

func TestRouterFallsBackOnRetryableError(t *testing.T) {
	a := &stub{name: "a", err: &UpstreamError{StatusCode: 503, Retryable: true, Err: errors.New("down")}}
	b := &stub{name: "b"}
	r, err := NewRouter(RouterOptions{Providers: map[string]Provider{"a": a, "b": b}, Catalog: catalog(), DefaultProvider: "a"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Complete(context.Background(), Request{Model: "primary"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "b" || resp.Route != "secondary" {
		t.Fatalf("served by %s/%s, want b/secondary", resp.Provider, resp.Route)
	}
	if len(resp.Attempts) != 2 || resp.Attempts[0].Status != 503 {
		t.Fatalf("attempts not recorded: %+v", resp.Attempts)
	}
}

// A 400 is the caller's mistake and would be the same mistake everywhere: it
// must neither fall back nor count against the breaker.
func TestRouterDoesNotFallBackOnClientError(t *testing.T) {
	a := &stub{name: "a", err: &UpstreamError{StatusCode: 400, Err: errors.New("bad")}}
	b := &stub{name: "b"}
	r, _ := NewRouter(RouterOptions{Providers: map[string]Provider{"a": a, "b": b}, Catalog: catalog(), DefaultProvider: "a"})
	if _, err := r.Complete(context.Background(), Request{Model: "primary"}); err == nil {
		t.Fatal("expected the 400 to surface")
	}
	if b.n != 0 {
		t.Fatal("fell back on a client error")
	}
}

func TestBreakerOpensThenProbes(t *testing.T) {
	now := time.Unix(0, 0)
	a := &stub{name: "a", err: &UpstreamError{StatusCode: 503, Retryable: true, Err: errors.New("down")}}
	b := &stub{name: "b"}
	r, _ := NewRouter(RouterOptions{
		Providers: map[string]Provider{"a": a, "b": b}, Catalog: catalog(), DefaultProvider: "a",
		Breaker: BreakerOptions{FailureThreshold: 3, Cooldown: 10 * time.Second, Now: func() time.Time { return now }},
	})
	for range 10 {
		if _, err := r.Complete(context.Background(), Request{Model: "primary"}); err != nil {
			t.Fatal(err)
		}
	}
	if a.n != 3 {
		t.Fatalf("primary called %d times; the breaker should stop at 3", a.n)
	}
	if r.CircuitStates()["a:m-a"] != CircuitOpen {
		t.Fatal("circuit should be open")
	}
	now = now.Add(11 * time.Second)
	a.err = nil
	resp, _ := r.Complete(context.Background(), Request{Model: "primary"})
	if resp.Provider != "a" || r.CircuitStates()["a:m-a"] != CircuitClosed {
		t.Fatal("a successful probe should close the circuit")
	}
}

func TestResolve(t *testing.T) {
	r, _ := NewRouter(RouterOptions{Providers: map[string]Provider{"a": &stub{name: "a"}, "b": &stub{name: "b"}},
		Catalog: catalog(), DefaultProvider: "a"})
	if c, _ := r.Resolve("b:openai/gpt-oss-20b"); c[0].Provider != "b" || c[0].Model != "openai/gpt-oss-20b" {
		t.Fatalf("direct addressing: %+v", c)
	}
	if c, _ := r.Resolve("whatever"); c[0].Provider != "a" {
		t.Fatalf("unknown names go to the default provider: %+v", c)
	}
	if _, err := r.Resolve("orphan"); err == nil {
		t.Fatal("a route whose provider is missing must not resolve")
	}
	if len(r.Unavailable()) != 1 {
		t.Fatal("orphan should be listed as unavailable")
	}
}

// The OpenAI SDK reads OPENAI_API_KEY from the environment when no key is
// passed. A Groq client built without its own key would send that credential
// to a third party, so construction must fail instead.
func TestGroqRequiresItsOwnKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-should-never-reach-groq")
	if _, err := NewGroq(OpenAIOptions{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	g, err := NewGroq(OpenAIOptions{APIKey: "gsk_test"})
	if err != nil || g.Name() != "groq" {
		t.Fatalf("groq adapter: %v %v", g, err)
	}
}
