package providers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/VicoAritonang/guard-rails-engine/internal/core"
)

// Replay serves recorded responses from a JSONL cassette.
//
// This is what makes an evaluation number trustworthy. Scoring guardrails
// against a live model conflates two sources of variance -- did the detector
// change, or did the model answer differently this time -- and only one of
// them is under the engineer's control. Recording once and replaying forever
// isolates the guardrails, so a change in F1 between two commits is
// attributable to the change in those commits.
//
// It is also how the outbound guards get exercised against real model output
// without a per-run API bill.
type Replay struct {
	mu     sync.RWMutex
	byKey  map[string]*Response
	path   string
	strict bool
}

// cassetteEntry is one recorded exchange.
type cassetteEntry struct {
	Key      string         `json:"key"`
	Model    string         `json:"model"`
	System   string         `json:"system,omitempty"`
	Messages []core.Message `json:"messages"`
	Response struct {
		Text       string     `json:"text"`
		StopReason string     `json:"stop_reason"`
		Usage      core.Usage `json:"usage"`
	} `json:"response"`
}

// NewReplay loads a cassette.
func NewReplay(path string) (*Replay, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: replay requires a cassette path", ErrNotConfigured)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("replay: open cassette: %w", err)
	}
	defer f.Close()

	r := &Replay{byKey: map[string]*Response{}, path: path, strict: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var e cassetteEntry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, fmt.Errorf("replay: %s line %d: %w", path, line, err)
		}
		key := e.Key
		if key == "" {
			key = RequestKey(Request{Model: e.Model, System: e.System, Messages: e.Messages})
		}
		r.byKey[key] = &Response{
			Model:      e.Model,
			Text:       e.Response.Text,
			StopReason: orDefault(e.Response.StopReason, "end_turn"),
			Usage:      e.Response.Usage,
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("replay: read cassette: %w", err)
	}
	if len(r.byKey) == 0 {
		return nil, fmt.Errorf("replay: cassette %s contains no entries", path)
	}
	return r, nil
}

// SetStrict controls what happens on a cassette miss. Strict (the default)
// fails loudly, which is right for CI: a silent fallback would let a changed
// prompt quietly stop being evaluated against the response it was recorded
// with, and the numbers would drift without anyone noticing.
func (r *Replay) SetStrict(strict bool) { r.strict = strict }

func (r *Replay) Name() string { return "replay" }

func (r *Replay) Complete(_ context.Context, req Request) (*Response, error) {
	key := RequestKey(req)
	r.mu.RLock()
	resp, ok := r.byKey[key]
	r.mu.RUnlock()
	if ok {
		clone := *resp
		return &clone, nil
	}
	if r.strict {
		return nil, fmt.Errorf("replay: no cassette entry for key %s (cassette %s, %d entries) -- re-record with `grctl record`",
			key, r.path, len(r.byKey))
	}
	return NewMock(MockOptions{}).Complete(context.Background(), req)
}

// RequestKey is the content hash used to index the cassette.
//
// It covers exactly the fields that change a model's answer: the model name,
// the system prompt, and the ordered conversation. It deliberately excludes
// max_tokens and metadata, so a harmless change to request plumbing does not
// invalidate an entire recorded corpus.
func RequestKey(req Request) string {
	h := sha256.New()
	fmt.Fprintf(h, "model=%s\n", req.Model)
	fmt.Fprintf(h, "system=%s\n", req.System)
	for _, m := range req.Messages {
		fmt.Fprintf(h, "%s=%s\n", m.Role, m.Content)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Recorder wraps a live provider and writes every exchange to a cassette.
type Recorder struct {
	inner Provider
	mu    sync.Mutex
	f     *os.File
	enc   *json.Encoder
}

// NewRecorder starts recording calls made through inner.
func NewRecorder(inner Provider, path string) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("recorder: %w", err)
	}
	return &Recorder{inner: inner, f: f, enc: json.NewEncoder(f)}, nil
}

func (r *Recorder) Name() string { return r.inner.Name() + "+recorder" }

func (r *Recorder) Complete(ctx context.Context, req Request) (*Response, error) {
	resp, err := r.inner.Complete(ctx, req)
	if err != nil {
		return nil, err
	}
	var e cassetteEntry
	e.Key = RequestKey(req)
	e.Model = req.Model
	e.System = req.System
	e.Messages = req.Messages
	e.Response.Text = resp.Text
	e.Response.StopReason = resp.StopReason
	e.Response.Usage = resp.Usage

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.enc.Encode(&e); err != nil {
		return resp, fmt.Errorf("recorder: write: %w", err)
	}
	return resp, nil
}

// Close flushes the cassette.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
