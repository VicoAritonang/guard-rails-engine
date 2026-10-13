package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Event is one thing the gateway did, streamed to the live console.
type Event struct {
	ID   int64     `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Data any       `json:"data"`
}

// Bus fans gateway events out to live subscribers.
//
// It is an observation channel, not a log of record: subscribers that fall
// behind lose events rather than slow the request path, and the ring buffer
// exists only so a console that connects mid-stream has something to draw.
// Events carry masked text only -- the same payload the provider saw, never the
// raw prompt.
type Bus struct {
	mu   sync.Mutex
	next int64
	ring []Event
	subs map[chan Event]struct{}
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{subs: map[chan Event]struct{}{}} }

// Publish implements mcp.Publisher.
func (b *Bus) Publish(kind string, data any) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	ev := Event{ID: b.next, Kind: kind, At: time.Now().UTC(), Data: data}
	b.ring = append(b.ring, ev)
	if len(b.ring) > 300 {
		b.ring = b.ring[len(b.ring)-300:]
	}
	for ch := range b.subs {
		select {
		case ch <- ev:
		default: // a slow console never slows a request
		}
	}
}

func (b *Bus) subscribe() (chan Event, []Event, func()) {
	ch := make(chan Event, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	recent := append([]Event(nil), b.ring...)
	b.mu.Unlock()
	return ch, recent, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

// handleEvents streams events as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok || s.bus == nil {
		writeError(w, http.StatusNotImplemented, "no_stream", "event streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, recent, cancel := s.bus.subscribe()
	defer cancel()
	write := func(ev Event) bool {
		raw, err := json.Marshal(ev)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Kind, raw); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	fmt.Fprint(w, "retry: 2000\n\n")
	// Replay only the tail, marked as history, so the console can render the
	// recent past without animating it as live traffic.
	if n := len(recent); n > 40 {
		recent = recent[n-40:]
	}
	for _, ev := range recent {
		ev.Kind = "history." + ev.Kind
		if !write(ev) {
			return
		}
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if !write(ev) {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
