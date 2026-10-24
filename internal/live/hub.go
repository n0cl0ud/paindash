// Package live fans out events to the browsers connected to /api/stream.
package live

import (
	"context"
	"sync"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// Message is either a live event or an invalidation telling the UI to refetch.
type Message struct {
	Event      *model.LiveEvent
	Invalidate []string
}

var allScopes = []string{"summary", "findings", "workloads"}

type subscriber struct {
	env string
	ch  chan Message
}

type Hub struct {
	mu    sync.Mutex
	subs  map[*subscriber]struct{}
	dirty map[string]bool // envs to invalidate at the next flush
}

func NewHub() *Hub {
	return &Hub{subs: map[*subscriber]struct{}{}, dirty: map[string]bool{}}
}

// Subscribe registers a client for one env. The returned func unsubscribes.
func (h *Hub) Subscribe(env string) (<-chan Message, func()) {
	s := &subscriber{env: env, ch: make(chan Message, 64)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		delete(h.subs, s)
		h.mu.Unlock()
	}
}

func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Publish sends an event to the clients of its env right away.
func (h *Hub) Publish(ev *model.LiveEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if ev.Env == model.AllEnvs || ev.Env == s.env {
			send(s, Message{Event: ev})
		}
	}
	h.dirty[ev.Env] = true
}

// Invalidate asks the clients of envs to refetch. Calls are coalesced and
// flushed once per second by Run, so a burst of writes costs one refetch.
func (h *Hub) Invalidate(envs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range envs {
		h.dirty[e] = true
	}
}

func (h *Hub) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.flush()
		}
	}
}

func (h *Hub) flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dirty) == 0 {
		return
	}
	for s := range h.subs {
		if h.dirty[model.AllEnvs] || h.dirty[s.env] {
			send(s, Message{Invalidate: allScopes})
		}
	}
	clear(h.dirty)
}

// send never blocks: a client too slow to drain 64 messages misses some and
// catches up with the next invalidation.
func send(s *subscriber, m Message) {
	select {
	case s.ch <- m:
	default:
	}
}
