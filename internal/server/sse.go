package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// streamHub is a tiny broadcast bus for Server-Sent Events. Each connected
// client owns a buffered channel; Broadcast writes a non-blocking signal so a
// slow / dead client never holds up the publisher.
type streamHub struct {
	mu      sync.Mutex
	clients map[chan streamEvent]struct{}
}

type streamEvent struct {
	Kind string // "refresh", "ping"
	Data string // optional payload, currently "{}" placeholder
}

func newStreamHub() *streamHub {
	return &streamHub{clients: make(map[chan streamEvent]struct{})}
}

func (h *streamHub) register() chan streamEvent {
	ch := make(chan streamEvent, 4)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *streamHub) unregister(ch chan streamEvent) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	// Drain so the goroutine writing doesn't block on close.
	go func() {
		for range ch {
		}
	}()
	close(ch)
}

// Broadcast a non-blocking signal to every subscriber. Slow clients miss the
// event rather than holding the publisher; their next /api/articles fetch
// reconciles state anyway.
func (h *streamHub) Broadcast(kind, data string) {
	if data == "" {
		data = "{}"
	}
	ev := streamEvent{Kind: kind, Data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default: // drop on full channel
		}
	}
}

// handleStream is the SSE endpoint. Keeps the response open, writes
// `event: <kind>\ndata: <json>\n\n` lines whenever something interesting fires,
// and emits a 30s keepalive comment so proxies don't time the connection out.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if proxied
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if s.stream == nil {
		http.Error(w, "stream hub not initialised", http.StatusServiceUnavailable)
		return
	}
	ch := s.stream.register()
	defer s.stream.unregister(ch)

	// Initial hello so the client knows the connection is live.
	fmt.Fprintf(w, "event: hello\ndata: {\"v\":\"0.2\"}\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, ev.Data)
			flusher.Flush()
		case <-keepalive.C:
			// SSE comment line per spec - keeps the connection warm.
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
