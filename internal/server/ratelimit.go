// ratelimit.go - simple per-IP sliding-window limiter used to cap AI
// endpoints. Goal: prevent a scraper / abuser from blowing through the
// Anthropic budget by hammering /api/digest force-refresh or /explain
// endpoints. Cache mitigates most of it; this is the second line.
//
// Not a real DDoS shield - that's Cloudflare / Caddy's job. This is
// just a cost guardrail: each IP can burn N AI calls per minute, no
// more. Beyond that returns 429.
//
// Storage is in-memory (sync.Map) with a tiny background sweeper.
// Tracks request timestamps per IP+route bucket. No persistence -
// restart clears the window, which is fine.

package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
	limit   int           // max requests per window
	window  time.Duration // sliding window length
}

// newRateLimiter returns a limiter with the given per-bucket cap.
func newRateLimiter(perWindow int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string][]time.Time),
		limit:   perWindow,
		window:  window,
	}
	go rl.sweep()
	return rl
}

// allow records the call and reports whether it's permitted.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	hist := rl.buckets[key]
	// Drop expired entries (linear scan; bucket length stays small at
	// any reasonable rate).
	keep := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= rl.limit {
		rl.buckets[key] = keep
		return false
	}
	keep = append(keep, now)
	rl.buckets[key] = keep
	return true
}

// sweep periodically evicts buckets that have gone idle so the map
// doesn't grow unbounded under churned-IP traffic.
func (rl *rateLimiter) sweep() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for k, hist := range rl.buckets {
			any := false
			for _, ts := range hist {
				if ts.After(cutoff) {
					any = true
					break
				}
			}
			if !any {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP pulls the originating client IP, preferring the X-Forwarded-
// For first hop when present (Caddy in front of the service sets it).
// Falls back to RemoteAddr's host portion.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma > 0 {
			xff = xff[:comma]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// aiRateLimit wraps an HTTP handler with a per-IP rate limiter scoped
// to a logical bucket (the route family). On exceed it returns 429
// with a Retry-After hint and a plain-text body explaining the cap.
func (s *Server) aiRateLimit(bucket string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := bucket + "|" + clientIP(r)
		if !s.aiLimiter.allow(key) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit: too many AI calls per minute from this IP","retry_after_s":60}`))
			return
		}
		h.ServeHTTP(w, r)
	})
}
