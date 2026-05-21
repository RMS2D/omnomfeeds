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
	"os"
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

// trustedProxyCIDRs is the allow-list of network prefixes whose
// X-Forwarded-For headers we honour. Configured via TRUSTED_PROXY_CIDR
// env var (comma-separated CIDRs); defaults to loopback only. If a
// request arrives from outside this set, the XFF header is IGNORED and
// we use the actual TCP source address. Stops spoofed XFF from
// bypassing rate limits or anonymising magic-link floods when the
// service is ever reached directly (local dev, debug deploys, mistake).
var trustedProxyCIDRs = parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDR"))

func parseTrustedProxyCIDRs(env string) []*net.IPNet {
	raw := env
	if raw == "" {
		raw = "127.0.0.0/8,::1/128"
	}
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func remoteIsTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the originating client IP. The X-Forwarded-For header
// is consulted ONLY when the request arrived from a trusted proxy
// (TRUSTED_PROXY_CIDR env var, defaults to loopback). Otherwise we use
// the direct TCP source. Without this, a client sending
// `X-Forwarded-For: 1.2.3.4` on each request can bypass per-IP rate
// limits and anonymise magic-link rate-limiting.
func clientIP(r *http.Request) string {
	if remoteIsTrustedProxy(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.Index(xff, ","); comma > 0 {
				xff = xff[:comma]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
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
