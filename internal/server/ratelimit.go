// ratelimit.go: per-IP sliding-window cost guardrail on summarizer endpoints.
// In-mem sync.Map with a background sweeper; restart clears the window.

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

// trustedProxyCIDRs: prefixes whose X-Forwarded-For we honour. Defaults to
// loopback. Anything else's XFF is ignored to block spoofed-IP bypasses.
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

// clientIP: returns originating IP. XFF honoured only from trusted proxies
// (TRUSTED_PROXY_CIDR) to block spoofed-IP bypasses of per-IP rate limits.
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
			w.Write([]byte(`{"error":"rate limit: too many summarizer calls per minute from this IP","retry_after_s":60}`))
			return
		}
		h.ServeHTTP(w, r)
	})
}
