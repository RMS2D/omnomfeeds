package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	sessionCookieName = "omnom_session"
	sessionTTL        = 30 * 24 * time.Hour
)

// setSessionCookie writes the cookie that carries the raw session token.
// Secure + HttpOnly so JS can't read it. SameSite=Lax so magic-link clicks
// from email survive the redirect.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the cookie client-side.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// tokenFromCookie decodes the base64 token in the session cookie.
// Returns the raw bytes and the SHA-256 hash for DB lookup.
func tokenFromRequest(r *http.Request) (raw, hash []byte, ok bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, false
	}
	b, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(c.Value)
	if err != nil || len(b) != 32 {
		return nil, nil, false
	}
	sum := sha256.Sum256(b)
	return b, sum[:], true
}

// remoteIP extracts the best-effort client IP, preferring X-Forwarded-For
// from Caddy. Used only as input to a SHA-256 fingerprint for rate-limiting
// magic link issuance, never logged in plaintext.
// remoteIP returns the originating IP, honouring X-Forwarded-For only
// when the request came in through a trusted proxy CIDR
// (TRUSTED_PROXY_CIDR env var, defaults to loopback). Without this, a
// magic-link flood can spoof XFF on each request to evade the per-IP
// cap when the service is ever reachable directly (local dev exposed
// publicly, debug deploys, mistake). Function and CIDR set duplicated
// in server/ratelimit.go to avoid an auth->server import cycle.
func remoteIP(r *http.Request) string {
	if authRemoteIsTrustedProxy(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var authTrustedProxyCIDRs = func() []*net.IPNet {
	raw := os.Getenv("TRUSTED_PROXY_CIDR")
	if raw == "" {
		raw = "127.0.0.0/8,::1/128"
	}
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func authRemoteIsTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range authTrustedProxyCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hashIP returns SHA-256(ip) so logs / DB rows don't carry plaintext IPs.
func hashIP(ip string) []byte {
	sum := sha256.Sum256([]byte(ip))
	return sum[:]
}
