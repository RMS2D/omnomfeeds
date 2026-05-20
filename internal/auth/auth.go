// Package auth handles Google OAuth login and session middleware for the
// hosted-mode deployment. Self-host installs never import or call into here.
//
// Flow:
//   1. GET  /auth/google    -> redirect to Google's consent screen
//   2. GET  /auth/callback  -> exchange code for ID token, upsert user, set cookie
//   3. POST /auth/logout    -> invalidate session, clear cookie
//   4. middleware: every /api/me/* and Pro-gated endpoint validates the cookie
//      and resolves *User into request context.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// User mirrors the users table row that the rest of the server cares about.
type User struct {
	ID          string
	Email       string
	DisplayName string
	ProUntil    *time.Time
}

// IsPro returns whether the user's Pro subscription is currently active.
func (u *User) IsPro() bool {
	return u != nil && u.ProUntil != nil && u.ProUntil.After(time.Now())
}

// Session is a server-side record of an authenticated browser. The cookie
// holds the unhashed token; the DB holds the SHA-256 hash.
type Session struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

// Handler bundles the OAuth handlers and middleware that the server mounts.
// Built once at startup from config.HostedConfig + the storage.Store.
type Handler struct {
	cfg   config.HostedConfig
	store *storage.Store
}

// NewHandler returns a Handler ready to mount onto an http.ServeMux. It
// returns an error if hosted mode is enabled but the required credentials
// (Google client ID + secret + redirect URL + session secret) are missing.
func NewHandler(cfg config.HostedConfig, store *storage.Store) (*Handler, error) {
	if !cfg.Enabled {
		return nil, errors.New("hosted mode not enabled")
	}
	if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
		return nil, errors.New("google oauth credentials not set")
	}
	if cfg.OAuthRedirectURL == "" {
		return nil, errors.New("oauth redirect url not set")
	}
	if cfg.SessionSecret == "" {
		return nil, errors.New("session secret not set")
	}
	return &Handler{cfg: cfg, store: store}, nil
}

// Mount attaches the auth routes to a mux. Routes:
//   GET  /auth/google
//   GET  /auth/callback
//   POST /auth/logout
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/auth/google", h.handleGoogleStart)
	mux.HandleFunc("/auth/callback", h.handleGoogleCallback)
	mux.HandleFunc("/auth/logout", h.handleLogout)
}

// handleGoogleStart redirects the browser to Google's consent screen with a
// random state parameter saved in a short-lived signed cookie for CSRF
// protection. Real implementation lands in the next batch.
func (h *Handler) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// handleGoogleCallback exchanges the code Google sends us for an ID token,
// extracts the user's stable provider ID + email, upserts a users row,
// issues a session, and sets the session cookie before redirecting back
// to the app root.
func (h *Handler) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// handleLogout invalidates the current session and clears the cookie.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// Middleware wraps an http.Handler with a session resolver. If a valid
// session cookie is present, the User is attached to the request context
// via WithUser; otherwise the next handler runs with no user attached.
// Endpoints that REQUIRE a user should call RequireUser instead.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real session lookup lands in the next batch. For now the wrapped
		// handler runs untouched.
		next.ServeHTTP(w, r)
	})
}

// RequireUser is a middleware that returns 401 when no user is in context.
// Wraps the Pro-gated endpoints (/api/me/*, /api/alerts/*, etc.).
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePro is RequireUser plus a Pro-active check. Returns 402 when the
// authed user is not on a Pro plan.
func RequirePro(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if !u.IsPro() {
			http.Error(w, "pro subscription required", http.StatusPaymentRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- request context helpers ---

type ctxKey int

const userKey ctxKey = 1

// WithUser stamps the User onto a request context. Used by the middleware
// after a successful session lookup.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// UserFromContext returns the User stamped onto ctx, or nil when not present.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userKey).(*User)
	return u
}

// --- token + hashing helpers ---

// newSessionToken returns a 32-byte random token b64-encoded for the cookie.
// The session row stores SHA-256(token); never the raw token.
func newSessionToken() (token string, hash []byte, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", nil, err
	}
	token = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)
	sum := sha256.Sum256(buf)
	return token, sum[:], nil
}
