// Package auth handles login + session middleware for the hosted-mode
// deployment. Self-host installs never import or call into here.
//
// Two login methods, both producing a row in users:
//
//	Google OAuth (one-click):
//	  GET  /auth/google           -> redirect to Google's consent screen
//	  GET  /auth/callback         -> exchange code, upsert user, set session cookie
//
//	Magic link (email-only, no password):
//	  POST /auth/magic            -> body {email}; we send a one-time link
//	  GET  /auth/magic/verify     -> ?t=<token>; validate, upsert, set cookie
//
//	Shared:
//	  POST /auth/logout           -> invalidate session, clear cookie
//
//	Middleware:
//	  every /api/me/* and Pro-gated endpoint validates the session cookie
//	  and resolves *User into request context.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
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
	IsAdmin     bool
}

// IsPro: admins get Pro at runtime but stay NULL in pro_until,
// so the dashboard's paid-subscriber metric remains accurate.
func (u *User) IsPro() bool {
	if u == nil {
		return false
	}
	if u.IsAdmin {
		return true
	}
	return u.ProUntil != nil && u.ProUntil.After(time.Now())
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
// returns an error if hosted mode is enabled but the credentials it needs
// are missing. Magic link works without Google OAuth configured (and vice
// versa), but at least one login path must be usable.
func NewHandler(cfg config.HostedConfig, store *storage.Store) (*Handler, error) {
	if !cfg.Enabled {
		return nil, errors.New("hosted mode not enabled")
	}
	if cfg.OAuthRedirectURL == "" {
		return nil, errors.New("oauth redirect url not set")
	}
	if cfg.SessionSecret == "" {
		return nil, errors.New("session secret not set")
	}
	googleOK := cfg.GoogleClientID != "" && cfg.GoogleClientSecret != ""
	magicOK := cfg.ResendAPIKey != ""
	if !googleOK && !magicOK {
		return nil, errors.New("no login method usable: set Google OAuth creds OR Resend API key (preferably both)")
	}
	return &Handler{cfg: cfg, store: store}, nil
}

// Mount attaches the auth routes to a mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	if h.cfg.GoogleClientID != "" {
		mux.HandleFunc("/auth/google", h.handleGoogleStart)
		mux.HandleFunc("/auth/callback", h.handleGoogleCallback)
	}
	if h.cfg.ResendAPIKey != "" {
		mux.HandleFunc("/auth/magic", h.handleMagicRequest)
		mux.HandleFunc("/auth/magic/verify", h.handleMagicVerify)
	}
	mux.HandleFunc("/auth/logout", h.handleLogout)
}

// Google OAuth handlers live in google.go. Magic-link handlers in magic.go.

// handleLogout revokes the current session and clears the cookie. POST-only so
// a third-party page with an <a href="/auth/logout"> link can't log users out.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, sum, ok := tokenFromRequest(r); ok {
		_ = h.store.RevokeSession(sum)
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Middleware resolves session via cookie then bearer; stamps user
// on context if found. Endpoints needing auth call RequireUser.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := h.resolveUser(r); u != nil {
			ctx := WithUser(r.Context(), u)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveUser tries cookie session first, then Authorization: Bearer.
// Returns nil on every failure (no user attached, anonymous flow).
func (h *Handler) resolveUser(r *http.Request) *User {
	if u := h.userFromCookie(r); u != nil {
		return u
	}
	return h.userFromBearer(r)
}

func (h *Handler) userFromCookie(r *http.Request) *User {
	_, sum, ok := tokenFromRequest(r)
	if !ok {
		return nil
	}
	sess, err := h.store.GetSessionByHash(sum)
	if err != nil {
		return nil
	}
	row, err := h.store.GetUserByID(sess.UserID)
	if err != nil {
		return nil
	}
	return h.userFromRow(row)
}

func (h *Handler) userFromBearer(r *http.Request) *User {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return nil
	}
	raw := strings.TrimSpace(authz[len("Bearer "):])
	if raw == "" {
		return nil
	}
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return nil
	}
	sum := sha256.Sum256(decoded)
	row, err := h.store.LookupAPITokenUser(sum[:])
	if err != nil {
		return nil
	}
	return h.userFromRow(row)
}

func (h *Handler) userFromRow(row *storage.UserRow) *User {
	return &User{
		ID:          row.ID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		ProUntil:    row.ProUntil,
		IsAdmin:     h.cfg.IsAdmin(row.Email),
	}
}

// RequireAdmin is a middleware that 403s any non-admin user. Used by the
// global-config mutation endpoints in hosted mode so a normal logged-in
// reader can't reach in and modify watched accounts / API keys / sources.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if !u.IsAdmin {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
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
