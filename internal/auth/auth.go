// Package auth handles login + session middleware for the hosted-mode
// deployment. Self-host installs never import or call into here.
//
// Two login methods, both producing a row in users:
//
//   Google OAuth (one-click):
//     GET  /auth/google           -> redirect to Google's consent screen
//     GET  /auth/callback         -> exchange code, upsert user, set session cookie
//
//   Magic link (email-only, no password):
//     POST /auth/magic            -> body {email}; we send a one-time link
//     GET  /auth/magic/verify     -> ?t=<token>; validate, upsert, set cookie
//
//   Shared:
//     POST /auth/logout           -> invalidate session, clear cookie
//
//   Middleware:
//     every /api/me/* and Pro-gated endpoint validates the session cookie
//     and resolves *User into request context.
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

// --- Google OAuth ---

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

// --- Magic link (email) ---
//
// Flow:
//   1. Client POSTs {email} to /auth/magic.
//   2. We rate-limit to one outbound email per (address, 60s).
//   3. Generate 32-byte token; store sha256(token) + email + expires_at
//      (15min) in magic_link_tokens.
//   4. Send the user an email with a link to
//      https://omnomfeeds.com/auth/magic/verify?t=<raw_token>
//   5. User clicks. Server hashes incoming token, looks up the row, checks
//      expires_at + used_at, marks used, upserts a users row with
//      id_provider="email" + id_external=email, issues a session cookie.
//
// We deliberately do not reveal whether the email exists. /auth/magic
// returns the same response for unknown vs. known emails.

// handleMagicRequest accepts {email} and emails the user a sign-in link.
// Returns 202 on accepted, regardless of whether the email was rate-limited
// or unknown, so callers can't enumerate accounts.
func (h *Handler) handleMagicRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// handleMagicVerify validates the one-time token from the email link and
// promotes the visitor to a logged-in session.
func (h *Handler) handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// --- Shared ---

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
