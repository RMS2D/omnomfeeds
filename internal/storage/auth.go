package storage

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// UserRow is the storage-layer shape of a users table row. The auth package
// converts it to its own User type at the boundary.
type UserRow struct {
	ID          string
	IDProvider  string // "google" or "email"
	IDExternal  string // google sub, or normalized email for magic-link users
	Email       string
	DisplayName string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ProUntil    *time.Time
}

// SessionRow is a row from user_sessions. The cookie holds the raw token; we
// only ever store SHA-256(token) in TokenHash.
type SessionRow struct {
	TokenHash  []byte
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	ExpiresAt  time.Time
}

// MagicLinkRow is a row from magic_link_tokens. ConsumeMagicLink atomically
// reads + marks the row used so a token cannot be replayed.
type MagicLinkRow struct {
	TokenHash []byte
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// NewUUID returns a RFC 4122 v4 UUID. SQLite has no native UUID type so we
// store them as TEXT.
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails in practice on platforms we run on.
		return ""
	}
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// --- Users ---

// UpsertUser finds-or-creates a row keyed by (id_provider, id_external).
// Returns the user ID (existing or newly minted).
func (s *Store) UpsertUser(provider, external, email, displayName string) (string, error) {
	var id string
	err := s.db.QueryRow(
		`SELECT id FROM users WHERE id_provider = ? AND id_external = ?`,
		provider, external,
	).Scan(&id)
	if err == nil {
		_, _ = s.db.Exec(
			`UPDATE users SET last_seen_at = CURRENT_TIMESTAMP, email = ?, display_name = COALESCE(NULLIF(?, ''), display_name) WHERE id = ?`,
			email, displayName, id,
		)
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	id = NewUUID()
	_, err = s.db.Exec(
		`INSERT INTO users (id, id_provider, id_external, email, display_name) VALUES (?, ?, ?, ?, ?)`,
		id, provider, external, email, displayName,
	)
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetUserByID fetches a single user row.
func (s *Store) GetUserByID(id string) (*UserRow, error) {
	var u UserRow
	var proUntil sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, id_provider, id_external, email, COALESCE(display_name, ''),
		        created_at, last_seen_at, pro_until
		   FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.IDProvider, &u.IDExternal, &u.Email, &u.DisplayName,
		&u.CreatedAt, &u.LastSeenAt, &proUntil)
	if err != nil {
		return nil, err
	}
	if proUntil.Valid {
		u.ProUntil = &proUntil.Time
	}
	return &u, nil
}

// SetProUntil updates the pro_until timestamp; called from the Stripe webhook
// when a subscription is created, renewed, or cancelled.
func (s *Store) SetProUntil(userID string, until time.Time) error {
	_, err := s.db.Exec(`UPDATE users SET pro_until = ? WHERE id = ?`, until, userID)
	return err
}

// DeleteUser hard-deletes a row. ON DELETE CASCADE wipes sessions, settings,
// bookmarks, read state, alerts, etc.
func (s *Store) DeleteUser(userID string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, userID)
	return err
}

// --- Sessions ---

func (s *Store) CreateSession(userID string, tokenHash []byte, userAgent string, ttl time.Duration) error {
	_, err := s.db.Exec(
		`INSERT INTO user_sessions (token_hash, user_id, user_agent, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, userAgent, time.Now().Add(ttl),
	)
	return err
}

// GetSessionByHash returns the session row if found AND not yet expired. An
// expired row returns sql.ErrNoRows so the middleware treats it as no session.
func (s *Store) GetSessionByHash(tokenHash []byte) (*SessionRow, error) {
	var r SessionRow
	err := s.db.QueryRow(
		`SELECT token_hash, user_id, created_at, last_seen_at, COALESCE(user_agent, ''), expires_at
		   FROM user_sessions WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP`,
		tokenHash,
	).Scan(&r.TokenHash, &r.UserID, &r.CreatedAt, &r.LastSeenAt, &r.UserAgent, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	// Touch last_seen_at asynchronously; we don't block the request on it.
	go func() {
		_, _ = s.db.Exec(`UPDATE user_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ?`, tokenHash)
	}()
	return &r, nil
}

// RevokeSession deletes the row keyed by token hash. No-op if not found.
func (s *Store) RevokeSession(tokenHash []byte) error {
	_, err := s.db.Exec(`DELETE FROM user_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// CleanupExpiredSessions removes rows past their expires_at. Called from a
// daily cron-style goroutine in server.go.
func (s *Store) CleanupExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Magic links ---

func (s *Store) CreateMagicLink(tokenHash []byte, email, userAgent string, ttl time.Duration, ipHash []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO magic_link_tokens (token_hash, email, expires_at, user_agent, ip_hash) VALUES (?, ?, ?, ?, ?)`,
		tokenHash, email, time.Now().Add(ttl), userAgent, ipHash,
	)
	return err
}

// ConsumeMagicLink validates + marks-used atomically. Returns the row only
// when found, unexpired, and not already used. Subsequent attempts to use the
// same token return an error.
func (s *Store) ConsumeMagicLink(tokenHash []byte) (*MagicLinkRow, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var r MagicLinkRow
	var usedAt sql.NullTime
	err = tx.QueryRow(
		`SELECT token_hash, email, created_at, expires_at, used_at
		   FROM magic_link_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&r.TokenHash, &r.Email, &r.CreatedAt, &r.ExpiresAt, &usedAt)
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		return nil, errors.New("magic link already used")
	}
	if r.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("magic link expired")
	}
	if _, err := tx.Exec(
		`UPDATE magic_link_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
		tokenHash,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &r, nil
}

// CleanupExpiredMagicLinks drops used or expired rows older than 24h. Called
// from the same cron goroutine as CleanupExpiredSessions.
func (s *Store) CleanupExpiredMagicLinks() (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM magic_link_tokens
		  WHERE expires_at < datetime('now', '-1 day')
		     OR (used_at IS NOT NULL AND used_at < datetime('now', '-1 day'))`,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RecentMagicLinksForEmail counts how many tokens were issued for an email in
// the last N seconds. Used as a coarse rate-limit (one per email per 60s).
func (s *Store) RecentMagicLinksForEmail(email string, since time.Duration) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM magic_link_tokens WHERE email = ? AND created_at > ?`,
		email, time.Now().Add(-since),
	).Scan(&n)
	return n, err
}
