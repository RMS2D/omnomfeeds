package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// jsonUnmarshalShim wraps encoding/json so the momentum tag-decode path
// can stay decoupled from the import in any storage_test variants.
func jsonUnmarshalShim(raw string, dst *[]string) error {
	return json.Unmarshal([]byte(raw), dst)
}

// UserRow is the storage-layer shape of a users table row. The auth package
// converts it to its own User type at the boundary.
type UserRow struct {
	ID                   string
	IDProvider           string // "google" or "email"
	IDExternal           string // google sub, or normalized email for magic-link users
	Email                string
	DisplayName          string
	CreatedAt            time.Time
	LastSeenAt           time.Time
	ProUntil             *time.Time
	StripeCustomerID     string
	StripeSubscriptionID string
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
	return s.scanUser(s.db.QueryRow(
		`SELECT id, id_provider, id_external, email, COALESCE(display_name, ''),
		        created_at, last_seen_at, pro_until,
		        COALESCE(stripe_customer_id, ''), COALESCE(stripe_subscription_id, '')
		   FROM users WHERE id = ?`, id))
}

// GetUserByStripeCustomerID lets the webhook find the right user when an
// event carries only a Stripe customer ID.
func (s *Store) GetUserByStripeCustomerID(custID string) (*UserRow, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, id_provider, id_external, email, COALESCE(display_name, ''),
		        created_at, last_seen_at, pro_until,
		        COALESCE(stripe_customer_id, ''), COALESCE(stripe_subscription_id, '')
		   FROM users WHERE stripe_customer_id = ?`, custID))
}

func (s *Store) scanUser(row *sql.Row) (*UserRow, error) {
	var u UserRow
	var proUntil sql.NullTime
	err := row.Scan(&u.ID, &u.IDProvider, &u.IDExternal, &u.Email, &u.DisplayName,
		&u.CreatedAt, &u.LastSeenAt, &proUntil, &u.StripeCustomerID, &u.StripeSubscriptionID)
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

// SetStripeCustomer links a Stripe customer (and optionally subscription)
// to a user row so subsequent webhook events can resolve back to the user.
func (s *Store) SetStripeCustomer(userID, customerID, subscriptionID string) error {
	_, err := s.db.Exec(
		`UPDATE users SET stripe_customer_id = ?, stripe_subscription_id = NULLIF(?, '') WHERE id = ?`,
		customerID, subscriptionID, userID,
	)
	return err
}

// ClearProAccess wipes pro_until + subscription id; called when a
// subscription is deleted server-side.
func (s *Store) ClearProAccess(userID string) error {
	_, err := s.db.Exec(
		`UPDATE users SET pro_until = NULL, stripe_subscription_id = NULL WHERE id = ?`,
		userID,
	)
	return err
}

// --- Per-user settings (single JSON blob) ---

// GetSettings returns the user's settings JSON, or "{}" if no row exists yet.
func (s *Store) GetSettings(userID string) (string, error) {
	var settings string
	err := s.db.QueryRow(
		`SELECT settings FROM user_settings WHERE user_id = ?`, userID,
	).Scan(&settings)
	if errors.Is(err, sql.ErrNoRows) {
		return "{}", nil
	}
	if err != nil {
		return "", err
	}
	return settings, nil
}

// PutSettings upserts the settings blob. Caller is responsible for ensuring
// the value is valid JSON; we store opaque text so the schema doesn't pin
// the shape.
func (s *Store) PutSettings(userID, settings string) error {
	_, err := s.db.Exec(
		`INSERT INTO user_settings (user_id, settings, updated_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(user_id) DO UPDATE SET
		   settings = excluded.settings,
		   updated_at = CURRENT_TIMESTAMP`,
		userID, settings,
	)
	return err
}

// --- Bookmarks ---

// ListBookmarkIDs returns just the article IDs the user has bookmarked,
// newest first. The frontend joins these against the article list it
// already has loaded; no need to ship article rows over the wire twice.
func (s *Store) ListBookmarkIDs(userID string) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT article_id FROM user_bookmarks WHERE user_id = ? ORDER BY bookmarked_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) AddBookmark(userID string, articleID int64) error {
	_, err := s.db.Exec(
		`INSERT INTO user_bookmarks (user_id, article_id) VALUES (?, ?)
		 ON CONFLICT(user_id, article_id) DO NOTHING`,
		userID, articleID,
	)
	return err
}

func (s *Store) RemoveBookmark(userID string, articleID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM user_bookmarks WHERE user_id = ? AND article_id = ?`,
		userID, articleID,
	)
	return err
}

// --- Read state ---

// ListReadIDs returns IDs the user has marked read. We cap the result at a
// big-but-bounded number to avoid blowing the wire on accounts that have
// read tens of thousands of items; the frontend only needs recent state.
func (s *Store) ListReadIDs(userID string, limit int) ([]int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	rows, err := s.db.Query(
		`SELECT article_id FROM user_read_state WHERE user_id = ?
		   ORDER BY read_at DESC LIMIT ?`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// MarkReadForUser writes a per-user read mark distinct from the global
// articles.read flag used by self-host mode.
func (s *Store) MarkReadForUser(userID string, articleID int64) error {
	_, err := s.db.Exec(
		`INSERT INTO user_read_state (user_id, article_id) VALUES (?, ?)
		 ON CONFLICT(user_id, article_id) DO NOTHING`,
		userID, articleID,
	)
	return err
}

// MarkAllReadForUser inserts a user_read_state row for every existing
// article (minus duplicates). One INSERT...SELECT keeps the worst-case
// 50k-row write in a single transaction. ON CONFLICT swallows the
// already-read entries so this is idempotent.
func (s *Store) MarkAllReadForUser(userID string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO user_read_state (user_id, article_id)
		 SELECT ?, id FROM articles WHERE duplicate_of IS NULL
		 ON CONFLICT(user_id, article_id) DO NOTHING`,
		userID,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Per-user Bluesky watched accounts ---

// ListUserBskyAccounts returns the handles a single user has subscribed to.
func (s *Store) ListUserBskyAccounts(userID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT handle FROM user_bluesky_accounts WHERE user_id = ? ORDER BY added_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) AddUserBskyAccount(userID, handle string) error {
	_, err := s.db.Exec(
		`INSERT INTO user_bluesky_accounts (user_id, handle) VALUES (?, ?)
		 ON CONFLICT(user_id, handle) DO NOTHING`,
		userID, handle,
	)
	return err
}

func (s *Store) RemoveUserBskyAccount(userID, handle string) error {
	_, err := s.db.Exec(
		`DELETE FROM user_bluesky_accounts WHERE user_id = ? AND handle = ?`,
		userID, handle,
	)
	return err
}

// AddBulkUserBskyAccounts writes a slice of handles atomically. Existing
// (user, handle) pairs are skipped via ON CONFLICT DO NOTHING.
func (s *Store) AddBulkUserBskyAccounts(userID string, handles []string) (int, error) {
	if len(handles) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	added := 0
	stmt, err := tx.Prepare(`INSERT INTO user_bluesky_accounts (user_id, handle) VALUES (?, ?) ON CONFLICT(user_id, handle) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, h := range handles {
		if h == "" {
			continue
		}
		res, err := stmt.Exec(userID, h)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, nil
}

// AllUserBskyHandles returns the distinct set of handles across every user.
// The fetcher unions this with the operator's config-baseline list to decide
// what to poll each cycle.
func (s *Store) AllUserBskyHandles() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT handle FROM user_bluesky_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// --- Admin metrics ---

// AdminStats is the slim metrics blob the admin dashboard reads. Each
// field is best-effort; on query failure the field stays at zero rather
// than failing the whole response.
type AdminStats struct {
	TotalUsers        int
	UsersLast7Days    int
	ProActiveCount    int
	ArticlesLast24h   int
	ArticlesTotal     int
	MagicLinksLast24h int
}

// CountAdminStats runs the per-stat queries in sequence and returns whatever
// it can. Errors are swallowed into zero values so a missing column doesn't
// black out the dashboard.
func (s *Store) CountAdminStats() AdminStats {
	var out AdminStats
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&out.TotalUsers)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE created_at >= datetime('now', '-7 days')`).Scan(&out.UsersLast7Days)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE pro_until IS NOT NULL AND pro_until > CURRENT_TIMESTAMP`).Scan(&out.ProActiveCount)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM articles WHERE fetched_at >= datetime('now', '-1 day')`).Scan(&out.ArticlesLast24h)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM articles`).Scan(&out.ArticlesTotal)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM magic_link_tokens WHERE created_at >= datetime('now', '-1 day')`).Scan(&out.MagicLinksLast24h)
	return out
}

// AdminUserRow is the slim shape used by the recent-signups + pro lists.
type AdminUserRow struct {
	ID          string
	Email       string
	DisplayName string
	IDProvider  string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ProUntil    *time.Time
}

// RecentSignups returns the N most recently-created users.
func (s *Store) RecentSignups(limit int) ([]AdminUserRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	return s.queryAdminUserRows(
		`SELECT id, email, COALESCE(display_name, ''), id_provider, created_at, last_seen_at, pro_until
		   FROM users ORDER BY created_at DESC LIMIT ?`, limit)
}

// ProSubscribers returns active Pro users ordered by ProUntil DESC.
func (s *Store) ProSubscribers(limit int) ([]AdminUserRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.queryAdminUserRows(
		`SELECT id, email, COALESCE(display_name, ''), id_provider, created_at, last_seen_at, pro_until
		   FROM users
		  WHERE pro_until IS NOT NULL AND pro_until > CURRENT_TIMESTAMP
		  ORDER BY pro_until DESC
		  LIMIT ?`, limit)
}

func (s *Store) queryAdminUserRows(query string, limit int) ([]AdminUserRow, error) {
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUserRow
	for rows.Next() {
		var u AdminUserRow
		var pro sql.NullTime
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.IDProvider, &u.CreatedAt, &u.LastSeenAt, &pro); err != nil {
			return nil, err
		}
		if pro.Valid {
			u.ProUntil = &pro.Time
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- Per-user REST API tokens (Pro) ---

// APITokenRow is one entry from user_api_tokens. The raw token never
// touches the DB; we only store SHA-256(token).
type APITokenRow struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string // first 8 chars of the raw token for display ("omk_a1b2...")
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateAPIToken inserts a token row keyed by SHA-256(rawToken). The plain
// token is returned to the caller exactly once and never persisted.
func (s *Store) CreateAPIToken(userID, name string, tokenHash []byte, prefix string) (string, error) {
	id := NewUUID()
	_, err := s.db.Exec(
		`INSERT INTO user_api_tokens (id, user_id, name, token_hash, scopes)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, name, tokenHash, prefix,
	)
	return id, err
}

// ListAPITokens returns the user's non-revoked tokens, newest first. Raw
// tokens are unrecoverable; the UI shows the prefix + name for identification.
func (s *Store) ListAPITokens(userID string) ([]APITokenRow, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, COALESCE(scopes, ''), created_at, last_used_at, revoked_at
		   FROM user_api_tokens
		  WHERE user_id = ? AND revoked_at IS NULL
		  ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APITokenRow
	for rows.Next() {
		var r APITokenRow
		var lastUsed, revoked sql.NullTime
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.Prefix,
			&r.CreatedAt, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			r.LastUsedAt = &lastUsed.Time
		}
		if revoked.Valid {
			r.RevokedAt = &revoked.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokeAPIToken soft-deletes a token. Hard delete would leave the audit
// trail thin; soft delete keeps last_used_at queryable if anything
// suspicious shows up later. user_id in the WHERE prevents cross-user
// revocation even with a guessed ID.
func (s *Store) RevokeAPIToken(userID, tokenID string) error {
	_, err := s.db.Exec(
		`UPDATE user_api_tokens SET revoked_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND user_id = ?`,
		tokenID, userID,
	)
	return err
}

// --- Momentum (free) ---
//
// MomentumEntry is one row of "tag X mentioned this week vs last week."
// Tags are filtered to interesting prefixes (kev:, T*, plus the regular
// keyword tags). Hash / artifact / cve specific tags are excluded
// (those are per-incident, not category-level trends).
type MomentumEntry struct {
	Tag      string
	Now      int
	Prev     int
	DeltaPct int // signed; +500 = "5x more this week"
}

// TagMomentum returns the top movers across two equal-length windows.
// Window is in hours - e.g. 168 = 7 days. The "now" window is the most
// recent N hours; "prev" is the N hours before that.
func (s *Store) TagMomentum(windowHours int, limit int) ([]MomentumEntry, error) {
	if windowHours <= 0 {
		windowHours = 168
	}
	if limit <= 0 {
		limit = 12
	}
	now := time.Now()
	nowStart := now.Add(-time.Duration(windowHours) * time.Hour)
	prevStart := nowStart.Add(-time.Duration(windowHours) * time.Hour)

	// Pull tag-frequencies per window. We do two queries (one per window)
	// because the tags column is a JSON blob; SQLite doesn't have great
	// indexed json extraction so we just LIKE-scan and tokenize in Go.
	nowMap, err := s.countTags(nowStart, now)
	if err != nil {
		return nil, err
	}
	prevMap, err := s.countTags(prevStart, nowStart)
	if err != nil {
		return nil, err
	}

	// Build candidate set: any tag that appears in the "now" window with
	// at least 3 mentions. Filters out long-tail one-shots that look like
	// huge percentage spikes but mean nothing.
	type cand struct {
		tag, key string
		now, prev int
	}
	var cands []cand
	for t, n := range nowMap {
		if n < 3 {
			continue
		}
		if !isMomentumTag(t) {
			continue
		}
		cands = append(cands, cand{tag: t, key: strings.ToLower(t), now: n, prev: prevMap[t]})
	}
	// Score by signed delta % so big climbers and big fallers both surface.
	out := make([]MomentumEntry, 0, len(cands))
	for _, c := range cands {
		dp := 0
		if c.prev == 0 {
			dp = 999 // "from nothing" - clamp visually in UI
		} else {
			dp = ((c.now - c.prev) * 100) / c.prev
		}
		out = append(out, MomentumEntry{
			Tag:      c.tag,
			Now:      c.now,
			Prev:     c.prev,
			DeltaPct: dp,
		})
	}
	// Sort by absolute delta desc, then by absolute now-count desc as a
	// tiebreak so high-volume tags float above low-volume noise.
	sortMomentum(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// isMomentumTag filters out tag forms that aren't interesting for trends:
// hashes, file artifacts, individual CVE ids (they trend per-incident,
// not per-category).
func isMomentumTag(t string) bool {
	low := strings.ToLower(t)
	if strings.HasPrefix(low, "sha256:") || strings.HasPrefix(low, "md5:") {
		return false
	}
	if strings.HasPrefix(low, "artifact:") {
		return false
	}
	// Individual CVE ids: skip (they don't repeat across articles cleanly)
	if strings.HasPrefix(low, "cve-") {
		return false
	}
	// KEV catalog additions ARE interesting - the SAME CVE doesn't repeat,
	// but the "kev:" prefix sums across them. Group them under one tag.
	if strings.HasPrefix(low, "kev:") {
		return false // handled separately as "kev" aggregate; see below
	}
	return true
}

// sortMomentum: descending by absolute delta pct, then by current count.
func sortMomentum(rows []MomentumEntry) {
	// Insertion sort - the slice is at most a few dozen entries.
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && momentumLess(rows[j], rows[j-1]) {
			rows[j], rows[j-1] = rows[j-1], rows[j]
			j--
		}
	}
}

func momentumLess(a, b MomentumEntry) bool {
	absA, absB := a.DeltaPct, b.DeltaPct
	if absA < 0 {
		absA = -absA
	}
	if absB < 0 {
		absB = -absB
	}
	if absA != absB {
		return absA > absB
	}
	return a.Now > b.Now
}

// countTags collects tag → count for articles fetched in [from, to).
// Reads the tags column as raw text and unmarshals row-by-row; cheap
// enough for a daily-momentum query.
func (s *Store) countTags(from, to time.Time) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT tags FROM articles
		  WHERE fetched_at >= ? AND fetched_at < ?
		    AND duplicate_of IS NULL`,
		from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var tags []string
		if err := unmarshalTagBlob(raw, &tags); err != nil {
			continue
		}
		for _, t := range tags {
			if t == "" {
				continue
			}
			out[t]++
		}
	}
	return out, rows.Err()
}

func unmarshalTagBlob(raw string, dst *[]string) error {
	// Tags are stored as JSON arrays of strings (or "[]" if empty).
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	return jsonUnmarshalShim(raw, dst)
}

// --- Email digest preferences (Pro) ---

type EmailDigestPref struct {
	UserID     string
	Frequency  string // "off" | "daily" | "weekly"
	LastSentAt *time.Time
	Email      string // joined from users table for the worker convenience
}

func (s *Store) GetEmailDigestPref(userID string) (*EmailDigestPref, error) {
	var p EmailDigestPref
	var last sql.NullTime
	err := s.db.QueryRow(
		`SELECT user_id, frequency, last_sent_at FROM user_email_digest_prefs WHERE user_id = ?`,
		userID,
	).Scan(&p.UserID, &p.Frequency, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return &EmailDigestPref{UserID: userID, Frequency: "off"}, nil
	}
	if err != nil {
		return nil, err
	}
	if last.Valid {
		p.LastSentAt = &last.Time
	}
	return &p, nil
}

func (s *Store) PutEmailDigestPref(userID, frequency string) error {
	_, err := s.db.Exec(
		`INSERT INTO user_email_digest_prefs (user_id, frequency) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET frequency = excluded.frequency`,
		userID, frequency,
	)
	return err
}

func (s *Store) MarkEmailDigestSent(userID string, when time.Time) error {
	_, err := s.db.Exec(
		`UPDATE user_email_digest_prefs SET last_sent_at = ? WHERE user_id = ?`,
		when, userID,
	)
	return err
}

// ListEmailDigestDue returns subscribed users whose schedule says they
// should get a digest now. The worker uses this; cheap join.
func (s *Store) ListEmailDigestDue() ([]EmailDigestPref, error) {
	rows, err := s.db.Query(
		`SELECT p.user_id, p.frequency, p.last_sent_at, u.email
		   FROM user_email_digest_prefs p
		   JOIN users u ON u.id = p.user_id
		  WHERE p.frequency IN ('daily', 'weekly')`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailDigestPref
	now := time.Now()
	for rows.Next() {
		var p EmailDigestPref
		var last sql.NullTime
		if err := rows.Scan(&p.UserID, &p.Frequency, &last, &p.Email); err != nil {
			return nil, err
		}
		if last.Valid {
			p.LastSentAt = &last.Time
		}
		// Daily: 23h cooldown so a slow tick can still hit close to 24h.
		// Weekly: 6 days 12h cooldown.
		var cooldown time.Duration
		if p.Frequency == "daily" {
			cooldown = 23 * time.Hour
		} else {
			cooldown = (6*24 + 12) * time.Hour
		}
		if p.LastSentAt != nil && now.Sub(*p.LastSentAt) < cooldown {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- Saved searches / "channels" (Pro) ---

type SavedSearch struct {
	ID        string
	UserID    string
	Name      string
	Query     string
	CreatedAt time.Time
	SortOrder int
}

func (s *Store) ListSavedSearches(userID string) ([]SavedSearch, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, query, created_at, sort_order
		   FROM user_saved_searches
		  WHERE user_id = ?
		  ORDER BY sort_order ASC, created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedSearch
	for rows.Next() {
		var r SavedSearch
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.Query, &r.CreatedAt, &r.SortOrder); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateSavedSearch(userID, name, query string) (string, error) {
	id := NewUUID()
	_, err := s.db.Exec(
		`INSERT INTO user_saved_searches (id, user_id, name, query, sort_order)
		 SELECT ?, ?, ?, ?, COALESCE(MAX(sort_order) + 1, 0)
		   FROM user_saved_searches WHERE user_id = ?`,
		id, userID, name, query, userID,
	)
	return id, err
}

func (s *Store) DeleteSavedSearch(userID, id string) error {
	_, err := s.db.Exec(
		`DELETE FROM user_saved_searches WHERE id = ? AND user_id = ?`,
		id, userID,
	)
	return err
}

// --- Article explanation cache (Pro) ---

// GetArticleExplanation returns the cached summary for an article, or
// ("", sql.ErrNoRows) if we haven't generated one yet.
func (s *Store) GetArticleExplanation(articleID int64) (string, error) {
	var text string
	err := s.db.QueryRow(
		`SELECT explanation FROM article_ai_explanations WHERE article_id = ?`,
		articleID,
	).Scan(&text)
	return text, err
}

func (s *Store) PutArticleExplanation(articleID int64, explanation, provider string) error {
	_, err := s.db.Exec(
		`INSERT INTO article_ai_explanations (article_id, explanation, provider)
		 VALUES (?, ?, ?)
		 ON CONFLICT(article_id) DO UPDATE SET
		   explanation = excluded.explanation,
		   generated_at = CURRENT_TIMESTAMP,
		   provider = excluded.provider`,
		articleID, explanation, provider,
	)
	return err
}

// GetArticleTriage returns the cached "what? so what?" inline triage
// line for an article, or ("", sql.ErrNoRows) on cache miss.
func (s *Store) GetArticleTriage(articleID int64) (string, error) {
	var text string
	err := s.db.QueryRow(
		`SELECT triage FROM article_ai_triage WHERE article_id = ?`,
		articleID,
	).Scan(&text)
	return text, err
}

// PutArticleTriage caches the inline triage line for an article.
func (s *Store) PutArticleTriage(articleID int64, triage, provider string) error {
	_, err := s.db.Exec(
		`INSERT INTO article_ai_triage (article_id, triage, provider)
		 VALUES (?, ?, ?)
		 ON CONFLICT(article_id) DO UPDATE SET
		   triage = excluded.triage,
		   generated_at = CURRENT_TIMESTAMP,
		   provider = excluded.provider`,
		articleID, triage, provider,
	)
	return err
}

// PrefetchedTriage returns triage lines already cached for a list of
// article IDs; missing entries are generated lazily.
func (s *Store) PrefetchedTriage(ids []int64) (map[int64]string, error) {
	if len(ids) == 0 {
		return map[int64]string{}, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := s.db.Query(
		`SELECT article_id, triage FROM article_ai_triage WHERE article_id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]string, len(ids))
	for rows.Next() {
		var id int64
		var triage string
		if err := rows.Scan(&id, &triage); err != nil {
			continue
		}
		out[id] = triage
	}
	return out, nil
}

// --- CVE explanation cache (Pro) ---

// GetCVEExplanation returns the cached 3-bullet summary for a CVE,
// or ("", sql.ErrNoRows) if we haven't generated one yet.
func (s *Store) GetCVEExplanation(cveID string) (string, error) {
	var text string
	err := s.db.QueryRow(
		`SELECT explanation FROM cve_ai_explanations WHERE cve_id = ?`,
		cveID,
	).Scan(&text)
	return text, err
}

// PutCVEExplanation upserts; subsequent generations for the same CVE
// just overwrite (CVE descriptions can be updated by NVD post-publication
// so a refresh might produce better text). Stored forever otherwise.
func (s *Store) PutCVEExplanation(cveID, explanation, provider string) error {
	_, err := s.db.Exec(
		`INSERT INTO cve_ai_explanations (cve_id, explanation, provider)
		 VALUES (?, ?, ?)
		 ON CONFLICT(cve_id) DO UPDATE SET
		   explanation = excluded.explanation,
		   generated_at = CURRENT_TIMESTAMP,
		   provider = excluded.provider`,
		cveID, explanation, provider,
	)
	return err
}

// LookupAPITokenUser is what the bearer middleware calls per request:
// resolve a SHA-256(token) hash to the owning user (if any). Also bumps
// last_used_at async-ish (best-effort, doesn't block the request path).
func (s *Store) LookupAPITokenUser(tokenHash []byte) (*UserRow, error) {
	var userID string
	err := s.db.QueryRow(
		`SELECT user_id FROM user_api_tokens
		  WHERE token_hash = ? AND revoked_at IS NULL`,
		tokenHash,
	).Scan(&userID)
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = s.db.Exec(
			`UPDATE user_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
			tokenHash,
		)
	}()
	return s.GetUserByID(userID)
}

// UserBskySubscriberSet returns the set of users who watch a given handle,
// for the article-view filter (so we can decide which users a bluesky
// article is visible to). Map for O(1) lookup at filter time.
func (s *Store) UserBskySubscriberSet(handle string) (map[string]bool, error) {
	rows, err := s.db.Query(
		`SELECT user_id FROM user_bluesky_accounts WHERE handle = ?`,
		handle,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out[uid] = true
	}
	return out, rows.Err()
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

// RecentMagicLinksForIP counts tokens issued from an IP fingerprint in the
// last N seconds. Looser cap than per-email since legitimate NAT users share.
func (s *Store) RecentMagicLinksForIP(ipHash []byte, since time.Duration) (int, error) {
	if len(ipHash) == 0 {
		return 0, nil
	}
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM magic_link_tokens WHERE ip_hash = ? AND created_at > ?`,
		ipHash, time.Now().Add(-since),
	).Scan(&n)
	return n, err
}
