package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/dedup"
	"github.com/RMS2D/omnomfeeds/internal/models"

	_ "modernc.org/sqlite"
)

// isSafeArticleURL rejects non-http(s) schemes to block javascript:/data:/file:.
func isSafeArticleURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	return true
}

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	// Single-writer pool + WAL + 5s busy timeout. SQLite is single-writer; more
	// connections just race into SQLITE_BUSY under the fetch loop.
	dsn := path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// DB exposes the underlying *sql.DB so enrichment packages can share it.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS articles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			url TEXT NOT NULL UNIQUE,
			normalized_url TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL,
			source_type TEXT NOT NULL,
			summary TEXT,
			score INTEGER DEFAULT 0,
			tags TEXT DEFAULT '[]',
			published_at DATETIME,
			fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			read INTEGER DEFAULT 0,
			duplicate_of INTEGER DEFAULT NULL,
			FOREIGN KEY (duplicate_of) REFERENCES articles(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_articles_score ON articles(score DESC);
		CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
		CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source);
		CREATE INDEX IF NOT EXISTS idx_articles_read ON articles(read);
		CREATE INDEX IF NOT EXISTS idx_articles_norm_url ON articles(normalized_url);
		CREATE INDEX IF NOT EXISTS idx_articles_dup ON articles(duplicate_of);
	`)
	if err != nil {
		s.db.Exec("ALTER TABLE articles ADD COLUMN normalized_url TEXT NOT NULL DEFAULT ''")
		s.db.Exec("ALTER TABLE articles ADD COLUMN duplicate_of INTEGER DEFAULT NULL")
		s.db.Exec("CREATE INDEX IF NOT EXISTS idx_articles_norm_url ON articles(normalized_url)")
		s.db.Exec("CREATE INDEX IF NOT EXISTS idx_articles_dup ON articles(duplicate_of)")
	}

	// Self-host bookmark table; distinct from multi-user user_bookmarks.
	_, _ = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS bookmarks (
			article_id    INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
			bookmarked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`)

	return s.migrateUserTables()
}

// migrateUserTables creates the HOSTED_MODE user overlay tables on every install.
func (s *Store) migrateUserTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			id_provider   TEXT NOT NULL,
			id_external   TEXT NOT NULL,
			email         TEXT NOT NULL,
			display_name  TEXT,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			pro_until     DATETIME,
			UNIQUE (id_provider, id_external),
			UNIQUE (email)
		);
		CREATE TABLE IF NOT EXISTS user_sessions (
			token_hash    BLOB PRIMARY KEY,
			user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			user_agent    TEXT,
			expires_at    DATETIME NOT NULL
		);
		-- Patch Tuesday auto-briefs. One row per (vendor, brief_date) so
		-- we never regenerate the same vendor's brief twice the same day.
		CREATE TABLE IF NOT EXISTS patch_briefs (
			vendor         TEXT NOT NULL,
			brief_date     DATE NOT NULL,
			brief_text     TEXT NOT NULL,
			article_count  INTEGER NOT NULL DEFAULT 0,
			window_start   DATETIME NOT NULL,
			window_end     DATETIME NOT NULL,
			generated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (vendor, brief_date)
		);
		CREATE INDEX IF NOT EXISTS idx_patch_briefs_date ON patch_briefs(brief_date);

		CREATE TABLE IF NOT EXISTS user_settings (
			user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			settings   TEXT NOT NULL DEFAULT '{}',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS user_read_state (
			user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			article_id  INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
			read_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, article_id)
		);
		CREATE TABLE IF NOT EXISTS user_bookmarks (
			user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			article_id     INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
			bookmarked_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			note           TEXT,
			PRIMARY KEY (user_id, article_id)
		);
		CREATE TABLE IF NOT EXISTS user_stack_tags (
			user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			tag      TEXT NOT NULL,
			PRIMARY KEY (user_id, tag)
		);
		CREATE TABLE IF NOT EXISTS user_dep_packages (
			user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			ecosystem    TEXT NOT NULL,
			name         TEXT NOT NULL,
			version_pin  TEXT NOT NULL,
			uploaded_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, ecosystem, name)
		);
		CREATE TABLE IF NOT EXISTS user_alert_rules (
			id              TEXT PRIMARY KEY,
			user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind            TEXT NOT NULL,
			pattern         TEXT NOT NULL,
			channel         TEXT NOT NULL,
			channel_target  TEXT,
			enabled         INTEGER NOT NULL DEFAULT 1,
			created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_fired_at   DATETIME
		);
		CREATE TABLE IF NOT EXISTS user_actor_follows (
			user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			actor_slug   TEXT NOT NULL,
			followed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, actor_slug)
		);
		CREATE TABLE IF NOT EXISTS user_custom_sources (
			id             TEXT PRIMARY KEY,
			user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name           TEXT NOT NULL,
			url            TEXT NOT NULL,
			enabled        INTEGER NOT NULL DEFAULT 1,
			last_fetch_at  DATETIME,
			last_error     TEXT,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS user_api_tokens (
			id            TEXT PRIMARY KEY,
			user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name          TEXT NOT NULL,
			token_hash    BLOB NOT NULL UNIQUE,
			scopes        TEXT,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at  DATETIME,
			revoked_at    DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_user_read_state_user ON user_read_state(user_id, read_at DESC);
		CREATE INDEX IF NOT EXISTS idx_user_bookmarks_user ON user_bookmarks(user_id, bookmarked_at DESC);
		CREATE INDEX IF NOT EXISTS idx_user_alert_rules_user ON user_alert_rules(user_id, enabled);
		CREATE INDEX IF NOT EXISTS idx_user_custom_sources_user ON user_custom_sources(user_id, enabled);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);

		-- One-time magic-link tokens for email-based login (Google OAuth alternative).
		-- TTL ~15 min, single use. token_hash is SHA-256(raw_token).
		CREATE TABLE IF NOT EXISTS magic_link_tokens (
			token_hash    BLOB PRIMARY KEY,
			email         TEXT NOT NULL,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at    DATETIME NOT NULL,
			used_at       DATETIME,
			user_agent    TEXT,
			ip_hash       BLOB
		);
		CREATE INDEX IF NOT EXISTS idx_magic_link_email   ON magic_link_tokens(email, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_magic_link_expires ON magic_link_tokens(expires_at);

		-- user_email_digest_prefs: per-user email digest schedule. One
		-- row per subscribed user. Frequency ∈ {off, daily, weekly};
		-- last_sent_at is updated after each successful Resend call so
		-- the worker can compute "is it time again."
		CREATE TABLE IF NOT EXISTS user_email_digest_prefs (
			user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			frequency    TEXT NOT NULL DEFAULT 'off',
			last_sent_at DATETIME
		);

		-- user_saved_searches: Pro feature, "channels". Each row is a
		-- named saved query the user can recall as a quick filter.
		CREATE TABLE IF NOT EXISTS user_saved_searches (
			id          TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			query       TEXT NOT NULL,
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			sort_order  INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_user_saved_searches_user ON user_saved_searches(user_id, sort_order);

		-- article_ai_explanations is the per-article version of the
		-- CVE deep-dive: 2-3 line plain-English summary per article.
		-- Cached forever; cheap regenerations are not worth the LLM cost.
		CREATE TABLE IF NOT EXISTS article_ai_explanations (
			article_id   INTEGER PRIMARY KEY,
			explanation  TEXT NOT NULL,
			generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			provider     TEXT NOT NULL DEFAULT ''
		);

		-- article_ai_triage caches the inline "what? so what?" one-liner
		-- shown next to each article in the Pro reader list view. One
		-- short sentence per article; cached forever. Cost-bounded:
		-- ~80 output tokens per new article that crosses the threshold.
		CREATE TABLE IF NOT EXISTS article_ai_triage (
			article_id   INTEGER PRIMARY KEY,
			triage       TEXT NOT NULL,
			generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			provider     TEXT NOT NULL DEFAULT ''
		);

		-- cve_ai_explanations caches the Pro 3-bullet summary keyed by CVE id
		-- so only the first explain request pays. Stored forever (CVE descs are immutable).
		CREATE TABLE IF NOT EXISTS cve_ai_explanations (
			cve_id       TEXT PRIMARY KEY,
			explanation  TEXT NOT NULL,
			generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			provider     TEXT NOT NULL DEFAULT ''
		);

		-- alert_fires dedups webhook firings so a single article can't
		-- spam a user with N webhooks when matched by N alert rules,
		-- and a single (rule, article) pair never fires twice across
		-- restarts or worker re-runs.
		CREATE TABLE IF NOT EXISTS alert_fires (
			rule_id     TEXT NOT NULL,
			article_id  INTEGER NOT NULL,
			fired_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (rule_id, article_id)
		);
		CREATE INDEX IF NOT EXISTS idx_alert_fires_rule ON alert_fires(rule_id, fired_at DESC);

		-- Per-user Bluesky watched-accounts. The fetcher fetches the union
		-- of this table and config.json's global list (operator baseline);
		-- the view layer filters per-user so user A's adds don't show up
		-- in user B's feed.
		CREATE TABLE IF NOT EXISTS user_bluesky_accounts (
			user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			handle     TEXT NOT NULL,
			added_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, handle)
		);
		CREATE INDEX IF NOT EXISTS idx_user_bsky_handle ON user_bluesky_accounts(handle);

		-- Lightweight, in-house analytics. Captures which features are
		-- actually used so we know what's worth keeping and what's worth
		-- ref is event-specific (article_id, cve_id, actor_slug, etc.);
		-- meta is optional JSON for extras (e.g. attack export scope).
		-- ip_hash and user_agent let admin views distinguish real users
		-- from crawler / scraper traffic; never displayed in plaintext.
		CREATE TABLE IF NOT EXISTS events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			user_id    TEXT,
			session    TEXT,
			event      TEXT NOT NULL,
			ref        TEXT,
			meta       TEXT,
			ip_hash    BLOB,
			user_agent TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts DESC);
		CREATE INDEX IF NOT EXISTS idx_events_event  ON events(event);
		CREATE INDEX IF NOT EXISTS idx_events_user   ON events(user_id);
		CREATE INDEX IF NOT EXISTS idx_events_ref    ON events(event, ref);
		CREATE INDEX IF NOT EXISTS idx_events_ip     ON events(ip_hash);
	`)
	if err != nil {
		return err
	}

	// Idempotent column adds for pre-existing events tables; duplicate
	// column errors are swallowed by SQLite via Exec without check.
	s.db.Exec(`ALTER TABLE events ADD COLUMN ip_hash BLOB`)
	s.db.Exec(`ALTER TABLE events ADD COLUMN user_agent TEXT`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_hash)`)

	// Stripe linkage columns added after the initial users table; ALTER
	// is idempotent enough for SQLite (duplicate-column errors swallowed).
	s.db.Exec(`ALTER TABLE users ADD COLUMN stripe_customer_id TEXT`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id)`)
	return nil
}

func (s *Store) Upsert(a models.Article) error {
	// Reject non-http(s) URLs at the storage boundary to block XSS payloads
	// from untrusted feeds (RSS, Bluesky, etc.).
	if !isSafeArticleURL(a.URL) {
		return nil
	}
	normURL := dedup.NormalizeURL(a.URL)
	tagsJSON, _ := json.Marshal(a.Tags)

	dupID := s.findDuplicate(a.Title, normURL, a.Source)

	_, err := s.db.Exec(`
		INSERT INTO articles (title, url, normalized_url, source, source_type, summary, score, tags, published_at, fetched_at, duplicate_of)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			title=excluded.title,
			summary=excluded.summary,
			score=excluded.score,
			tags=excluded.tags,
			fetched_at=excluded.fetched_at,
			duplicate_of=excluded.duplicate_of
	`, a.Title, a.URL, normURL, a.Source, a.SourceType, a.Summary, a.Score, string(tagsJSON), a.PublishedAt, a.FetchedAt, dupID)
	return err
}

func (s *Store) findDuplicate(title, normURL, source string) *int64 {
	var existID int64
	err := s.db.QueryRow(
		`SELECT id FROM articles
		 WHERE normalized_url = ? AND source != ? AND duplicate_of IS NULL
		 ORDER BY score DESC LIMIT 1`,
		normURL, source,
	).Scan(&existID)
	if err == nil {
		return &existID
	}

	cutoff := time.Now().Add(-72 * time.Hour)
	rows, err := s.db.Query(
		`SELECT id, title FROM articles
		 WHERE source != ? AND published_at > ? AND duplicate_of IS NULL
		 ORDER BY published_at DESC LIMIT 200`,
		source, cutoff,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var existTitle string
		if rows.Scan(&id, &existTitle) != nil {
			continue
		}
		if dedup.TitleSimilarity(title, existTitle) >= 0.55 {
			return &id
		}
	}

	return nil
}

type ListFilter struct {
	Source      string
	SourceType  string
	ExcludeType string
	MinScore    int
	Search      string
	Unread      bool
	ShowDupes   bool
	HasIOCs     bool
	Since       time.Time
	Limit       int
	Offset      int
	// Restricts visible "Bluesky:@handle" sources; nil = no filter.
	VisibleBskySources *[]string
	// Non-empty switches read-state to a per-user overlay via user_read_state.
	UserID string
}

func (s *Store) List(f ListFilter) ([]models.Article, error) {
	// When UserID is set, JOIN user_read_state to override the global read flag.
	var args []any
	var query string
	if f.UserID != "" {
		query = `SELECT a.id, a.title, a.url, a.source, a.source_type, a.summary,
		         a.score, a.tags, a.published_at, a.fetched_at,
		         CASE WHEN urs.user_id IS NULL THEN 0 ELSE 1 END AS read,
		         a.duplicate_of
		         FROM articles a
		         LEFT JOIN user_read_state urs
		           ON urs.article_id = a.id AND urs.user_id = ?
		         WHERE 1=1`
		args = append(args, f.UserID)
	} else {
		query = `SELECT id, title, url, source, source_type, summary, score, tags,
		         published_at, fetched_at, read, duplicate_of FROM articles WHERE 1=1`
	}

	if !f.ShowDupes {
		query += " AND duplicate_of IS NULL"
	}
	if f.Source != "" {
		query += " AND source = ?"
		args = append(args, f.Source)
	}
	if f.SourceType != "" {
		query += " AND source_type = ?"
		args = append(args, f.SourceType)
	}
	if f.ExcludeType != "" {
		query += " AND source_type != ?"
		args = append(args, f.ExcludeType)
	}
	if f.MinScore > 0 {
		query += " AND score >= ?"
		args = append(args, f.MinScore)
	}
	if f.Search != "" {
		query += " AND (title LIKE ? OR summary LIKE ?)"
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	if f.Unread {
		if f.UserID != "" {
			// "Unread for this user" - no matching user_read_state row.
			query += " AND urs.user_id IS NULL"
		} else {
			query += " AND read = 0"
		}
	}
	if f.HasIOCs {
		query += " AND (tags LIKE '%sha256:%' OR tags LIKE '%md5:%' OR tags LIKE '%ext:%')"
	}
	if !f.Since.IsZero() {
		query += " AND published_at >= ?"
		args = append(args, f.Since)
	}
	if f.VisibleBskySources != nil {
		// Author-feed articles store "Bluesky:@handle"; search-feed articles
		// store "Bluesky" and stay public. Empty allow-list hides all authors.
		if len(*f.VisibleBskySources) == 0 {
			query += " AND (source_type != 'bluesky' OR source NOT LIKE 'Bluesky:@%')"
		} else {
			placeholders := make([]string, len(*f.VisibleBskySources))
			for i, src := range *f.VisibleBskySources {
				placeholders[i] = "?"
				args = append(args, src)
			}
			query += " AND (source_type != 'bluesky' OR source NOT LIKE 'Bluesky:@%' OR source IN (" + strings.Join(placeholders, ",") + "))"
		}
	}

	query += " ORDER BY published_at DESC, score DESC"

	if f.Limit <= 0 {
		f.Limit = 100
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanArticles(rows)
}

func (s *Store) DuplicatesOf(id int64) ([]models.Article, error) {
	rows, err := s.db.Query(
		`SELECT id, title, url, source, source_type, summary, score, tags,
		 published_at, fetched_at, read, duplicate_of
		 FROM articles WHERE duplicate_of = ? ORDER BY score DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArticles(rows)
}

func (s *Store) MarkRead(id int64) error {
	_, err := s.db.Exec("UPDATE articles SET read = 1 WHERE id = ?", id)
	return err
}

func (s *Store) MarkAllRead() error {
	_, err := s.db.Exec("UPDATE articles SET read = 1")
	return err
}

// PatchBrief is one row in the patch_briefs table.
type PatchBrief struct {
	Vendor       string    `json:"vendor"`
	BriefDate    string    `json:"brief_date"` // YYYY-MM-DD
	BriefText    string    `json:"brief_text"`
	ArticleCount int       `json:"article_count"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	GeneratedAt  time.Time `json:"generated_at"`
}

// GetPatchBrief returns the brief for vendor+YYYY-MM-DD, or nil if none.
func (s *Store) GetPatchBrief(vendor, briefDate string) (*PatchBrief, error) {
	row := s.db.QueryRow(
		`SELECT vendor, brief_date, brief_text, article_count, window_start, window_end, generated_at
		   FROM patch_briefs WHERE vendor = ? AND brief_date = ?`,
		vendor, briefDate,
	)
	var b PatchBrief
	if err := row.Scan(&b.Vendor, &b.BriefDate, &b.BriefText, &b.ArticleCount, &b.WindowStart, &b.WindowEnd, &b.GeneratedAt); err != nil {
		return nil, nil
	}
	return &b, nil
}

// PutPatchBrief inserts or replaces a brief row.
func (s *Store) PutPatchBrief(b PatchBrief) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO patch_briefs
		   (vendor, brief_date, brief_text, article_count, window_start, window_end, generated_at)
		 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		b.Vendor, b.BriefDate, b.BriefText, b.ArticleCount, b.WindowStart, b.WindowEnd,
	)
	return err
}

// RecentPatchBriefs returns briefs generated in the last `days` days, newest first.
func (s *Store) RecentPatchBriefs(days int) ([]PatchBrief, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := s.db.Query(
		`SELECT vendor, brief_date, brief_text, article_count, window_start, window_end, generated_at
		   FROM patch_briefs
		  WHERE brief_date >= date('now', ?)
		  ORDER BY brief_date DESC, vendor ASC`,
		fmt.Sprintf("-%d days", days),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PatchBrief
	for rows.Next() {
		var b PatchBrief
		if err := rows.Scan(&b.Vendor, &b.BriefDate, &b.BriefText, &b.ArticleCount, &b.WindowStart, &b.WindowEnd, &b.GeneratedAt); err != nil {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// VendorArticles returns de-duped articles in [since, until] whose
// title/summary/tags substring-match any keyword (case-insensitive).
func (s *Store) VendorArticles(since, until time.Time, keywords []string, limit int) ([]models.Article, error) {
	if limit <= 0 {
		limit = 80
	}
	if len(keywords) == 0 {
		return nil, nil
	}
	// OR LIKE across title+summary+tag text in one pass; word boundaries
	// aren't critical at this scale.
	clauses := make([]string, 0, len(keywords))
	args := []any{since, until}
	for _, k := range keywords {
		clauses = append(clauses, "(LOWER(title || ' ' || COALESCE(summary,'') || ' ' || tags) LIKE ?)")
		args = append(args, "%"+strings.ToLower(k)+"%")
	}
	args = append(args, limit)
	q := `SELECT id, title, url, source, source_type, COALESCE(summary,''), score, tags, published_at, fetched_at, read
	        FROM articles
	       WHERE published_at >= ? AND published_at < ?
	         AND duplicate_of IS NULL
	         AND (` + strings.Join(clauses, " OR ") + `)
	       ORDER BY score DESC
	       LIMIT ?`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Article
	for rows.Next() {
		var a models.Article
		var tagsJSON string
		var readInt int
		if err := rows.Scan(&a.ID, &a.Title, &a.URL, &a.Source, &a.SourceType, &a.Summary, &a.Score, &tagsJSON, &a.PublishedAt, &a.FetchedAt, &readInt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		a.Read = readInt != 0
		out = append(out, a)
	}
	return out, nil
}

// GetWhatsNewDismiss reads last_whats_new_dismiss from the user_settings blob.
func (s *Store) GetWhatsNewDismiss(userID string) (time.Time, error) {
	blob, err := s.GetSettings(userID)
	if err != nil {
		return time.Time{}, err
	}
	var sm map[string]any
	if err := json.Unmarshal([]byte(blob), &sm); err != nil {
		return time.Time{}, nil
	}
	raw, ok := sm["last_whats_new_dismiss"].(string)
	if !ok || raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// PutWhatsNewDismiss merges last_whats_new_dismiss into the settings blob.
func (s *Store) PutWhatsNewDismiss(userID string, ts time.Time) error {
	blob, err := s.GetSettings(userID)
	if err != nil {
		return err
	}
	var sm map[string]any
	if err := json.Unmarshal([]byte(blob), &sm); err != nil || sm == nil {
		sm = map[string]any{}
	}
	sm["last_whats_new_dismiss"] = ts.UTC().Format(time.RFC3339)
	out, err := json.Marshal(sm)
	if err != nil {
		return err
	}
	return s.PutSettings(userID, string(out))
}

// RecentAliasMentionCount counts articles in the last `days` whose
// title or summary substring-matches any alias (case-insensitive).
func (s *Store) RecentAliasMentionCount(aliases []string, days int) (int, error) {
	if len(aliases) == 0 {
		return 0, nil
	}
	if days <= 0 {
		days = 30
	}
	clauses := make([]string, 0, len(aliases))
	args := []any{fmt.Sprintf("-%d days", days)}
	for _, a := range aliases {
		clauses = append(clauses, "LOWER(title || ' ' || COALESCE(summary,'')) LIKE ?")
		args = append(args, "%"+strings.ToLower(a)+"%")
	}
	q := `SELECT COUNT(*) FROM articles
	       WHERE published_at >= datetime('now', ?)
	         AND duplicate_of IS NULL
	         AND (` + strings.Join(clauses, " OR ") + `)`
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CVEActivity is one row of the "hottest CVEs right now" leaderboard.
// Mentions counts how many articles tagged that CVE in the window.
type CVEActivity struct {
	CVE          string    `json:"cve"`
	Mentions     int       `json:"mentions"`
	KEV          bool      `json:"kev"`
	LatestTitle  string    `json:"latest_title"`
	LatestURL    string    `json:"latest_url"`
	LatestSource string    `json:"latest_source"`
	LatestAt     time.Time `json:"latest_at"`
}

var hotCVERe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// HottestCVEs returns the top CVE IDs by mention count in the last `hours`,
// with the newest article carrying each CVE for context. KEV flag set if any.
func (s *Store) HottestCVEs(hours, limit int) ([]CVEActivity, error) {
	rows, err := s.db.Query(
		`SELECT title, url, source, tags, published_at FROM articles
		   WHERE published_at >= datetime('now', ?)
		     AND duplicate_of IS NULL
		     AND tags LIKE '%CVE-%'
		   ORDER BY published_at DESC`,
		fmt.Sprintf("-%d hours", hours),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type slot struct {
		count              int
		title, url, source string
		at                 time.Time
		kev                bool
	}
	agg := map[string]*slot{}

	for rows.Next() {
		var title, url, source, tagsJSON string
		var pubAt time.Time
		if err := rows.Scan(&title, &url, &source, &tagsJSON, &pubAt); err != nil {
			continue
		}
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		// Build the per-article "this CVE was tagged as KEV here" lookup
		// first so the second pass can set the flag correctly.
		kevSet := map[string]bool{}
		for _, t := range tags {
			if strings.HasPrefix(t, "kev:") {
				kevSet[strings.TrimPrefix(t, "kev:")] = true
			}
		}
		for _, t := range tags {
			if !hotCVERe.MatchString(t) {
				continue
			}
			sl, ok := agg[t]
			if !ok {
				sl = &slot{}
				agg[t] = sl
			}
			sl.count++
			if sl.at.IsZero() || pubAt.After(sl.at) {
				sl.title, sl.url, sl.source, sl.at = title, url, source, pubAt
			}
			if kevSet[t] {
				sl.kev = true
			}
		}
	}

	out := make([]CVEActivity, 0, len(agg))
	for cve, sl := range agg {
		out = append(out, CVEActivity{
			CVE: cve, Mentions: sl.count, KEV: sl.kev,
			LatestTitle: sl.title, LatestURL: sl.url, LatestSource: sl.source, LatestAt: sl.at,
		})
	}
	sortHottest(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// sortHottest sorts by mention count desc, then by latest-mention recency.
func sortHottest(rows []CVEActivity) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 {
			a, b := rows[j-1], rows[j]
			less := b.Mentions > a.Mentions || (b.Mentions == a.Mentions && b.LatestAt.After(a.LatestAt))
			if !less {
				break
			}
			rows[j-1], rows[j] = b, a
			j--
		}
	}
}

// CVEConsensusRow is one source's track record on a CVE for the heatmap.
type CVEConsensusRow struct {
	Source     string    `json:"source"`
	SourceType string    `json:"source_type"`
	Count      int       `json:"count"`
	LastSeen   time.Time `json:"last_seen"`
	LatestURL  string    `json:"latest_url"`
}

// ArticlesForCVE returns articles tagged with the exact CVE ID, newest first.
func (s *Store) ArticlesForCVE(cveID string, limit int) ([]models.Article, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT a.id, a.title, a.url, a.source, a.source_type,
		       COALESCE(a.summary, ''), a.score, COALESCE(a.tags, '[]'),
		       a.published_at, a.fetched_at
		FROM articles a, json_each(a.tags) je
		WHERE je.value = ?
		  AND a.duplicate_of IS NULL
		ORDER BY a.published_at DESC
		LIMIT ?
	`, cveID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Article
	for rows.Next() {
		var a models.Article
		var tagsJSON string
		if err := rows.Scan(&a.ID, &a.Title, &a.URL, &a.Source, &a.SourceType,
			&a.Summary, &a.Score, &tagsJSON, &a.PublishedAt, &a.FetchedAt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		out = append(out, a)
	}
	return out, rows.Err()
}

// TopMentionedCVEs returns the most-mentioned CVE IDs corpus-wide, by mention count.
func (s *Store) TopMentionedCVEs(limit int) ([]string, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	rows, err := s.db.Query(`
		SELECT je.value AS cve, COUNT(*) AS n
		FROM articles a, json_each(a.tags) je
		WHERE a.duplicate_of IS NULL
		  AND je.value LIKE 'CVE-%'
		GROUP BY je.value
		ORDER BY n DESC, cve ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

func (s *Store) CVEConsensus(cveID string, days int) ([]CVEConsensusRow, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}
	rows, err := s.db.Query(
		`SELECT source, source_type, url, published_at, tags FROM articles
		   WHERE published_at >= datetime('now', ?)
		     AND duplicate_of IS NULL
		     AND tags LIKE ?
		   ORDER BY published_at DESC`,
		fmt.Sprintf("-%d days", days),
		"%"+cveID+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type slot struct {
		sourceType string
		count      int
		lastSeen   time.Time
		latestURL  string
	}
	agg := map[string]*slot{}
	for rows.Next() {
		var src, srcType, url, tagsJSON string
		var pubAt time.Time
		if err := rows.Scan(&src, &srcType, &url, &pubAt, &tagsJSON); err != nil {
			continue
		}
		// Confirm the CVE is actually a tag and not a substring match
		// against another field in the JSON.
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		found := false
		for _, t := range tags {
			if strings.EqualFold(t, cveID) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		sl, ok := agg[src]
		if !ok {
			sl = &slot{sourceType: srcType}
			agg[src] = sl
		}
		sl.count++
		if pubAt.After(sl.lastSeen) {
			sl.lastSeen = pubAt
			sl.latestURL = url
		}
	}

	out := make([]CVEConsensusRow, 0, len(agg))
	for src, sl := range agg {
		out = append(out, CVEConsensusRow{
			Source: src, SourceType: sl.sourceType,
			Count: sl.count, LastSeen: sl.lastSeen, LatestURL: sl.latestURL,
		})
	}
	// Most-recent first; tiebreak by count desc.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 {
			a, b := out[j-1], out[j]
			less := b.LastSeen.After(a.LastSeen) || (b.LastSeen.Equal(a.LastSeen) && b.Count > a.Count)
			if !less {
				break
			}
			out[j-1], out[j] = b, a
			j--
		}
	}
	return out, nil
}

// CVETimelineEvent is one milestone in a CVE's lifecycle.
type CVETimelineEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // first_mention | first_poc | advisory | latest
	Label  string    `json:"label"`
	Source string    `json:"source"`
	Title  string    `json:"title"`
	URL    string    `json:"url"`
}

// vendorPSIRTSources lists sources that count as first-party vendor advisories.
var vendorPSIRTSources = map[string]bool{
	"MSRC Blog":                  true,
	"Palo Alto PSIRT":            true,
	"Fortinet PSIRT":             true,
	"SonicWall PSIRT":            true,
	"NetApp Security":            true,
	"Citrix Security":            true,
	"AWS Security Bulletins":     true,
	"Cisco Talos":                true,
	"NCSC UK":                    true,
	"CISA Alerts":                true,
	"Ubuntu Security Notices":    true,
	"Debian DSA":                 true,
	"Chrome Releases":            true,
	"Mozilla Security":           true,
	"Microsoft Security":         true,
	"Microsoft Threat Intel":     true,
	"Sophos Security Advisories": true,
}

// pocTagSet identifies articles whose tags signal exploit / PoC
// availability. Backs the "first PoC" milestone on the CVE timeline.
var pocTagSet = map[string]bool{
	"exploit": true,
	"poc":     true,
	"rce":     true,
}

// CVETimeline returns chronological milestone events for a CVE:
// first_mention, first_poc, advisory (PSIRT), latest. Empty if no articles match.
func (s *Store) CVETimeline(cveID string) ([]CVETimelineEvent, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}
	rows, err := s.db.Query(
		`SELECT title, url, source, source_type, COALESCE(published_at, fetched_at), tags
		   FROM articles
		  WHERE duplicate_of IS NULL
		    AND tags LIKE ?
		  ORDER BY COALESCE(published_at, fetched_at) ASC`,
		"%"+cveID+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type seen struct {
		at                 time.Time
		title, url, source string
	}
	var firstMention *seen
	var firstPoC *seen
	var firstAdvisory *seen
	var latest *seen

	for rows.Next() {
		var title, url, source, sourceType, tagsJSON string
		var pubAt time.Time
		if err := rows.Scan(&title, &url, &source, &sourceType, &pubAt, &tagsJSON); err != nil {
			continue
		}
		// Confirm CVE is an exact tag (the LIKE could match substrings).
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		exact := false
		hasPoC := false
		for _, t := range tags {
			if strings.EqualFold(t, cveID) {
				exact = true
			}
			if pocTagSet[strings.ToLower(t)] {
				hasPoC = true
			}
		}
		if !exact {
			continue
		}
		row := &seen{at: pubAt, title: title, url: url, source: source}
		if firstMention == nil {
			firstMention = row
		}
		latest = row
		if firstPoC == nil && hasPoC {
			firstPoC = row
		}
		if firstAdvisory == nil && vendorPSIRTSources[source] {
			firstAdvisory = row
		}
	}

	var out []CVETimelineEvent
	add := func(r *seen, kind, label string) {
		if r == nil {
			return
		}
		out = append(out, CVETimelineEvent{
			At: r.at, Kind: kind, Label: label,
			Source: r.source, Title: r.title, URL: r.url,
		})
	}
	add(firstMention, "first_mention", "First article mention")
	add(firstAdvisory, "advisory", "Vendor advisory / official source")
	add(firstPoC, "first_poc", "First PoC / exploit reference")
	// Only include "latest" if it's a different article from the first.
	if latest != nil && firstMention != nil && latest.url != firstMention.url {
		add(latest, "latest", "Latest mention")
	}
	// Sort by time asc - the events might have come in non-chronological
	// order if the same article fills multiple roles.
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// TTPFrequency counts T-code occurrences in tags over the last `days` days.
func (s *Store) TTPFrequency(days int) (map[string]int, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := s.db.Query(
		`SELECT tags FROM articles
		   WHERE published_at >= datetime('now', ?)
		     AND duplicate_of IS NULL
		     AND tags LIKE '%T1%'`,
		fmt.Sprintf("-%d days", days),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ttpRe := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	out := map[string]int{}
	for rows.Next() {
		var tagsJSON string
		if err := rows.Scan(&tagsJSON); err != nil {
			continue
		}
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		for _, t := range tags {
			if ttpRe.MatchString(t) {
				out[t]++
			}
		}
	}
	return out, nil
}

// TTPFrequencyForBookmarks counts T-codes across a user's bookmarks.
func (s *Store) TTPFrequencyForBookmarks(userID string) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT a.tags FROM articles a
		   JOIN user_bookmarks b ON b.article_id = a.id
		  WHERE b.user_id = ?
		    AND a.duplicate_of IS NULL`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ttpRe := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	out := map[string]int{}
	for rows.Next() {
		var tagsJSON string
		if err := rows.Scan(&tagsJSON); err != nil {
			continue
		}
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		for _, t := range tags {
			if ttpRe.MatchString(t) {
				out[t]++
			}
		}
	}
	return out, nil
}

// PreKEVCandidates returns CVE -> distinct-source-count for CVEs mentioned in
// the last `hours` with at least minSources distinct sources. Caller filters KEV.
func (s *Store) PreKEVCandidates(hours, minSources int) (map[string]int, error) {
	if hours <= 0 {
		hours = 72
	}
	if minSources <= 0 {
		minSources = 3
	}
	rows, err := s.db.Query(
		`SELECT source, tags FROM articles
		   WHERE published_at >= datetime('now', ?)
		     AND duplicate_of IS NULL
		     AND tags LIKE '%CVE-%'`,
		fmt.Sprintf("-%d hours", hours),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// CVE -> set of distinct source names that posted about it.
	agg := map[string]map[string]struct{}{}
	for rows.Next() {
		var source, tagsJSON string
		if err := rows.Scan(&source, &tagsJSON); err != nil {
			continue
		}
		var tags []string
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			continue
		}
		for _, t := range tags {
			if !hotCVERe.MatchString(t) {
				continue
			}
			set, ok := agg[t]
			if !ok {
				set = make(map[string]struct{})
				agg[t] = set
			}
			set[source] = struct{}{}
		}
	}

	out := make(map[string]int, len(agg))
	for cve, sources := range agg {
		if len(sources) >= minSources {
			out[cve] = len(sources)
		}
	}
	return out, nil
}

// RecentKEVMentionCount counts kev:*-tagged articles published in the last `hours`.
func (s *Store) RecentKEVMentionCount(hours int) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM articles
		   WHERE published_at >= datetime('now', ?)
		     AND duplicate_of IS NULL
		     AND tags LIKE '%kev:%'`,
		fmt.Sprintf("-%d hours", hours),
	).Scan(&n)
	return n, err
}

func (s *Store) Stats() (models.Stats, error) {
	var stats models.Stats
	stats.SourceBreakdown = make(map[string]int)
	stats.TopTags = make(map[string]int)
	stats.LastUpdated = time.Now()

	s.db.QueryRow("SELECT COUNT(*) FROM articles WHERE duplicate_of IS NULL").Scan(&stats.TotalArticles)
	s.db.QueryRow("SELECT COUNT(*) FROM articles WHERE read = 0 AND duplicate_of IS NULL").Scan(&stats.UnreadCount)

	var dupCount int
	s.db.QueryRow("SELECT COUNT(*) FROM articles WHERE duplicate_of IS NOT NULL").Scan(&dupCount)
	stats.SourceBreakdown["_duplicates_hidden"] = dupCount

	rows, err := s.db.Query("SELECT source, COUNT(*) FROM articles WHERE duplicate_of IS NULL GROUP BY source")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var src string
			var cnt int
			rows.Scan(&src, &cnt)
			stats.SourceBreakdown[src] = cnt
		}
	}

	tagRows, err := s.db.Query("SELECT tags FROM articles WHERE score > 0 AND duplicate_of IS NULL ORDER BY published_at DESC LIMIT 500")
	if err == nil {
		defer tagRows.Close()
		for tagRows.Next() {
			var tagsJSON string
			tagRows.Scan(&tagsJSON)
			var tags []string
			json.Unmarshal([]byte(tagsJSON), &tags)
			for _, t := range tags {
				stats.TopTags[t]++
			}
		}
	}

	return stats, nil
}

func (s *Store) Sources() ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT source FROM articles ORDER BY source")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var src string
		rows.Scan(&src)
		sources = append(sources, src)
	}
	return sources, nil
}

// ToggleBookmark flips bookmark state and returns the new value.
func (s *Store) ToggleBookmark(id int64) (bool, error) {
	var exists int
	row := s.db.QueryRow("SELECT 1 FROM bookmarks WHERE article_id = ?", id)
	if err := row.Scan(&exists); err == nil && exists == 1 {
		_, err := s.db.Exec("DELETE FROM bookmarks WHERE article_id = ?", id)
		return false, err
	}
	_, err := s.db.Exec("INSERT INTO bookmarks (article_id) VALUES (?)", id)
	return true, err
}

// BookmarkIDs returns every bookmarked article_id as a set for O(1) lookup.
func (s *Store) BookmarkIDs() (map[int64]bool, error) {
	rows, err := s.db.Query("SELECT article_id FROM bookmarks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// BookmarkedArticles returns bookmarked articles in most-recently-bookmarked order.
func (s *Store) BookmarkedArticles(limit int) ([]models.Article, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`
		SELECT a.id, a.title, a.url, a.source, a.source_type, a.summary,
		       a.score, a.tags, a.published_at, a.fetched_at, a.read,
		       a.duplicate_of
		  FROM articles a
		  JOIN bookmarks b ON b.article_id = a.id
		 WHERE a.duplicate_of IS NULL
		 ORDER BY b.bookmarked_at DESC
		 LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArticles(rows)
}

func (s *Store) Purge(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := s.db.Exec("DELETE FROM articles WHERE published_at < ? AND read = 1", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupReport summarises what one daily cleanup tick deleted so the
// caller can log it.
type CleanupReport struct {
	Sessions      int64
	MagicLinks    int64
	AlertFires    int64
	Articles      int64
	Events        int64
	NVD           int64
	OTX           int64
	WALCheckpoint string // result of PRAGMA wal_checkpoint
}

// DailyCleanup runs the retention pass: sessions, magic links, alert-fire
// dedup rows, read articles >90d, events >180d, NVD/OTX cache >90d, + WAL
// checkpoint. Each step is independent.
func (s *Store) DailyCleanup() CleanupReport {
	var r CleanupReport
	r.Sessions, _ = s.CleanupExpiredSessions()
	r.MagicLinks, _ = s.CleanupExpiredMagicLinks()
	r.AlertFires, _ = s.CleanupOldAlertFires()

	// Read articles >90d. Unread stays forever.
	if n, err := s.Purge(90 * 24 * time.Hour); err == nil {
		r.Articles = n
	}

	// Analytics events >180d (past the dashboard's longest 90d window).
	eventsCutoff := time.Now().Add(-180 * 24 * time.Hour)
	if res, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, eventsCutoff); err == nil {
		r.Events, _ = res.RowsAffected()
	}

	// NVD + OTX cache: 90d TTL since CVE metadata mutates (CVSS, KEV add).
	nvdCutoff := time.Now().Add(-90 * 24 * time.Hour)
	if res, err := s.db.Exec(`DELETE FROM cve_details WHERE fetched_at < ?`, nvdCutoff); err == nil {
		r.NVD, _ = res.RowsAffected()
	}
	if res, err := s.db.Exec(`DELETE FROM cve_otx WHERE fetched_at < ?`, nvdCutoff); err == nil {
		r.OTX, _ = res.RowsAffected()
	}

	// PASSIVE checkpoint: non-blocking, doesn't wait for readers.
	var busy, log_, checkpointed int
	if err := s.db.QueryRow(`PRAGMA wal_checkpoint(PASSIVE)`).Scan(&busy, &log_, &checkpointed); err == nil {
		r.WALCheckpoint = fmt.Sprintf("busy=%d log=%d checkpointed=%d", busy, log_, checkpointed)
	}
	return r
}

func scanArticles(rows *sql.Rows) ([]models.Article, error) {
	var articles []models.Article
	for rows.Next() {
		var a models.Article
		var tagsJSON string
		var pub, fetch sql.NullTime
		var dupOf sql.NullInt64
		err := rows.Scan(&a.ID, &a.Title, &a.URL, &a.Source, &a.SourceType,
			&a.Summary, &a.Score, &tagsJSON, &pub, &fetch, &a.Read, &dupOf)
		if err != nil {
			continue
		}
		if pub.Valid {
			a.PublishedAt = pub.Time
		}
		if fetch.Valid {
			a.FetchedAt = fetch.Time
		}
		json.Unmarshal([]byte(tagsJSON), &a.Tags)
		if a.Tags == nil {
			a.Tags = []string{}
		}
		articles = append(articles, a)
	}
	if articles == nil {
		articles = []models.Article{}
	}
	return articles, rows.Err()
}

func (s *Store) DeleteBySource(source string) error {
	_, err := s.db.Exec("DELETE FROM articles WHERE source = ?", source)
	return err
}

func (s *Store) SearchTags(tag string) ([]models.Article, error) {
	rows, err := s.db.Query(
		`SELECT id, title, url, source, source_type, summary, score, tags,
		 published_at, fetched_at, read, duplicate_of
		 FROM articles WHERE tags LIKE ? AND duplicate_of IS NULL
		 ORDER BY score DESC, published_at DESC LIMIT 100`,
		"%"+strings.ToLower(tag)+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArticles(rows)
}
