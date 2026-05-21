package storage

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/models"
)

// AlertRule is one webhook-firing rule belonging to a user. The shape
// maps 1:1 to the user_alert_rules table that's already in the schema.
//
// Kind ∈ {"kev", "keyword", "cve", "tag"}:
//
//	kev      - every article newly tagged with kev:* fires
//	keyword  - case-insensitive substring match against title+summary
//	cve      - exact match against any tag of the form "cve-YYYY-NNNN"
//	tag      - exact match against any tag (case-insensitive)
//
// Channel ∈ {"slack", "discord", "generic"} - controls the body format
// of the outgoing HTTP POST. ChannelTarget is the destination webhook URL.
type AlertRule struct {
	ID            string
	UserID        string
	Kind          string
	Pattern       string
	Channel       string
	ChannelTarget string
	Enabled       bool
	CreatedAt     time.Time
	LastFiredAt   *time.Time
}

// ListAlertRules returns every rule a user has configured, newest first.
func (s *Store) ListAlertRules(userID string) ([]AlertRule, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, kind, pattern, channel, COALESCE(channel_target, ''),
		        enabled, created_at, last_fired_at
		   FROM user_alert_rules
		  WHERE user_id = ?
		  ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var enabled int
		var lastFired sql.NullTime
		if err := rows.Scan(&r.ID, &r.UserID, &r.Kind, &r.Pattern, &r.Channel,
			&r.ChannelTarget, &enabled, &r.CreatedAt, &lastFired); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		if lastFired.Valid {
			r.LastFiredAt = &lastFired.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateAlertRule writes a new rule. Caller generates the ID (UUID).
func (s *Store) CreateAlertRule(r AlertRule) error {
	if r.ID == "" {
		r.ID = NewUUID()
	}
	en := 0
	if r.Enabled {
		en = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO user_alert_rules
		   (id, user_id, kind, pattern, channel, channel_target, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.UserID, r.Kind, r.Pattern, r.Channel, r.ChannelTarget, en,
	)
	return err
}

// UpdateAlertRule changes pattern / channel / channel_target / enabled on
// an existing rule. Kind is immutable (delete + recreate if you need it).
func (s *Store) UpdateAlertRule(r AlertRule) error {
	en := 0
	if r.Enabled {
		en = 1
	}
	res, err := s.db.Exec(
		`UPDATE user_alert_rules
		    SET pattern = ?, channel = ?, channel_target = ?, enabled = ?
		  WHERE id = ? AND user_id = ?`,
		r.Pattern, r.Channel, r.ChannelTarget, en, r.ID, r.UserID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("rule not found")
	}
	return nil
}

// DeleteAlertRule removes a rule and (via cascade) any pending fire records
// for it. user_id is required in the WHERE so a user can only delete their
// own rules even if they hand-craft an ID.
func (s *Store) DeleteAlertRule(userID, ruleID string) error {
	_, err := s.db.Exec(
		`DELETE FROM user_alert_rules WHERE id = ? AND user_id = ?`,
		ruleID, userID,
	)
	return err
}

// ListEnabledAlertRules is what the worker calls each tick: every enabled
// rule across every user. Cheap because the table is small.
func (s *Store) ListEnabledAlertRules() ([]AlertRule, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, kind, pattern, channel, COALESCE(channel_target, ''),
		        enabled, created_at, last_fired_at
		   FROM user_alert_rules
		  WHERE enabled = 1`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var enabled int
		var lastFired sql.NullTime
		if err := rows.Scan(&r.ID, &r.UserID, &r.Kind, &r.Pattern, &r.Channel,
			&r.ChannelTarget, &enabled, &r.CreatedAt, &lastFired); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		if lastFired.Valid {
			r.LastFiredAt = &lastFired.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkDuplicate sets dupeID's duplicate_of column to primaryID. Cheap
// idempotent UPDATE; safe to call even if the row is already marked.
func (s *Store) MarkDuplicate(dupeID, primaryID int64) error {
	_, err := s.db.Exec(
		`UPDATE articles SET duplicate_of = ? WHERE id = ? AND duplicate_of IS NULL`,
		primaryID, dupeID,
	)
	return err
}

// ArticlesForDedup returns recent non-duplicate articles with a score
// above minScore. Used by the dedup worker; capped to keep the LLM batch
// reasonable.
func (s *Store) ArticlesForDedup(since time.Time, minScore, limit int) ([]models.Article, error) {
	if limit <= 0 {
		limit = 60
	}
	rows, err := s.db.Query(
		`SELECT id, title, url, source, source_type, summary, score, tags,
		        published_at, fetched_at
		   FROM articles
		  WHERE fetched_at >= ? AND duplicate_of IS NULL AND score >= ?
		  ORDER BY fetched_at DESC
		  LIMIT ?`,
		since, minScore, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArticles(rows)
}

// ArticlesForAlerts returns articles fetched after `since`, only including
// columns the matcher and formatter need. Capped to a generous limit so a
// firehose ingest cycle doesn't blow memory.
func (s *Store) ArticlesForAlerts(since time.Time) ([]models.Article, error) {
	rows, err := s.db.Query(
		`SELECT id, title, url, source, source_type, summary, score, tags,
		        published_at, fetched_at
		   FROM articles
		  WHERE fetched_at >= ? AND duplicate_of IS NULL
		  ORDER BY fetched_at DESC
		  LIMIT 500`,
		since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArticles(rows)
}

// AlreadyFired reports whether (ruleID, articleID) has already triggered.
// Used by the worker to dedup; once fired we never fire again for that pair.
func (s *Store) AlreadyFired(ruleID string, articleID int64) (bool, error) {
	var dummy int
	err := s.db.QueryRow(
		`SELECT 1 FROM alert_fires WHERE rule_id = ? AND article_id = ?`,
		ruleID, articleID,
	).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RecordFire inserts the dedup row and bumps the rule's last_fired_at in
// one transaction. Idempotent: if the row already exists it's a no-op.
func (s *Store) RecordFire(ruleID string, articleID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO alert_fires (rule_id, article_id) VALUES (?, ?)
		 ON CONFLICT(rule_id, article_id) DO NOTHING`,
		ruleID, articleID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE user_alert_rules SET last_fired_at = CURRENT_TIMESTAMP WHERE id = ?`,
		ruleID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// CleanupOldAlertFires drops dedup rows older than 14 days. The window has
// to be longer than the article-fetched cutoff the worker uses so we don't
// re-fire on articles whose dedup row aged out but which are still being
// scanned. Called from the same cleanup goroutine that prunes sessions.
func (s *Store) CleanupOldAlertFires() (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM alert_fires WHERE fired_at < datetime('now', '-14 days')`,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ArticleMatchesRule returns true when the article should fire the rule.
// The matcher is intentionally cheap: substring + tag-prefix checks, no
// regex. Adding regex would need careful per-rule timeout guards.
func ArticleMatchesRule(a *models.Article, r *AlertRule) bool {
	switch r.Kind {
	case "kev":
		for _, t := range a.Tags {
			if strings.HasPrefix(strings.ToLower(t), "kev:") {
				return true
			}
		}
		return false
	case "keyword":
		if r.Pattern == "" {
			return false
		}
		needle := strings.ToLower(r.Pattern)
		hay := strings.ToLower(a.Title + " " + a.Summary)
		return strings.Contains(hay, needle)
	case "cve":
		if r.Pattern == "" {
			return false
		}
		want := strings.ToLower(r.Pattern)
		// CVE tags are stored exactly as "CVE-YYYY-NNNN" (case may vary).
		for _, t := range a.Tags {
			if strings.EqualFold(t, want) {
				return true
			}
		}
		// Also accept body matches so a CVE mentioned in the title hits
		// even if the scorer didn't tag it (edge case for very-fresh CVEs).
		if strings.Contains(strings.ToLower(a.Title), want) {
			return true
		}
		return false
	case "tag":
		if r.Pattern == "" {
			return false
		}
		want := strings.ToLower(r.Pattern)
		for _, t := range a.Tags {
			if strings.EqualFold(t, want) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
