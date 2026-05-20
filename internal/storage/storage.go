package storage

import (
	"database/sql"
	"encoding/json"
	"github.com/RMS2D/omnomfeeds/internal/dedup"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA foreign_keys=ON")

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

// DB returns the underlying *sql.DB so enrichment packages (mitre/cve) can
// share the same SQLite file for their own tables. Read/write only.
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
	return nil
}

func (s *Store) Upsert(a models.Article) error {
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
}

func (s *Store) List(f ListFilter) ([]models.Article, error) {
	query := `SELECT id, title, url, source, source_type, summary, score, tags,
	          published_at, fetched_at, read, duplicate_of FROM articles WHERE 1=1`
	var args []interface{}

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
		query += " AND read = 0"
	}
	if f.HasIOCs {
		query += " AND (tags LIKE '%sha256:%' OR tags LIKE '%md5:%' OR tags LIKE '%ext:%')"
	}
	if !f.Since.IsZero() {
		query += " AND published_at >= ?"
		args = append(args, f.Since)
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

func (s *Store) Purge(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := s.db.Exec("DELETE FROM articles WHERE published_at < ? AND read = 1", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
