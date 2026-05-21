package cve

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const epssCSVURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// EPSSScore mirrors first.org's per-CVE exploit-probability output.
type EPSSScore struct {
	Score      float64 `json:"score"`      // [0, 1] probability of exploit in next 30d
	Percentile float64 `json:"percentile"` // [0, 1] rank vs all scored CVEs
}

// EPSSClient maintains the local EPSS table.
type EPSSClient struct {
	db *sql.DB
}

func NewEPSSClient(db *sql.DB) *EPSSClient {
	return &EPSSClient{db: db}
}

func (e *EPSSClient) EnsureTable() error {
	_, err := e.db.Exec(`
		CREATE TABLE IF NOT EXISTS epss (
			cve_id TEXT PRIMARY KEY,
			score REAL NOT NULL,
			percentile REAL NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

// Refresh pulls the latest EPSS scores CSV and upserts every row. Idempotent.
func (e *EPSSClient) Refresh(ctx context.Context) error {
	if err := e.EnsureTable(); err != nil {
		return err
	}
	log.Printf("[EPSS] downloading scores from %s", epssCSVURL)
	req, _ := http.NewRequestWithContext(ctx, "GET", epssCSVURL, nil)
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1")
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("epss: status %d", resp.StatusCode)
	}
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzr.Close()
	cr := csv.NewReader(gzr)
	cr.FieldsPerRecord = -1 // EPSS CSV has comment lines we must tolerate
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO epss (cve_id, score, percentile, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	count := 0
	for {
		rec, err := cr.Read()
		if err != nil {
			break
		}
		if len(rec) < 3 {
			continue
		}
		// EPSS CSV starts with a #model_version line and a header row "cve,epss,percentile".
		if strings.HasPrefix(rec[0], "#") || strings.EqualFold(rec[0], "cve") {
			continue
		}
		score, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			continue
		}
		pct, err := strconv.ParseFloat(rec[2], 64)
		if err != nil {
			continue
		}
		if _, err := stmt.Exec(strings.ToUpper(rec[0]), score, pct); err != nil {
			return err
		}
		count++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("[EPSS] loaded %d scores", count)
	return nil
}

// Get returns the EPSS score for a CVE, or nil if not in the local cache.
// Cheap for one-off lookups (CVE modal, etc.); use GetMany for batches
// to avoid the per-row round-trip cost.
func (e *EPSSClient) Get(cveID string) *EPSSScore {
	row := e.db.QueryRow(`SELECT score, percentile FROM epss WHERE cve_id = ?`, strings.ToUpper(strings.TrimSpace(cveID)))
	var s EPSSScore
	if err := row.Scan(&s.Score, &s.Percentile); err != nil {
		return nil
	}
	return &s
}

// GetMany resolves a list of CVE IDs in a single query, returning a
// map of upper-cased ID -> score. Missing IDs are simply absent from
// the map. Used by the hottest/trending leaderboards where N can be
// 50 and the per-CVE round-trip dominates the response time.
func (e *EPSSClient) GetMany(cveIDs []string) map[string]EPSSScore {
	out := map[string]EPSSScore{}
	if len(cveIDs) == 0 {
		return out
	}
	// De-dup + normalise. Build the IN-clause placeholder list as we
	// go; SQLite has a default limit of 999 host parameters which is
	// well above any realistic call here.
	seen := make(map[string]bool, len(cveIDs))
	args := make([]interface{}, 0, len(cveIDs))
	placeholders := make([]string, 0, len(cveIDs))
	for _, raw := range cveIDs {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		args = append(args, id)
		placeholders = append(placeholders, "?")
	}
	if len(args) == 0 {
		return out
	}
	q := `SELECT cve_id, score, percentile FROM epss WHERE cve_id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := e.db.Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s EPSSScore
		if err := rows.Scan(&id, &s.Score, &s.Percentile); err == nil {
			out[id] = s
		}
	}
	return out
}
