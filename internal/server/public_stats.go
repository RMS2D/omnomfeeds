package server

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/actors"
)

// publicStats is the small, cheap payload the landing page shows as a
// trust strip. Numbers come straight from the DB, capped at the latest
// 30 / 7 day windows, cached in-memory for 5 minutes so a landing-page
// spike doesn't hammer SQLite.
type publicStats struct {
	ArticlesTotal       int64 `json:"articles_total"`
	Articles30d         int64 `json:"articles_30d"`
	SourcesActive       int   `json:"sources_active"`
	SourcesTotal        int   `json:"sources_total"`
	CVEsHot7d           int   `json:"cves_hot_7d"`
	KEVPops7d           int   `json:"kev_pops_7d"`
	ActorsTracked       int   `json:"actors_tracked"`
	MalwareTracked      int   `json:"malware_tracked"`
	LastFetchAgoSeconds int64 `json:"last_fetch_ago_seconds"`
	GeneratedAt         int64 `json:"generated_at"`
}

type publicStatsCache struct {
	mu   sync.Mutex
	data *publicStats
	at   time.Time
}

var statsCache = &publicStatsCache{}

// handlePublicStats serves /api/landing/stats. Public, no auth, cached
// 5 min. Designed for the landing page trust strip; the heavier
// /api/stats endpoint stays for the in-app source breakdown.
func (s *Server) handlePublicStats(w http.ResponseWriter, r *http.Request) {
	statsCache.mu.Lock()
	if statsCache.data != nil && time.Since(statsCache.at) < 5*time.Minute {
		out := *statsCache.data
		statsCache.mu.Unlock()
		writeJSON(w, http.StatusOK, out)
		return
	}
	statsCache.mu.Unlock()

	out := s.buildPublicStats()

	statsCache.mu.Lock()
	statsCache.data = out
	statsCache.at = time.Now()
	statsCache.mu.Unlock()

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) buildPublicStats() *publicStats {
	out := &publicStats{
		GeneratedAt:    time.Now().Unix(),
		ActorsTracked:  len(actors.Actors),
		MalwareTracked: len(actors.Malwares),
	}

	db := s.store.DB()

	// Total articles (de-duped). The headline number for "stuff we've
	// seen", since launch.
	db.QueryRow(`SELECT COUNT(*) FROM articles WHERE duplicate_of IS NULL`).Scan(&out.ArticlesTotal)

	// Articles in the last 30 days. The "active feed" number.
	db.QueryRow(`
		SELECT COUNT(*) FROM articles
		WHERE duplicate_of IS NULL
		  AND published_at >= datetime('now','-30 days')
	`).Scan(&out.Articles30d)

	// Sources: total = configured feeds; active = at least one successful
	// fetch in the last 24h (any article newer than that from this source).
	sourceCounts := map[string]int{}
	rows, err := db.Query(`
		SELECT source, COUNT(*) FROM articles
		WHERE duplicate_of IS NULL
		  AND fetched_at >= datetime('now','-24 hours')
		GROUP BY source
	`)
	if err == nil {
		for rows.Next() {
			var name string
			var n int
			if err := rows.Scan(&name, &n); err == nil {
				sourceCounts[name] = n
			}
		}
		rows.Close()
	}
	out.SourcesActive = len(sourceCounts)
	s.statusMu.RLock()
	out.SourcesTotal = len(s.status)
	s.statusMu.RUnlock()

	// Distinct CVE IDs surfaced in the last 7 days. Tags are stored
	// as bare CVE-XXXX-XXXX strings (uppercase, no prefix); json_each
	// walks the JSON array column per-row and we LIKE on the value.
	db.QueryRow(`
		SELECT COUNT(DISTINCT je.value)
		FROM articles a, json_each(a.tags) je
		WHERE a.duplicate_of IS NULL
		  AND a.published_at >= datetime('now','-7 days')
		  AND je.value LIKE 'CVE-%'
	`).Scan(&out.CVEsHot7d)

	// KEV-flagged articles in the last 7 days. The scorer tags every
	// hit as 'kev:CVE-XXXX-XXXX', so a simple LIKE on the blob catches
	// any article whose tag array contains at least one kev entry.
	db.QueryRow(`
		SELECT COUNT(*) FROM articles
		WHERE duplicate_of IS NULL
		  AND published_at >= datetime('now','-7 days')
		  AND tags LIKE '%kev:%'
	`).Scan(&out.KEVPops7d)

	// How long since the freshest article was fetched. Lets the landing
	// page show "last sip 3m ago" as a liveness signal.
	var lastFetch string
	db.QueryRow(`
		SELECT COALESCE(MAX(fetched_at), '')
		FROM articles WHERE duplicate_of IS NULL
	`).Scan(&lastFetch)
	if lastFetch != "" {
		// fetched_at lands in SQLite as Go's default time.Time.String(),
		// which includes a trailing " m=+12.345" monotonic suffix that
		// breaks time.Parse. Strip it before trying layouts.
		clean := lastFetch
		if i := strings.Index(clean, " m=+"); i > 0 {
			clean = clean[:i]
		}
		layouts := []string{
			"2006-01-02 15:04:05.999999999 -0700 MST",
			"2006-01-02 15:04:05 -0700 MST",
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05",
		}
		out.LastFetchAgoSeconds = -1
		for _, layout := range layouts {
			if t, err := time.Parse(layout, clean); err == nil {
				out.LastFetchAgoSeconds = int64(time.Since(t).Seconds())
				break
			}
		}
	} else {
		out.LastFetchAgoSeconds = -1
	}

	return out
}
