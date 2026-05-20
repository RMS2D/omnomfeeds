package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/curated"
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/mitre"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/sources"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Enrichment bundles optional intel sources that hydrate CVE / T-code chips.
// Any field can be nil; the server returns 503 from the matching endpoint.
type Enrichment struct {
	MITRE mitre.Map
	NVD   *cve.NVDClient
	EPSS  *cve.EPSSClient
	AI    ai.Summarizer
}

type Server struct {
	store       *storage.Store
	sources     []sources.Source
	fastSources []sources.Source
	scorer      *scoring.Scorer
	cfg         *config.Config
	http        *http.Server
	status      map[string]*models.SourceStatus
	enrich      *Enrichment
	stream      *streamHub

	// Cached AI digest: regenerating costs API budget, so we hold the latest
	// brief for 1 hour. Force-refresh via POST /api/digest.
	digestMu      sync.Mutex
	digestText    string
	digestAt      time.Time
	digestArticles int
}

func New(store *storage.Store, srcs []sources.Source, fastSrcs []sources.Source, scorer *scoring.Scorer, cfg *config.Config, webFS fs.FS, enr *Enrichment) *Server {
	s := &Server{
		store:       store,
		sources:     srcs,
		fastSources: fastSrcs,
		scorer:      scorer,
		cfg:         cfg,
		status:      make(map[string]*models.SourceStatus),
		enrich:      enr,
		stream:      newStreamHub(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/articles", s.handleArticles)
	mux.HandleFunc("/api/articles/read", s.handleMarkRead)
	mux.HandleFunc("/api/articles/readall", s.handleMarkAllRead)
	mux.HandleFunc("/api/articles/dupes", s.handleDuplicates)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/sources", s.handleSources)
	mux.HandleFunc("/api/refresh", s.handleRefresh)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/bluesky", s.handleConfigBluesky)
	mux.HandleFunc("/api/config/accounts", s.handleConfigAccounts)
	mux.HandleFunc("/api/config/bazaar", s.handleConfigBazaar)
	mux.HandleFunc("/api/config/github", s.handleConfigGitHub)
	// Editorial curated lists (one-click subscribe targets)
	mux.HandleFunc("/api/curated/bluesky", s.handleCuratedBluesky)
	// Scoring rules so the UI can show what's considered "security-related"
	mux.HandleFunc("/api/scoring", s.handleScoring)
	// Enrichment endpoints
	mux.HandleFunc("/api/mitre", s.handleMitreMap)
	mux.HandleFunc("/api/mitre/", s.handleMitreTechnique)
	mux.HandleFunc("/api/cve/", s.handleCVE)
	// Server-Sent Events stream for real-time refresh notifications
	mux.HandleFunc("/api/stream", s.handleStream)
	// AI digest (BYOK)
	mux.HandleFunc("/api/digest", s.handleDigest)
	// Serve static frontend from the provided filesystem. main passes an
	// embed.FS in release builds; tests can pass os.DirFS for live editing.
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	s.http = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: cors(mux),
	}
	return s
}

func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.http.Shutdown(ctx)
}

func (s *Server) FetchAll() {
	s.fetchGroup(s.sources)
	s.fetchGroup(s.fastSources)
}

func (s *Server) FetchFast() {
	s.fetchGroup(s.fastSources)
}

func (s *Server) fetchGroup(srcs []sources.Source) {
	for _, src := range srcs {
		go func(src sources.Source) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			status := &models.SourceStatus{
				Name: src.Name(),
				Type: src.Type(),
			}

			// Tell the UI which source we're about to bite into. The "feeding"
			// event powers the live ticker in the status bar.
			if s.stream != nil {
				s.stream.Broadcast("feeding", fmt.Sprintf(`{"source":%q}`, src.Name()))
			}

			articles, err := src.Fetch(ctx)
			if err != nil {
				log.Printf("[%s] fetch error: %v", src.Name(), err)
				status.LastError = err.Error()
				status.LastFetch = time.Now()
				s.status[src.Name()] = status
				return
			}

			count := 0
			for i := range articles {
				score, tags := s.scorer.Score(&articles[i])
				if score > articles[i].Score {
					articles[i].Score = score
				}

				tagMap := make(map[string]bool)
				for _, t := range articles[i].Tags {
					tagMap[t] = true
				}
				for _, t := range tags {
					tagMap[t] = true
				}

				var mergedTags []string
				for t := range tagMap {
					mergedTags = append(mergedTags, t)
				}
				articles[i].Tags = mergedTags

				if articles[i].Score == 0 {
					continue
				}
				if err := s.store.Upsert(articles[i]); err == nil {
					count++
				}
			}

			status.LastFetch = time.Now()
			status.ItemCount = count
			s.status[src.Name()] = status
			log.Printf("[%s] fetched %d articles", src.Name(), count)
			// Push a refresh hint to any SSE clients so the UI can pull immediately
			// instead of waiting for its polling interval. count==0 still broadcasts
			// so the LIVE indicator flashes (signals "we're alive, just nothing new").
			if s.stream != nil {
				s.stream.Broadcast("refresh", fmt.Sprintf(`{"source":%q,"new":%d}`, src.Name(), count))
			}
		}(src)
	}
}

func (s *Server) handleArticles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minScore, _ := strconv.Atoi(q.Get("min_score"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	filter := storage.ListFilter{
		Source:      q.Get("source"),
		SourceType:  q.Get("source_type"),
		ExcludeType: q.Get("exclude_type"),
		MinScore:    minScore,
		HasIOCs:     q.Get("has_iocs") == "true",
		Search:      q.Get("search"),
		Unread:      q.Get("unread") == "true",
		ShowDupes:   q.Get("show_dupes") == "true",
		Since:       parseSince(q.Get("since")),
		Limit:       limit,
		Offset:      offset,
	}

	articles, err := s.store.List(filter)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, articles)
}

func (s *Server) handleMarkRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	s.store.MarkRead(body.ID)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *Server) handleMarkAllRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	s.store.MarkAllRead()
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *Server) handleDuplicates(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid id"})
		return
	}
	dupes, err := s.store.DuplicatesOf(id)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, dupes)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, stats)
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	var statuses []*models.SourceStatus
	for _, st := range s.status {
		statuses = append(statuses, st)
	}
	writeJSON(w, 200, statuses)
}

func (s *Server) handleCuratedBluesky(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, curated.Bluesky)
}

func (s *Server) handleScoring(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"categories": s.scorer.Categories(),
		"how_it_works": "Every fetched article is scored 0-100 against these keyword categories. " +
			"Score is the sum of category weights for each category that matched (case-insensitive substring match against title + summary). " +
			"Articles that score zero (nothing matched) are dropped at ingest and never stored. " +
			"Bluesky watched-account posts go through the same filter: an off-topic post by a security researcher won't appear.",
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	s.FetchAll()
	writeJSON(w, 200, map[string]string{"ok": "true", "message": "refresh started"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	safe := s.cfg.SafeCopy()
	writeJSON(w, 200, safe)
}

func (s *Server) handleConfigBluesky(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var body struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if body.Identifier != "" {
		s.cfg.Bluesky.Identifier = body.Identifier
	}
	if body.Password != "" && body.Password != "********" {
		s.cfg.Bluesky.Password = body.Password
	}
	s.cfg.Bluesky.Enabled = true
	if err := s.cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true", "message": "saved, restart to apply"})
}

func (s *Server) handleConfigAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		writeJSON(w, 200, s.cfg.Bluesky.WatchedAccounts)
		return
	}
	if r.Method == "POST" {
		var body struct {
			Action string `json:"action"`
			Handle string `json:"handle"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		handle := strings.TrimPrefix(strings.TrimSpace(body.Handle), "@")
		if handle == "" {
			writeJSON(w, 400, map[string]string{"error": "handle required"})
			return
		}
		switch body.Action {
		case "add":
			for _, h := range s.cfg.Bluesky.WatchedAccounts {
				if h == handle {
					writeJSON(w, 200, map[string]string{"ok": "true", "message": "already watched"})
					return
				}
			}
			s.cfg.Bluesky.WatchedAccounts = append(s.cfg.Bluesky.WatchedAccounts, handle)
		case "remove":
			var filtered []string
			for _, h := range s.cfg.Bluesky.WatchedAccounts {
				if h != handle {
					filtered = append(filtered, h)
				}
			}
			s.cfg.Bluesky.WatchedAccounts = filtered
		default:
			writeJSON(w, 400, map[string]string{"error": "action must be add or remove"})
			return
		}
		if err := s.cfg.Save(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": "true", "accounts": s.cfg.Bluesky.WatchedAccounts})
		return
	}
	w.WriteHeader(405)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func parseSince(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	durations := map[string]time.Duration{
		"1h":  1 * time.Hour,
		"6h":  6 * time.Hour,
		"12h": 12 * time.Hour,
		"24h": 24 * time.Hour,
		"3d":  3 * 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
	}
	if d, ok := durations[s]; ok {
		return time.Now().UTC().Add(-d)
	}
	return time.Time{}
}

// --- Configuration API Endpoints ---

// --- Enrichment handlers ---

// handleMitreMap returns the compact {id: name} map for the frontend.
func (s *Server) handleMitreMap(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.MITRE == nil {
		writeJSON(w, 503, map[string]string{"error": "mitre not loaded"})
		return
	}
	writeJSON(w, 200, s.enrich.MITRE.CompactNames())
}

// handleMitreTechnique returns the full technique record for a single T-code.
func (s *Server) handleMitreTechnique(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.MITRE == nil {
		writeJSON(w, 503, map[string]string{"error": "mitre not loaded"})
		return
	}
	id := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/mitre/")))
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "technique id required"})
		return
	}
	t := s.enrich.MITRE[id]
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "not found", "id": id})
		return
	}
	writeJSON(w, 200, t)
}

// handleDigest returns the AI-generated "what happened today" brief.
// GET serves the cached brief (or generates one if cache empty / stale).
// POST forces a fresh generation, ignoring the cache.
func (s *Server) handleDigest(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.AI == nil {
		writeJSON(w, 503, map[string]any{
			"error":    "no AI provider configured",
			"hint":     "set ANTHROPIC_API_KEY or OPENAI_API_KEY env var, then restart secfeed",
			"provider": "",
		})
		return
	}
	force := r.Method == "POST"

	s.digestMu.Lock()
	cachedText := s.digestText
	cachedAt := s.digestAt
	cachedN := s.digestArticles
	s.digestMu.Unlock()

	if !force && cachedText != "" && time.Since(cachedAt) < time.Hour {
		writeJSON(w, 200, map[string]any{
			"digest":         cachedText,
			"cached":         true,
			"age_seconds":    int(time.Since(cachedAt).Seconds()),
			"provider":       s.enrich.AI.Name(),
			"article_count":  cachedN,
			"generated_at":   cachedAt.Format(time.RFC3339),
		})
		return
	}

	// Pull the top recent articles to summarise.
	articles, err := s.store.List(storage.ListFilter{
		Since:    time.Now().Add(-24 * time.Hour),
		MinScore: 5,
		Limit:    200,
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if len(articles) == 0 {
		writeJSON(w, 200, map[string]string{"error": "no scored articles in the last 24h - nothing to summarise"})
		return
	}
	// Sort by score desc and cap to MaxArticles
	sort.Slice(articles, func(i, j int) bool { return articles[i].Score > articles[j].Score })
	if len(articles) > ai.MaxArticles {
		articles = articles[:ai.MaxArticles]
	}

	aiArticles := make([]ai.Article, 0, len(articles))
	for _, a := range articles {
		aiArticles = append(aiArticles, ai.Article{
			Title:   a.Title,
			Score:   a.Score,
			Tags:    a.Tags,
			Source:  a.Source,
			Summary: a.Summary,
		})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 95*time.Second)
	defer cancel()

	text, err := s.enrich.AI.Summarize(ctx, aiArticles)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "provider": s.enrich.AI.Name()})
		return
	}

	s.digestMu.Lock()
	s.digestText = text
	s.digestAt = time.Now()
	s.digestArticles = len(articles)
	s.digestMu.Unlock()

	writeJSON(w, 200, map[string]any{
		"digest":         text,
		"cached":         false,
		"provider":       s.enrich.AI.Name(),
		"article_count":  len(articles),
		"generated_at":   time.Now().Format(time.RFC3339),
	})
}

// handleCVE returns NVD + EPSS detail for a CVE. KEV status is already on the
// article tags from the scorer, so the frontend overlays that itself.
func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.NVD == nil {
		writeJSON(w, 503, map[string]string{"error": "nvd client not available"})
		return
	}
	id := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/cve/")))
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "cve id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	d, err := s.enrich.NVD.Get(ctx, id)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error(), "id": id})
		return
	}
	if s.enrich.EPSS != nil {
		if e := s.enrich.EPSS.Get(id); e != nil {
			d.EPSSScore = e.Score
			d.EPSSPercentile = e.Percentile
		}
	}
	writeJSON(w, 200, d)
}

func (s *Server) handleConfigBazaar(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var body config.BazaarConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if body.APIKey != "" && body.APIKey != "********" {
		s.cfg.MalwareBazaar.APIKey = body.APIKey
	}
	s.cfg.Save()
	writeJSON(w, 200, map[string]string{"ok": "true", "message": "MalwareBazaar settings saved"})
}

func (s *Server) handleConfigGitHub(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var body config.GitHubConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	s.cfg.GitHub.Enabled = body.Enabled
	if body.Token != "" && body.Token != "********" {
		s.cfg.GitHub.Token = body.Token
	}
	s.cfg.Save()
	writeJSON(w, 200, map[string]string{"ok": "true", "message": "GitHub settings saved"})
}
