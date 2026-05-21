package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/actors"
	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/alerts"
	"github.com/RMS2D/omnomfeeds/internal/analytics"
	"github.com/RMS2D/omnomfeeds/internal/auth"
	"github.com/RMS2D/omnomfeeds/internal/billing"
	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/curated"
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/digestmail"
	"github.com/RMS2D/omnomfeeds/internal/mitre"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/sources"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// serverStarted is the process-start timestamp, used by /healthz to
// report uptime. serverVersion mirrors the ldflags-injected build tag.
var (
	serverStarted = time.Now()
	serverVersion = "dev"
)

// SetVersion lets main.go pipe the ldflags-injected version string
// through to the /healthz handler.
func SetVersion(v string) { serverVersion = v }

// Enrichment bundles optional intel sources that hydrate CVE / T-code chips.
// Any field can be nil; the server returns 503 from the matching endpoint.
type Enrichment struct {
	MITRE mitre.Map
	NVD   *cve.NVDClient
	EPSS  *cve.EPSSClient
	OTX   *cve.OTXClient
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
	auth        *auth.Handler    // hosted-mode only; nil for self-host
	billing     *billing.Handler // hosted-mode only + Stripe creds present

	// Optional worker handles wired in from main.go after construction.
	// Used by the admin "send test" endpoints to trigger real pipeline
	// fires on demand. Nil if the worker wasn't started (e.g. no Resend
	// key, self-host mode).
	digestWorker *digestmail.Worker
	alertsWorker *alerts.Worker

	// Cached AI digest: regenerating costs API budget, so we hold the latest
	// brief for 1 hour. Force-refresh via POST /api/digest.
	digestMu       sync.Mutex
	digestText     string
	digestAt       time.Time
	digestArticles int

	// In-memory cache for the "what changed while you were gone" summary.
	// Keyed by userID|sinceTimestamp so a fresh dismiss invalidates the
	// entry (the key shifts). TTL is 6 hours; eviction is lazy on read.
	whatsNewMu    sync.Mutex
	whatsNewCache map[string]*whatsNewEntry

	// In-memory cache for the pre-KEV velocity set (CVEs getting heat
	// across multiple curated sources but not yet in KEV). Computed once
	// then reused across all article-list requests for 5 minutes - cheap
	// enough to keep fresh, expensive enough to want pooled.
	preKEVMu    sync.Mutex
	preKEVCache map[string]int
	preKEVAt    time.Time

	// Per-IP rate limiter on AI endpoints. Guards the Anthropic bill
	// against a scraper hammering /api/digest force-refresh or the
	// per-article / per-CVE explainers. See ratelimit.go.
	aiLimiter *rateLimiter

	// analytics records who-uses-what for the admin dashboard. nil-safe;
	// Emit() returns early when nil so self-host installs that disable
	// the events table never hit the DB.
	analytics *analytics.Analytics
}

type whatsNewEntry struct {
	payload []byte
	expiry  time.Time
}

func New(store *storage.Store, srcs []sources.Source, fastSrcs []sources.Source, scorer *scoring.Scorer, cfg *config.Config, webFS fs.FS, enr *Enrichment) *Server {
	s := &Server{
		store:       store,
		sources:     srcs,
		fastSources: fastSrcs,
		scorer:      scorer,
		cfg:         cfg,
		status:        make(map[string]*models.SourceStatus),
		enrich:        enr,
		stream:        newStreamHub(),
		whatsNewCache: make(map[string]*whatsNewEntry),
		// 20 AI calls per minute per IP. Authenticated Pro users
		// rarely hit this (cache hits dominate); scrapers slam into
		// it fast.
		aiLimiter: newRateLimiter(20, 60*time.Second),
		analytics: analytics.New(store.DB()),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/articles", s.handleArticles)
	mux.HandleFunc("/api/landing/stats", s.handlePublicStats)
	mux.HandleFunc("/api/articles/read", s.handleMarkRead)
	mux.HandleFunc("/api/articles/readall", s.handleMarkAllRead)
	mux.HandleFunc("/api/articles/dupes", s.handleDuplicates)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/sources", s.handleSources)
	mux.HandleFunc("/api/refresh", s.handleRefresh)
	mux.HandleFunc("/api/config", s.handleConfig)
	// Global-config mutation endpoints. In hosted mode these require admin
	// (set ADMIN_EMAILS=). In self-host mode they stay open since there's
	// no auth concept and the user IS the operator.
	mux.Handle("/api/config/bluesky", adminGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleConfigBluesky)))
	mux.Handle("/api/config/accounts", adminGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleConfigAccounts)))
	mux.Handle("/api/config/bazaar", adminGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleConfigBazaar)))
	mux.Handle("/api/config/github", adminGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleConfigGitHub)))
	// Editorial curated lists (one-click subscribe targets)
	mux.HandleFunc("/api/curated/bluesky", s.handleCuratedBluesky)
	// Scoring rules so the UI can show what's considered "security-related"
	mux.HandleFunc("/api/scoring", s.handleScoring)
	// Momentum: which tags are heating up week-over-week. Free for all.
	mux.HandleFunc("/api/momentum", s.handleMomentum)
	// Worm's mood: cheap public endpoint the UI polls to colour the worm
	// sprite (hibernating / eating / frenzy) based on KEV velocity.
	mux.HandleFunc("/api/worm/mood", s.handleWormMood)
	// Liveness probe for uptime monitors. Returns 200 with a tiny JSON
	// payload when the process is up and the DB connection works. No
	// auth, no rate limit, no DB-heavy queries - just enough to prove
	// the service is alive.
	mux.HandleFunc("/healthz", s.handleHealthz)
	// Hottest CVEs leaderboard - public ticker fodder, drives the /live page.
	mux.HandleFunc("/api/cves/hottest", s.handleHottestCVEs)
	// Pre-KEV velocity: CVEs being talked about by multiple sources but
	// not yet on the CISA KEV list. Public; powers the per-row prekev tag
	// and a future leaderboard panel.
	mux.HandleFunc("/api/cves/pre-kev", s.handlePreKEV)
	// Patch Tuesday briefs (Microsoft / Adobe / Oracle calendar-pinned).
	// Public read; the worker generates them on patch days. Frontend
	// renders the most recent per vendor as a banner.
	mux.HandleFunc("/api/briefs/patch", s.handlePatchBriefs)
	// ATT&CK Navigator layer export. Two modes:
	//   /api/attack/export             - public, last 30d global TTP freq
	//   /api/attack/export?scope=mine  - authed, user's bookmarks (Pro)
	mux.HandleFunc("/api/attack/export", s.handleAttackExport)
	// Threat-actor / malware-family lookup. Returns metadata for the
	// "Insight Card" modal when a user clicks an actor: or malware: chip.
	mux.HandleFunc("/api/actors/", s.handleActorLookup)
	mux.HandleFunc("/api/malware/", s.handleMalwareLookup)
	// Enrichment endpoints
	mux.HandleFunc("/api/mitre", s.handleMitreMap)
	mux.HandleFunc("/api/mitre/", s.handleMitreTechnique)
	mux.HandleFunc("/api/cve/", s.handleCVE)
	// Server-Sent Events stream for real-time refresh notifications
	mux.HandleFunc("/api/stream", s.handleStream)
	// AI digest. In hosted mode the brief uses the operator's Anthropic
	// key (which costs real money per call), so Pro is required. Self-host
	// uses BYOK from env and stays open. Per-IP rate limit applies on
	// top of the Pro gate so a single Pro account can't burn through
	// the budget either (cache covers them anyway, but defence in depth).
	mux.Handle("/api/digest", s.aiRateLimit("digest", proGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleDigest))))
	// Per-article AI explainer. Pro-gated in hosted mode; cached per
	// article.id so repeat clicks across users only cost one LLM call.
	mux.Handle("/api/articles/explain/", s.aiRateLimit("explain", proGate(cfg.Hosted.Enabled, http.HandlerFunc(s.handleArticleExplain))))
	// Per-user identity endpoint. Returns nil for anonymous; populated when
	// auth middleware resolves a session cookie.
	mux.HandleFunc("/api/me", s.handleMe)
	// Which login methods this deployment exposes. Used by /login.html to
	// render the right buttons.
	mux.HandleFunc("/api/auth/methods", s.handleAuthMethods)

	// In hosted mode, register OAuth + magic-link + logout under /auth/,
	// and wrap the whole mux in the session-resolving middleware so any
	// endpoint can read auth.UserFromContext(r.Context()).
	if cfg.Hosted.Enabled {
		ah, err := auth.NewHandler(cfg.Hosted, store)
		if err != nil {
			log.Printf("[auth] disabled: %v", err)
		} else {
			s.auth = ah
			ah.Mount(mux)
		}

		bh, err := billing.NewHandler(cfg.Hosted, store)
		if err != nil {
			log.Printf("[billing] disabled: %v", err)
		} else {
			s.billing = bh
			bh.SetAnalytics(s.analytics)
			bh.Mount(mux)
		}

		// Per-user sync endpoints. Settings, bookmarks, read marks; all
		// require an authenticated session.
		mux.Handle("/api/me/settings", auth.RequireUser(http.HandlerFunc(s.handleMeSettings)))
		mux.Handle("/api/me/bookmarks", auth.RequireUser(http.HandlerFunc(s.handleMeBookmarks)))
		mux.Handle("/api/me/bookmarks/", auth.RequireUser(http.HandlerFunc(s.handleMeBookmarks)))
		mux.Handle("/api/me/read", auth.RequireUser(http.HandlerFunc(s.handleMeRead)))
		mux.Handle("/api/me/bluesky/accounts", auth.RequireUser(http.HandlerFunc(s.handleMeBskyAccounts)))

		// Pro: per-user webhook alert rules. The handler enforces the Pro
		// gate internally so the same handler can serve list / create /
		// update / delete with consistent error messages.
		mux.Handle("/api/me/alerts", auth.RequireUser(http.HandlerFunc(s.handleMeAlerts)))
		mux.Handle("/api/me/alerts/", auth.RequireUser(http.HandlerFunc(s.handleMeAlerts)))

		// Pro: per-user REST API tokens. Browser must be cookie-authed
		// (so a stolen token can't itself mint more tokens); the handler
		// enforces the Pro gate internally.
		mux.Handle("/api/me/tokens", auth.RequireUser(http.HandlerFunc(s.handleMeTokens)))
		mux.Handle("/api/me/tokens/", auth.RequireUser(http.HandlerFunc(s.handleMeTokens)))

		// Pro: saved searches / channels.
		mux.Handle("/api/me/channels", auth.RequireUser(http.HandlerFunc(s.handleMeChannels)))
		mux.Handle("/api/me/channels/", auth.RequireUser(http.HandlerFunc(s.handleMeChannels)))

		// Pro: AI personalization. Re-sorts the visible feed by relevance
		// to a user-supplied profile blurb.
		mux.Handle("/api/me/personalize", auth.RequireUser(http.HandlerFunc(s.handleMePersonalize)))

		// Pro: email digest preference (off / daily / weekly).
		mux.Handle("/api/me/digest", auth.RequireUser(http.HandlerFunc(s.handleMeDigest)))

		// Pro: "what changed while you were gone" banner backing endpoint.
		// GET returns summary or {dismissed:true}; POST dismisses + bumps
		// the timestamp so the banner stays hidden for the next 24h.
		mux.Handle("/api/me/whats-new", auth.RequireUser(http.HandlerFunc(s.handleMeWhatsNew)))

		// Admin dashboard: /admin (HTML) + /api/admin/stats (JSON). Both
		// re-check IsAdmin inside the handler / middleware so a non-admin
		// gets bounced even if they hand-craft a URL.
		mux.Handle("/api/admin/stats", auth.RequireAdmin(http.HandlerFunc(s.handleAdminStats)))
		mux.Handle("/api/admin/digest/send-test", auth.RequireAdmin(http.HandlerFunc(s.handleAdminDigestSendTest)))
		mux.Handle("/api/admin/alert/send-test", auth.RequireAdmin(http.HandlerFunc(s.handleAdminAlertSendTest)))
		mux.Handle("/api/admin/analytics/summary", auth.RequireAdmin(http.HandlerFunc(s.handleAdminAnalyticsSummary)))
		mux.Handle("/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handleAdminPage(w, r, webFS)
		}))
		mux.Handle("/admin/analytics", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFile(w, r, webFS, "admin-analytics.html")
		})))
	}

	// Static frontend. In self-host mode "/" is the app itself; in hosted
	// mode "/" is the marketing landing and "/app" is the reader UI. Both
	// routes ultimately read from the same embed.FS, just with different
	// default files.
	fileServer := http.FileServer(http.FS(webFS))
	if cfg.Hosted.Enabled {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/":
				s.emit(w, r, analytics.EvPageView, "/", nil)
				serveEmbeddedFile(w, r, webFS, "landing.html")
			case r.URL.Path == "/app", strings.HasPrefix(r.URL.Path, "/app/"):
				s.emit(w, r, analytics.EvPageView, "/app", nil)
				serveEmbeddedFile(w, r, webFS, "index.html")
			case r.URL.Path == "/privacy":
				serveEmbeddedFile(w, r, webFS, "privacy.html")
			case r.URL.Path == "/terms":
				serveEmbeddedFile(w, r, webFS, "terms.html")
			case r.URL.Path == "/live":
				s.emit(w, r, analytics.EvPageView, "/live", nil)
				serveEmbeddedFile(w, r, webFS, "live.html")
			case r.URL.Path == "/pro":
				s.emit(w, r, analytics.EvPageView, "/pro", nil)
				s.emit(w, r, analytics.EvProView, "", nil)
				serveEmbeddedFile(w, r, webFS, "pro-preview.html")
			case r.URL.Path == "/robots.txt":
				serveEmbeddedFileAs(w, r, webFS, "robots.txt", "text/plain; charset=utf-8")
			case r.URL.Path == "/sitemap.xml":
				serveEmbeddedFileAs(w, r, webFS, "sitemap.xml", "application/xml; charset=utf-8")
			case r.URL.Path == "/favicon.svg":
				serveEmbeddedFileAs(w, r, webFS, "favicon.svg", "image/svg+xml")
			case r.URL.Path == "/og-cover.svg":
				serveEmbeddedFileAs(w, r, webFS, "og-cover.svg", "image/svg+xml")
			case r.URL.Path == "/og-cover.png":
				serveEmbeddedFileAs(w, r, webFS, "og-cover.png", "image/png")
			default:
				fileServer.ServeHTTP(w, r)
			}
		})
	} else {
		// Self-host: pretty URLs for the legal pages too so the same links
		// embedded in the templates work either way.
		mux.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFile(w, r, webFS, "privacy.html")
		})
		mux.HandleFunc("/terms", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFile(w, r, webFS, "terms.html")
		})
		mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFile(w, r, webFS, "live.html")
		})
		mux.HandleFunc("/pro", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFile(w, r, webFS, "pro-preview.html")
		})
		mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFileAs(w, r, webFS, "robots.txt", "text/plain; charset=utf-8")
		})
		mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFileAs(w, r, webFS, "sitemap.xml", "application/xml; charset=utf-8")
		})
		mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFileAs(w, r, webFS, "favicon.svg", "image/svg+xml")
		})
		mux.HandleFunc("/og-cover.svg", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFileAs(w, r, webFS, "og-cover.svg", "image/svg+xml")
		})
		mux.HandleFunc("/og-cover.png", func(w http.ResponseWriter, r *http.Request) {
			serveEmbeddedFileAs(w, r, webFS, "og-cover.png", "image/png")
		})
		mux.Handle("/", fileServer)
	}

	var handler http.Handler = mux
	if s.auth != nil {
		handler = s.auth.Middleware(handler)
	}
	s.http = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: cors(handler),
	}
	return s
}

// visibleBskySourcesForCaller returns the list of "Bluesky:@handle" source
// strings the requester is allowed to see. Three contributors to the set:
//
//  1. Operator baseline (config.json's Bluesky.WatchedAccounts).
//  2. The editorial curated researcher list (107 handles), auto-included
//     so every hosted user has a populated feed without configuring a
//     single thing.
//  3. The caller's personal additions (user_bluesky_accounts), if signed
//     in. This is the "add your own" layer.
//
// Anonymous viewers in hosted mode get just (1) and (2).
func (s *Server) visibleBskySourcesForCaller(r *http.Request) []string {
	seen := make(map[string]bool)
	add := func(h string) {
		h = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(h)), "@")
		if h != "" {
			seen[h] = true
		}
	}
	for _, h := range s.cfg.Bluesky.WatchedAccounts {
		add(h)
	}
	for _, h := range curated.BlueskyHandles() {
		add(h)
	}
	if u := auth.UserFromContext(r.Context()); u != nil {
		if extras, err := s.store.ListUserBskyAccounts(u.ID); err == nil {
			for _, h := range extras {
				add(h)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, "Bluesky:@"+h)
	}
	return out
}

// proGate wraps h with auth.RequirePro when hosted mode is on, locking the
// endpoint to Pro subscribers (admins count as Pro via IsPro()). Self-host
// stays open since there's no auth concept and you ARE the operator.
func proGate(hosted bool, h http.Handler) http.Handler {
	if !hosted {
		return h
	}
	return auth.RequirePro(h)
}

// adminGate wraps h with auth.RequireAdmin when hosted mode is on, so the
// global-config mutation endpoints stay open in self-host but lock down to
// admins in multi-tenant deployments. In self-host mode the call is a no-op
// passthrough.
func adminGate(hosted bool, h http.Handler) http.Handler {
	if !hosted {
		return h
	}
	return auth.RequireAdmin(h)
}

// serveEmbeddedFile writes a single file out of webFS with the right
// Content-Type. Lets "/" serve landing.html and "/app" serve index.html
// without renaming files in the embed.FS tree.
func serveEmbeddedFile(w http.ResponseWriter, r *http.Request, webFS fs.FS, name string) {
	f, err := webFS.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f.(io.ReadSeeker))
}

// serveEmbeddedFileAs is like serveEmbeddedFile but pins the
// Content-Type instead of letting Go sniff. Used for files where the
// extension alone wouldn't yield the right MIME (and for the few
// non-text assets where we want to be explicit - favicon.svg,
// sitemap.xml, robots.txt, og-cover.svg).
func serveEmbeddedFileAs(w http.ResponseWriter, r *http.Request, webFS fs.FS, name, contentType string) {
	f, err := webFS.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, name, info.ModTime(), f.(io.ReadSeeker))
}

func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

// SetDigestWorker registers the email-digest worker so the admin "send
// test" endpoint can trigger a one-off send. Wired from main.go.
func (s *Server) SetDigestWorker(w *digestmail.Worker) { s.digestWorker = w }

// SetAlertsWorker registers the webhook-alert worker so the admin "send
// test" endpoint can fire a synthetic payload at a webhook URL.
func (s *Server) SetAlertsWorker(w *alerts.Worker) { s.alertsWorker = w }

// handleAdminDigestSendTest fires one digest email immediately at the
// supplied recipient, bypassing the cooldown / opt-in checks. Admin-gated.
func (s *Server) handleAdminDigestSendTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if s.digestWorker == nil {
		writeJSON(w, 503, map[string]string{"error": "digest worker not running (needs hosted mode + AI provider + RESEND_API_KEY)"})
		return
	}
	var body struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	to := strings.TrimSpace(body.To)
	if to == "" || !strings.Contains(to, "@") {
		writeJSON(w, 400, map[string]string{"error": "to: valid email required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if err := s.digestWorker.SendNow(ctx, to); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true", "sent_to": to})
}

// handleAdminAlertSendTest fires a synthetic webhook at the supplied URL
// using the channel-appropriate formatter. Admin-gated. The same SSRF
// guard the live alert path uses applies here too.
func (s *Server) handleAdminAlertSendTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if s.alertsWorker == nil {
		writeJSON(w, 503, map[string]string{"error": "alerts worker not running (hosted mode required)"})
		return
	}
	var body struct {
		Channel string `json:"channel"`
		Target  string `json:"target"`
		Kind    string `json:"kind"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	body.Channel = strings.ToLower(strings.TrimSpace(body.Channel))
	body.Target = strings.TrimSpace(body.Target)
	body.Kind = strings.ToLower(strings.TrimSpace(body.Kind))
	if body.Target == "" {
		writeJSON(w, 400, map[string]string{"error": "target: webhook URL required"})
		return
	}
	if body.Channel == "" {
		body.Channel = "generic"
	}
	if body.Kind == "" {
		body.Kind = "kev"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.alertsWorker.SendTest(ctx, body.Channel, body.Target, body.Kind); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true", "channel": body.Channel, "kind": body.Kind})
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

	// In hosted mode, restrict bluesky author-feed articles to the
	// requester's personal watch list plus the operator's baseline.
	// Self-host: skip; you ARE the operator and see everything you
	// configured. Anonymous hosted visitors: baseline only.
	if s.cfg.Hosted.Enabled {
		visible := s.visibleBskySourcesForCaller(r)
		filter.VisibleBskySources = &visible
		// Per-user read overlay: signed-in callers get their own read
		// state from user_read_state instead of the global flag.
		// History scope: free tier 30 days, Pro tier full corpus.
		// This is the actual Pro distinction the landing promises -
		// the same /api/articles endpoint, the same SQL, but free
		// users see a 30-day window over both listing + search while
		// Pro spans the whole archive.
		u := auth.UserFromContext(r.Context())
		if u != nil {
			filter.UserID = u.ID
		}
		if !u.IsPro() {
			thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
			if filter.Since.IsZero() || filter.Since.Before(thirtyDaysAgo) {
				filter.Since = thirtyDaysAgo
			}
		}
	}

	articles, err := s.store.List(filter)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	// Asset-profile boost: if the caller has saved a comma-separated stack
	// list in their settings, decorate each article that mentions any
	// keyword with a yours:<kw> tag the frontend renders as a "your stack"
	// pill. Doesn't reorder - the badge is the signal.
	if s.cfg.Hosted.Enabled {
		if u := auth.UserFromContext(r.Context()); u != nil {
			if m := s.loadAssetMatcher(u.ID); m != nil {
				for i := range articles {
					for _, kw := range m.match(&articles[i]) {
						articles[i].Tags = append(articles[i].Tags, "yours:"+kw)
					}
				}
			}
		}
	}

	// Threat actor + malware family extraction: scan each article's
	// title/summary/tags for known APT names + malware families.
	// Matches become "actor:<slug>" / "malware:<slug>" tags the
	// frontend renders as distinct chips. Free for everyone (the
	// curated list ships in the binary).
	for i := range articles {
		extracted := actors.Extract(articles[i].Title, articles[i].Summary, articles[i].Tags)
		if len(extracted) > 0 {
			articles[i].Tags = append(articles[i].Tags, extracted...)
		}
	}

	// Pre-KEV velocity decoration: tag articles that mention a CVE which
	// has crossed the "talked about by 3+ distinct sources in the last
	// 72h" threshold AND is not yet on the CISA KEV list. The frontend
	// renders this as a prominent "🔮 PRE-KEV" badge - it's a heads-up
	// that CISA may add this CVE soon and you might want to act now.
	if preKEV := s.getPreKEVSet(); len(preKEV) > 0 {
		for i := range articles {
			for _, t := range articles[i].Tags {
				if _, ok := preKEV[t]; ok {
					articles[i].Tags = append(articles[i].Tags, "prekev:"+t)
				}
			}
		}
	}

	// AI triage attachment for Pro users: bulk-fetch cached triage lines
	// for the returned articles and stick them on the .Triage field.
	// Articles without cached triage get the empty string (omitempty hides
	// the field in JSON). A background worker fills the cache over time
	// for high-score articles; lazy fill happens via the explicit triage
	// endpoint.
	if s.cfg.Hosted.Enabled {
		if u := auth.UserFromContext(r.Context()); u != nil && u.IsPro() {
			ids := make([]int64, 0, len(articles))
			for i := range articles {
				ids = append(ids, articles[i].ID)
			}
			if triage, err := s.store.PrefetchedTriage(ids); err == nil && len(triage) > 0 {
				for i := range articles {
					if t, ok := triage[articles[i].ID]; ok {
						articles[i].Triage = t
					}
				}
			}
		}
	}

	writeJSON(w, 200, articles)
}

// getPreKEVSet returns the cached set of CVEs that have crossed the
// pre-KEV velocity threshold (>=3 distinct sources in the last 72h) and
// are NOT on the CISA KEV list. Refreshed every 5 minutes lazy-on-read
// so concurrent /api/articles requests share the work.
func (s *Server) getPreKEVSet() map[string]int {
	s.preKEVMu.Lock()
	if s.preKEVCache != nil && time.Since(s.preKEVAt) < 5*time.Minute {
		out := s.preKEVCache
		s.preKEVMu.Unlock()
		return out
	}
	s.preKEVMu.Unlock()

	raw, err := s.store.PreKEVCandidates(72, 3)
	if err != nil {
		return nil
	}
	filtered := make(map[string]int, len(raw))
	for cve, n := range raw {
		// KEV check lives in the scorer; if the CVE is already on the
		// KEV list this is no longer a "pre-KEV" signal.
		if s.scorer != nil && s.scorer.IsKEV(cve) {
			continue
		}
		filtered[cve] = n
	}
	s.preKEVMu.Lock()
	s.preKEVCache = filtered
	s.preKEVAt = time.Now()
	s.preKEVMu.Unlock()
	return filtered
}

// loadAssetMatcher pulls the caller's asset_profile from user_settings and
// compiles it into a reusable matcher. Returns nil for empty profiles or
// when the settings row doesn't parse. Cheap: settings is a small JSON blob.
func (s *Server) loadAssetMatcher(userID string) *assetMatcher {
	settings, err := s.store.GetSettings(userID)
	if err != nil {
		return nil
	}
	var sm map[string]any
	if err := json.Unmarshal([]byte(settings), &sm); err != nil {
		return nil
	}
	raw, ok := sm["asset_profile"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	return newAssetMatcher(raw)
}

type assetMatcher struct {
	keywords []string
	res      []*regexp.Regexp
}

// newAssetMatcher splits the user's comma / newline / semicolon-separated
// keyword list, deduplicates, and compiles a case-insensitive word-boundary
// regex per keyword. Empty profile returns nil. Caps at 30 keywords to
// keep matching cost bounded.
func newAssetMatcher(raw string) *assetMatcher {
	keywords := parseAssetProfile(raw)
	if len(keywords) == 0 {
		return nil
	}
	if len(keywords) > 30 {
		keywords = keywords[:30]
	}
	res := make([]*regexp.Regexp, 0, len(keywords))
	clean := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		// Word-boundary regex - "go" matches "go" but not "argo".
		re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
		if err != nil {
			continue
		}
		res = append(res, re)
		clean = append(clean, kw)
	}
	if len(res) == 0 {
		return nil
	}
	return &assetMatcher{keywords: clean, res: res}
}

// match returns the keywords from the user's asset profile that appear
// (word-boundary) anywhere in the article's title, summary, or existing
// tags. Empty if nothing matched.
func (m *assetMatcher) match(a *models.Article) []string {
	haystack := a.Title + " " + a.Summary + " " + strings.Join(a.Tags, " ")
	var hits []string
	for i, re := range m.res {
		if re.MatchString(haystack) {
			hits = append(hits, m.keywords[i])
		}
	}
	return hits
}

// parseAssetProfile splits the user-supplied keyword string on commas,
// semicolons, newlines, and pipes. Strips whitespace AND surrounding
// punctuation users tend to copy-paste in (quotes, brackets, parens,
// backticks), lowercases, drops entries shorter than 2 chars or longer
// than 30, dedupes.
func parseAssetProfile(raw string) []string {
	const punctTrim = `"'` + "`" + `()[]{}<>.,:;!?*` // chars to strip from edges
	out := []string{}
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';' || r == '|'
	}) {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, punctTrim)
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) < 2 || len(p) > 30 {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
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
	// Hosted + signed in: write a per-user read mark. The global
	// articles.read column is only used in self-host mode where one
	// process == one operator.
	if s.cfg.Hosted.Enabled {
		if u := auth.UserFromContext(r.Context()); u != nil {
			s.store.MarkReadForUser(u.ID, body.ID)
			writeJSON(w, 200, map[string]string{"ok": "true"})
			return
		}
		// Anonymous hosted visitors: no-op (they have no account to
		// store the read mark against). Don't touch the global flag.
		writeJSON(w, 200, map[string]string{"ok": "true"})
		return
	}
	s.store.MarkRead(body.ID)
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (s *Server) handleMarkAllRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if s.cfg.Hosted.Enabled {
		if u := auth.UserFromContext(r.Context()); u != nil {
			s.store.MarkAllReadForUser(u.ID)
			writeJSON(w, 200, map[string]string{"ok": "true"})
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "true"})
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

// handleAuthMethods reports which login flows are wired up. Self-host: both
// false. Hosted: depends on which env-var creds are populated.
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{
		"google":      s.cfg.Hosted.Enabled && s.cfg.Hosted.GoogleClientID != "" && s.cfg.Hosted.GoogleClientSecret != "",
		"magic_link":  s.cfg.Hosted.Enabled && s.cfg.Hosted.ResendAPIKey != "",
		"hosted_mode": s.cfg.Hosted.Enabled,
		"billing":     s.billing != nil,
	})
}

// handleMe returns the resolved user (if any) for the current session cookie.
// Returns null in JSON when the visitor is anonymous, so the client can
// distinguish "logged out" from "request failed" without checking status.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		writeJSON(w, 200, nil)
		return
	}
	writeJSON(w, 200, map[string]any{
		"id":           u.ID,
		"email":        u.Email,
		"display_name": u.DisplayName,
		"is_pro":       u.IsPro(),
		"pro_until":    u.ProUntil,
		"is_admin":     u.IsAdmin,
	})
}

// handleHottestCVEs returns the top CVE IDs by article-mention count over
// a 72h window. Public endpoint; powers the /live "what's hot right now"
// leaderboard. Optional ?hours= and ?limit= query params.
func (s *Server) handleHottestCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 || hours > 24*14 {
		hours = 72
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.store.HottestCVEs(hours, limit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// Light EPSS overlay if we have it cached - lets the UI show "92% EPSS"
	// without an extra round trip per row.
	if s.enrich != nil && s.enrich.EPSS != nil {
		type withEPSS struct {
			storage.CVEActivity
			EPSSScore      float64 `json:"epss_score,omitempty"`
			EPSSPercentile float64 `json:"epss_percentile,omitempty"`
		}
		enriched := make([]withEPSS, 0, len(rows))
		for _, c := range rows {
			r := withEPSS{CVEActivity: c}
			if e := s.enrich.EPSS.Get(c.CVE); e != nil {
				r.EPSSScore = e.Score
				r.EPSSPercentile = e.Percentile
			}
			enriched = append(enriched, r)
		}
		writeJSON(w, 200, map[string]any{
			"window_hours": hours,
			"rows":         enriched,
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"window_hours": hours,
		"rows":         rows,
	})
}

// handleActorLookup returns the curated metadata for a threat actor
// slug + a count of recent articles mentioning any of its aliases.
// Returns 404 for unknown slugs. Powers the Insight Card modal that
// pops when a user clicks an actor: chip in the reader.
func (s *Server) handleActorLookup(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/actors/")))
	if slug == "" {
		writeJSON(w, 400, map[string]string{"error": "actor slug required"})
		return
	}
	a := actors.FindActor(slug)
	if a == nil {
		writeJSON(w, 404, map[string]string{"error": "not in curated list", "slug": slug})
		return
	}
	count, _ := s.store.RecentAliasMentionCount(a.Aliases, 30)
	s.emit(w, r, analytics.EvActorChipOpen, slug, nil)
	writeJSON(w, 200, map[string]any{
		"slug":         a.Slug,
		"display":      a.Display,
		"aliases":      a.Aliases,
		"origin":       a.Origin,
		"recent_count": count,
		"mitre_url":    "https://attack.mitre.org/groups/",
	})
}

// handleMalwareLookup mirrors handleActorLookup for malware families.
func (s *Server) handleMalwareLookup(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/malware/")))
	if slug == "" {
		writeJSON(w, 400, map[string]string{"error": "malware slug required"})
		return
	}
	m := actors.FindMalware(slug)
	if m == nil {
		writeJSON(w, 404, map[string]string{"error": "not in curated list", "slug": slug})
		return
	}
	count, _ := s.store.RecentAliasMentionCount(m.Aliases, 30)
	s.emit(w, r, analytics.EvMalwareChipOpen, slug, nil)
	writeJSON(w, 200, map[string]any{
		"slug":         m.Slug,
		"display":      m.Display,
		"aliases":      m.Aliases,
		"kind":         m.Kind,
		"recent_count": count,
		"mitre_url":    "https://attack.mitre.org/software/",
	})
}

// handleAttackExport emits a MITRE ATT&CK Navigator v4.5 layer JSON
// the user can paste into https://mitre-attack.github.io/attack-navigator/
// to see their TTP coverage as a heat-map.
//
//	scope (query) - "global" (default) or "mine" (requires auth + Pro)
//	days  (query) - lookback for global mode; defaults 30, max 180
//
// Response Content-Disposition forces a download.
func (s *Server) handleAttackExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := strings.ToLower(strings.TrimSpace(q.Get("scope")))
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > 180 {
		days = 30
	}

	var freq map[string]int
	var err error
	var layerName, layerDesc string

	switch scope {
	case "mine":
		u := auth.UserFromContext(r.Context())
		if u == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if s.cfg.Hosted.Enabled && !u.IsPro() {
			http.Error(w, "pro subscription required", http.StatusPaymentRequired)
			return
		}
		freq, err = s.store.TTPFrequencyForBookmarks(u.ID)
		layerName = "oM noM - " + u.Email + " bookmarks"
		layerDesc = "TTPs from articles bookmarked by " + u.Email
	default:
		freq, err = s.store.TTPFrequency(days)
		layerName = fmt.Sprintf("oM noM - last %d days", days)
		layerDesc = fmt.Sprintf("TTP frequency across all sources, last %d days", days)
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	// Compute max for normalised score scaling.
	maxCount := 0
	for _, n := range freq {
		if n > maxCount {
			maxCount = n
		}
	}
	if maxCount == 0 {
		maxCount = 1
	}

	// Layer v4.5 schema. https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMAT.md
	type navTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Comment     string `json:"comment,omitempty"`
		Enabled     bool   `json:"enabled"`
	}
	type navGradient struct {
		Colors  []string `json:"colors"`
		MinValue int     `json:"minValue"`
		MaxValue int     `json:"maxValue"`
	}
	type navLayer struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Versions    map[string]any `json:"versions"`
		Domain      string         `json:"domain"`
		Techniques  []navTechnique `json:"techniques"`
		Gradient    navGradient    `json:"gradient"`
		ShowTacticRowBackground bool `json:"showTacticRowBackground"`
		TacticRowBackground     string `json:"tacticRowBackground"`
		SelectTechniquesAcrossTactics bool `json:"selectTechniquesAcrossTactics"`
		HideDisabled bool `json:"hideDisabled"`
	}

	techniques := make([]navTechnique, 0, len(freq))
	for tid, count := range freq {
		techniques = append(techniques, navTechnique{
			TechniqueID: tid,
			Score:       count,
			Comment:     fmt.Sprintf("%d mention(s) across articles", count),
			Enabled:     true,
		})
	}
	// Stable sort by score desc so the JSON is deterministic for diffing.
	sort.Slice(techniques, func(i, j int) bool {
		if techniques[i].Score != techniques[j].Score {
			return techniques[i].Score > techniques[j].Score
		}
		return techniques[i].TechniqueID < techniques[j].TechniqueID
	})

	layer := navLayer{
		Name:        layerName,
		Description: layerDesc,
		Versions: map[string]any{
			"attack":    "14",
			"navigator": "4.9.4",
			"layer":     "4.5",
		},
		Domain:     "enterprise-attack",
		Techniques: techniques,
		Gradient: navGradient{
			Colors:   []string{"#0a0e14", "#00e5a0", "#ffb547", "#ff4d6a"},
			MinValue: 1,
			MaxValue: maxCount,
		},
		ShowTacticRowBackground: false,
		TacticRowBackground:     "#dddddd",
		SelectTechniquesAcrossTactics: true,
		HideDisabled:                  false,
	}

	filename := "omnom-attack-layer-" + time.Now().UTC().Format("2006-01-02") + ".json"
	s.emit(w, r, analytics.EvAttackExport, scope, map[string]any{
		"days":     days,
		"techniques": len(techniques),
		"max":      maxCount,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	json.NewEncoder(w).Encode(layer)
}

// handlePatchBriefs returns every patch brief generated in the last
// `days` days (default 30), newest first. Frontend filters by which
// vendors the user toggled on. Public endpoint - the briefs are
// summaries of public articles, no per-user state involved.
func (s *Server) handlePatchBriefs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > 90 {
		days = 30
	}
	rows, err := s.store.RecentPatchBriefs(days)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []storage.PatchBrief{}
	}
	writeJSON(w, 200, map[string]any{
		"window_days": days,
		"briefs":      rows,
	})
}

// handlePreKEV returns the CVEs that have crossed the "multiple curated
// sources are talking about this in the last 72h" threshold AND aren't
// already on the CISA KEV list. The list is sorted by distinct-source
// count desc, then alphabetical. Optional ?hours= and ?min= override.
// Public; same data the per-article prekev:* tag pulls from.
func (s *Server) handlePreKEV(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours, _ := strconv.Atoi(q.Get("hours"))
	if hours <= 0 || hours > 24*14 {
		hours = 72
	}
	minSrc, _ := strconv.Atoi(q.Get("min"))
	if minSrc <= 0 {
		minSrc = 3
	}
	raw, err := s.store.PreKEVCandidates(hours, minSrc)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	type row struct {
		CVE     string `json:"cve"`
		Sources int    `json:"distinct_sources"`
	}
	out := make([]row, 0, len(raw))
	for cve, n := range raw {
		if s.scorer != nil && s.scorer.IsKEV(cve) {
			continue
		}
		out = append(out, row{CVE: cve, Sources: n})
	}
	// Sort: source count desc, then CVE id asc (stable, predictable).
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sources != out[j].Sources {
			return out[i].Sources > out[j].Sources
		}
		return out[i].CVE < out[j].CVE
	})
	writeJSON(w, 200, map[string]any{
		"window_hours":  hours,
		"min_sources":   minSrc,
		"rows":          out,
		"total":         len(out),
	})
}

// handleHealthz answers liveness probes from uptime monitors. Returns
// 200 + tiny JSON when the DB connection is healthy, 503 otherwise.
// Cheap: a single SELECT 1 on the DB plus a uptime-since-start calc.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	var n int
	if err := s.store.DB().QueryRow(`SELECT 1`).Scan(&n); err != nil || n != 1 {
		writeJSON(w, 503, map[string]any{
			"status":  "degraded",
			"error":   "db unreachable",
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"version":     serverVersion,
		"uptime_s":    int(time.Since(serverStarted).Seconds()),
		"hosted_mode": s.cfg.Hosted.Enabled,
	})
}

// handleWormMood returns the worm's current state based on KEV activity
// in the last 24 hours. Drives the visual mood swing in the header sprite.
// Thresholds calibrated against the live corpus (median ~4/day, max ~13
// in normal weeks - 10+ is a real spike, e.g. Patch Tuesday or campaign).
//   level 0 / "hibernating" - no KEV-tagged article published in 24h
//   level 1 / "eating"      - 1-9 (normal activity)
//   level 2 / "frenzy"      - 10+ (patch wave / active campaign)
func (s *Server) handleWormMood(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.RecentKEVMentionCount(24)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	level, label := 0, "hibernating"
	switch {
	case count >= 10:
		level, label = 2, "frenzy"
	case count >= 1:
		level, label = 1, "eating"
	}
	writeJSON(w, 200, map[string]any{
		"level":   level,
		"label":   label,
		"kev_24h": count,
		"since":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleMomentum returns the top week-over-week tag movers. Free for all
// (lightweight aggregation over the articles table). MITRE-coded tags get
// a friendly name overlay if the loaded MITRE map has one.
func (s *Server) handleMomentum(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.TagMomentum(168, 14)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	movers := make([]map[string]any, 0, len(rows))
	for _, m := range rows {
		entry := map[string]any{
			"tag":       m.Tag,
			"now":       m.Now,
			"prev":      m.Prev,
			"delta_pct": m.DeltaPct,
		}
		// If it looks like a MITRE technique id (T1059, T1218.001, etc.),
		// overlay the human name. Same map the rest of the UI uses.
		if s.enrich != nil && s.enrich.MITRE != nil {
			id := strings.ToUpper(m.Tag)
			if n, ok := s.enrich.MITRE[id]; ok && n.Name != "" {
				entry["name"] = n.Name
			}
		}
		movers = append(movers, entry)
	}
	writeJSON(w, 200, map[string]any{
		"window_hours": 168,
		"window_label": "last 7 days vs prior 7 days",
		"movers":       movers,
	})
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
			Action  string   `json:"action"`
			Handle  string   `json:"handle"`
			Handles []string `json:"handles"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}

		switch body.Action {
		case "add", "remove":
			handle := strings.TrimPrefix(strings.TrimSpace(body.Handle), "@")
			if handle == "" {
				writeJSON(w, 400, map[string]string{"error": "handle required"})
				return
			}
			if body.Action == "add" {
				for _, h := range s.cfg.Bluesky.WatchedAccounts {
					if h == handle {
						writeJSON(w, 200, map[string]string{"ok": "true", "message": "already watched"})
						return
					}
				}
				s.cfg.Bluesky.WatchedAccounts = append(s.cfg.Bluesky.WatchedAccounts, handle)
			} else {
				var filtered []string
				for _, h := range s.cfg.Bluesky.WatchedAccounts {
					if h != handle {
						filtered = append(filtered, h)
					}
				}
				s.cfg.Bluesky.WatchedAccounts = filtered
			}

		case "add_bulk":
			// Cap defensively so a malformed client can't blow the config out.
			if len(body.Handles) > 1000 {
				writeJSON(w, 400, map[string]string{"error": "too many handles (>1000)"})
				return
			}
			existing := make(map[string]bool, len(s.cfg.Bluesky.WatchedAccounts))
			for _, h := range s.cfg.Bluesky.WatchedAccounts {
				existing[h] = true
			}
			added := 0
			for _, raw := range body.Handles {
				h := strings.TrimPrefix(strings.TrimSpace(raw), "@")
				if h == "" || existing[h] {
					continue
				}
				s.cfg.Bluesky.WatchedAccounts = append(s.cfg.Bluesky.WatchedAccounts, h)
				existing[h] = true
				added++
			}
			if added == 0 {
				writeJSON(w, 200, map[string]interface{}{"ok": "true", "added": 0, "accounts": s.cfg.Bluesky.WatchedAccounts})
				return
			}

		default:
			writeJSON(w, 400, map[string]string{"error": "action must be add, remove, or add_bulk"})
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
			"digest":        cachedText,
			"cached":        true,
			"age_seconds":   int(time.Since(cachedAt).Seconds()),
			"provider":      s.enrich.AI.Name(),
			"article_count": cachedN,
			"generated_at":  cachedAt.Format(time.RFC3339),
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
		"digest":        text,
		"cached":        false,
		"provider":      s.enrich.AI.Name(),
		"article_count": len(articles),
		"generated_at":  time.Now().Format(time.RFC3339),
	})
}

// handleCVE owns /api/cve/<id> (NVD + EPSS detail, open to everyone) and
// /api/cve/<id>/explain (3-bullet AI deep-dive, Pro-gated). KEV status
// is already on the article tags from the scorer, so the frontend
// overlays that itself.
func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.NVD == nil {
		writeJSON(w, 503, map[string]string{"error": "nvd client not available"})
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, "/api/cve/")
	tail = strings.Trim(tail, "/")
	if tail == "" {
		writeJSON(w, 400, map[string]string{"error": "cve id required"})
		return
	}

	// "/api/cve/<id>/explain" -> deep-dive AI summary.
	if strings.HasSuffix(strings.ToLower(tail), "/explain") {
		id := strings.ToUpper(strings.TrimSuffix(tail, "/explain"))
		id = strings.TrimSuffix(id, "/EXPLAIN")
		s.handleCVEExplain(w, r, id)
		return
	}

	id := strings.ToUpper(tail)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	d, err := s.enrich.NVD.Get(ctx, id)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error(), "id": id})
		return
	}
	s.emit(w, r, analytics.EvCVEModalOpen, id, nil)
	if s.enrich.EPSS != nil {
		if e := s.enrich.EPSS.Get(id); e != nil {
			d.EPSSScore = e.Score
			d.EPSSPercentile = e.Percentile
		}
	}
	// OTX community-pulse overlay. Best-effort - if OTX is down or rate
	// limits us, the CVE modal still renders with NVD + EPSS data.
	out := map[string]any{
		"id":              d.ID,
		"description":     d.Description,
		"cvss_v3_score":   d.CVSSv3Score,
		"cvss_v3_severity": d.CVSSv3Severity,
		"cvss_v3_vector":  d.CVSSv3Vector,
		"cwe":             d.CWE,
		"published":       d.Published,
		"last_modified":   d.LastModified,
		"epss_score":      d.EPSSScore,
		"epss_percentile": d.EPSSPercentile,
		"cached":          d.Cached,
	}
	if s.enrich.OTX != nil {
		// OTX is slow (4-5s TTFB from some datacenters) so this window
		// is generous. Once cached the next read is instant.
		otxCtx, otxCancel := context.WithTimeout(r.Context(), 22*time.Second)
		defer otxCancel()
		if otxData, err := s.enrich.OTX.Get(otxCtx, id); err == nil && otxData != nil {
			out["otx_pulse_count"] = otxData.PulseCount
			out["otx_recent_pulses"] = otxData.RecentCount
		}
	}
	// Researcher consensus heatmap: which curated sources have posted
	// about this CVE in the last 30 days. Aggregates from the articles
	// table directly; no external API. Cheap because the corpus is small.
	if rows, err := s.store.CVEConsensus(id, 30); err == nil && len(rows) > 0 {
		out["consensus"] = rows
		out["consensus_total_sources"] = len(rows)
	}
	// Chronological timeline: first mention, vendor advisory, first PoC,
	// latest. Built from the article corpus, no external API. Useful
	// context on how a CVE has been talked about over time.
	if events, err := s.store.CVETimeline(id); err == nil && len(events) > 0 {
		out["timeline"] = events
	}
	writeJSON(w, 200, out)
}

// handleArticleExplain returns the 2-3 line plain-English summary of a
// single article. Pro-gated by proGate at mount time; cached in
// article_ai_explanations forever.
func (s *Server) handleArticleExplain(w http.ResponseWriter, r *http.Request) {
	if s.enrich == nil || s.enrich.AI == nil {
		writeJSON(w, 503, map[string]string{"error": "no AI provider configured"})
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/articles/explain/")
	idStr = strings.Trim(idStr, "/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, 400, map[string]string{"error": "article id required"})
		return
	}

	if cached, err := s.store.GetArticleExplanation(id); err == nil && cached != "" {
		writeJSON(w, 200, map[string]any{
			"id":          id,
			"explanation": cached,
			"cached":      true,
			"provider":    s.enrich.AI.Name(),
		})
		return
	}

	articles, err := s.store.List(storage.ListFilter{ShowDupes: true, Limit: 1, Source: ""})
	_ = articles // silence unused if we change strategy
	// Pull the specific article by id. Quick path through the DB rather
	// than spinning up a new method - the existing List filter doesn't
	// take an id, but a small WHERE works just as well via raw DB.
	var (
		title, source, summary string
		score                  int
		tagsJSON               string
	)
	err = s.store.DB().QueryRow(
		`SELECT title, source, COALESCE(summary,''), score, tags FROM articles WHERE id = ?`,
		id,
	).Scan(&title, &source, &summary, &score, &tagsJSON)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "article not found"})
		return
	}
	var tags []string
	_ = json.Unmarshal([]byte(tagsJSON), &tags)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	text, err := s.enrich.AI.ExplainArticle(ctx, ai.Article{
		Title:   title,
		Source:  source,
		Summary: summary,
		Score:   score,
		Tags:    tags,
	})
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "provider": s.enrich.AI.Name()})
		return
	}
	_ = s.store.PutArticleExplanation(id, text, s.enrich.AI.Name())
	writeJSON(w, 200, map[string]any{
		"id":          id,
		"explanation": text,
		"cached":      false,
		"provider":    s.enrich.AI.Name(),
	})
}

// handleCVEExplain returns the 3-bullet AI deep-dive for a CVE. Cached
// in cve_ai_explanations so the first Pro user pays the LLM call and
// every subsequent reader gets the cached text. Pro-gated in hosted
// mode; open in self-host (you ARE the operator paying for the key).
func (s *Server) handleCVEExplain(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "cve id required"})
		return
	}
	if s.enrich.AI == nil {
		writeJSON(w, 503, map[string]string{"error": "no AI provider configured"})
		return
	}
	if s.cfg.Hosted.Enabled {
		u := auth.UserFromContext(r.Context())
		if u == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if !u.IsPro() {
			http.Error(w, "pro subscription required", http.StatusPaymentRequired)
			return
		}
	}

	// Cache hit returns instantly. Same text for every reader.
	if cached, err := s.store.GetCVEExplanation(id); err == nil && cached != "" {
		writeJSON(w, 200, map[string]any{
			"cve":         id,
			"explanation": cached,
			"cached":      true,
			"provider":    s.enrich.AI.Name(),
		})
		return
	}

	// Fresh generation: pull NVD detail to feed the prompt.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := s.enrich.NVD.Get(ctx, id)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "nvd lookup failed: " + err.Error(), "id": id})
		return
	}
	if s.enrich.EPSS != nil {
		if e := s.enrich.EPSS.Get(id); e != nil {
			d.EPSSScore = e.Score
			d.EPSSPercentile = e.Percentile
		}
	}

	// KEV status: read it off the scorer's in-memory KEV map. The same
	// map drives the per-article kev:* tag, so this stays consistent.
	kev := s.scorer != nil && s.scorer.IsKEV(id)

	payload := ai.CVEDetail{
		ID:             id,
		Description:    d.Description,
		CVSSScore:      d.CVSSv3Score,
		CVSSSeverity:   d.CVSSv3Severity,
		EPSSScore:      d.EPSSScore,
		EPSSPercentile: d.EPSSPercentile,
		KEV:            kev,
		CWE:            d.CWE,
	}
	text, err := s.enrich.AI.ExplainCVE(ctx, payload)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "provider": s.enrich.AI.Name()})
		return
	}
	_ = s.store.PutCVEExplanation(id, text, s.enrich.AI.Name())
	writeJSON(w, 200, map[string]any{
		"cve":         id,
		"explanation": text,
		"cached":      false,
		"provider":    s.enrich.AI.Name(),
	})
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
