package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/aidedup"
	"github.com/RMS2D/omnomfeeds/internal/aitriage"
	"github.com/RMS2D/omnomfeeds/internal/alerts"
	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/curated"
	"github.com/RMS2D/omnomfeeds/internal/digestmail"
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/mitre"
	"github.com/RMS2D/omnomfeeds/internal/patchtuesday"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/server"
	"github.com/RMS2D/omnomfeeds/internal/sources"
	"github.com/RMS2D/omnomfeeds/internal/storage"
	"github.com/RMS2D/omnomfeeds/internal/tui"
)

//go:embed web
var webFS embed.FS

//go:embed config.default.json
var defaultConfigBytes []byte

// Set via -ldflags at release time.
var version = "dev"

func main() {
	// Subcommand dispatch lives at the top so the TUI doesn't pay the
	// cost of spinning up the full feed-fetcher / scoring / server stack.
	// `secfeed tui` only needs the config path + a read-mostly SQLite
	// handle; everything else is the daemon's job and runs separately.
	if len(os.Args) > 1 && os.Args[1] == "tui" {
		runTUI()
		return
	}

	cfgPath := resolveConfigPath()
	if err := ensureConfigExists(cfgPath); err != nil {
		log.Fatalf("config init: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Resolve a relative db_path against the config directory so the SQLite
	// file lands next to config.json rather than in the user's CWD.
	if cfg.DBPath != "" && !filepath.IsAbs(cfg.DBPath) {
		cfg.DBPath = filepath.Join(filepath.Dir(cfgPath), cfg.DBPath)
	}

	db, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	defer db.Close()

	scorer := scoring.New()
	scorer.UpdateKEV()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			scorer.UpdateKEV()
		}
	}()

	var normalSrcs []sources.Source
	var fastSrcs []sources.Source
	if strings.TrimSpace(cfg.MalwareBazaar.APIKey) != "" {
		fastSrcs = append(fastSrcs, sources.NewMalwareBazaar(cfg.MalwareBazaar.APIKey))
	}
	for _, feed := range cfg.RSSFeeds {
		src := sources.NewRSS(feed.Name, feed.URL)
		if feed.Fast {
			fastSrcs = append(fastSrcs, src)
		} else {
			normalSrcs = append(normalSrcs, src)
		}
	}
	for _, sub := range cfg.Subreddits {
		normalSrcs = append(normalSrcs, sources.NewReddit(sub))
	}
	var bskySrc *sources.BlueskySource
	if cfg.Bluesky.Enabled && len(cfg.Bluesky.SearchTerms) > 0 {
		bskySrc = sources.NewBluesky(
			cfg.Bluesky.SearchTerms, cfg.Bluesky.Identifier, cfg.Bluesky.Password)
		normalSrcs = append(normalSrcs, bskySrc)
	}
	if cfg.Bluesky.Enabled && bskySrc != nil {
		// Compute the watched-handles list fresh each fetch cycle:
		// operator's config.json baseline ∪ the editorial curated list
		// ∪ every user's personal subs. New per-user adds get picked up
		// without a binary restart. The curated list is auto-included so
		// hosted users get a populated feed the moment they sign up.
		handlesFn := func() []string {
			seen := make(map[string]struct{})
			add := func(h string) {
				h = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(h), "@"))
				if h != "" {
					seen[h] = struct{}{}
				}
			}
			for _, h := range cfg.Bluesky.WatchedAccounts {
				add(h)
			}
			for _, h := range curated.BlueskyHandles() {
				add(h)
			}
			if extras, err := db.AllUserBskyHandles(); err == nil {
				for _, h := range extras {
					add(h)
				}
			}
			out := make([]string, 0, len(seen))
			for h := range seen {
				out = append(out, h)
			}
			return out
		}
		// Only register the source if there's at least one handle to fetch
		// at startup time. If the operator's list is empty but users add
		// handles later, the source still ticks (handlesFn re-checks every
		// poll). So always register when bsky auth is configured.
		normalSrcs = append(normalSrcs, sources.NewBlueskyAccounts(handlesFn, bskySrc))
	}
	for _, inst := range cfg.Mastodon.Instances {
		normalSrcs = append(normalSrcs, sources.NewMastodon(inst, cfg.Mastodon.Hashtags))
	}
	if cfg.GitHub.Enabled {
		fastSrcs = append(fastSrcs, sources.NewGitHubAdvisory(cfg.GitHub.Token))
		normalSrcs = append(normalSrcs, sources.NewGitHubPoC(cfg.GitHub.Token))
	}

	webSubFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}

	// --- Enrichment layer: MITRE ATT&CK + NVD CVE cache + EPSS ---
	cacheDir := filepath.Dir(cfg.DBPath)
	mitreLoader := mitre.New(cacheDir)
	mitreMap := mitreLoader.Load() // synchronous on first run, cache-hit afterwards

	nvdClient := cve.NewNVDClient(db.DB(), os.Getenv("NVD_API_KEY"))
	if err := nvdClient.EnsureTable(); err != nil {
		log.Printf("[NVD] table init: %v", err)
	}

	epssClient := cve.NewEPSSClient(db.DB())
	if err := epssClient.EnsureTable(); err != nil {
		log.Printf("[EPSS] table init: %v", err)
	}

	otxClient := cve.NewOTXClient(db.DB())
	if err := otxClient.EnsureTable(); err != nil {
		log.Printf("[OTX] table init: %v", err)
	}
	// Refresh EPSS scores in background: once at boot, then daily.
	go func() {
		bgCtx := context.Background()
		if err := epssClient.Refresh(bgCtx); err != nil {
			log.Printf("[EPSS] initial refresh: %v", err)
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := epssClient.Refresh(bgCtx); err != nil {
				log.Printf("[EPSS] refresh: %v", err)
			}
		}
	}()

	// --- AI provider (BYOK) ---
	var aiClient ai.Summarizer
	provider := strings.ToLower(strings.TrimSpace(cfg.AI.Provider))
	anthroKey := os.Getenv("ANTHROPIC_API_KEY")
	openaiKey := os.Getenv("OPENAI_API_KEY")
	if provider == "" {
		// Auto-detect by available key
		if anthroKey != "" {
			provider = "anthropic"
		} else if openaiKey != "" {
			provider = "openai"
		}
	}
	switch provider {
	case "anthropic":
		if anthroKey == "" {
			log.Printf("[AI] anthropic provider selected but ANTHROPIC_API_KEY env var unset; AI digest disabled")
		} else {
			aiClient = ai.NewAnthropicClient(anthroKey, cfg.AI.Model, cfg.AI.Focus)
			log.Printf("[AI] provider :: %s", aiClient.Name())
		}
	case "openai":
		if openaiKey == "" {
			log.Printf("[AI] openai provider selected but OPENAI_API_KEY env var unset; AI digest disabled")
		} else {
			aiClient = ai.NewOpenAIClient(openaiKey, cfg.AI.Model, cfg.AI.Focus)
			log.Printf("[AI] provider :: %s", aiClient.Name())
		}
	case "":
		// neither key set - silent, no AI features
	default:
		log.Printf("[AI] unknown provider %q (expected anthropic or openai)", provider)
	}

	enr := &server.Enrichment{
		MITRE: mitreMap,
		NVD:   nvdClient,
		EPSS:  epssClient,
		OTX:   otxClient,
		AI:    aiClient,
	}

	total := len(normalSrcs) + len(fastSrcs)
	server.SetVersion(version)
	srv := server.New(db, normalSrcs, fastSrcs, scorer, cfg, webSubFS, enr)

	log.Printf("oM noM Security Feeds %s :: initial fetch from %d sources (%d fast, %d normal)...", version, total, len(fastSrcs), len(normalSrcs))
	srv.FetchAll()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background sweeper for the in-memory caches added for /cve/<id>,
	// /trending, /pre-kev, and "while you were gone". Every cache had a
	// read-time TTL check but never removed expired entries; without the
	// sweeper cvePageCache could grow toward NVD's ~240k CVE space.
	srv.StartCacheSweeper(ctx)

	// Daily DB cleanup: expired sessions, magic-link tokens, alert-fire
	// dedup rows, read articles >90d, analytics events >180d, NVD/OTX
	// cache >90d, then a WAL checkpoint to keep the journal bounded.
	// First tick at +5min so the box has time to settle after restart;
	// subsequent ticks at 24h intervals.
	go func() {
		t := time.NewTimer(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r := db.DailyCleanup()
				log.Printf("[cleanup] sessions=%d magic=%d alert_fires=%d articles=%d events=%d nvd=%d otx=%d wal=%s",
					r.Sessions, r.MagicLinks, r.AlertFires, r.Articles, r.Events, r.NVD, r.OTX, r.WALCheckpoint)
				t.Reset(24 * time.Hour)
			}
		}
	}()

	// Pro webhook-alert worker. Only spun up in hosted mode; in self-host
	// nobody can save alert rules so the goroutine would have nothing to do.
	if cfg.Hosted.Enabled {
		siteBase := strings.TrimSuffix(cfg.Hosted.OAuthRedirectURL, "/auth/callback")
		if siteBase == "" {
			siteBase = "https://omnomfeeds.com"
		}
		w := alerts.New(db, siteBase)
		srv.SetAlertsWorker(w)
		go w.Run(ctx)
		log.Printf("[alerts] webhook worker started (site=%s)", siteBase)
	}

	// Pro AI semantic-dedup worker. Hosted mode + AI provider required;
	// runs every 30 minutes regardless of user count - the cost is fixed
	// per cycle, the benefit is shared.
	if cfg.Hosted.Enabled && aiClient != nil {
		dw := aidedup.New(db, aiClient)
		go dw.Run(ctx)
		log.Printf("[aidedup] semantic-dedup worker started")
	}

	// Pro email digest worker. Sends daily / weekly summaries to opted-in
	// users via Resend. Needs both AI provider and Resend API key.
	if cfg.Hosted.Enabled && aiClient != nil && cfg.Hosted.ResendAPIKey != "" {
		siteBase := strings.TrimSuffix(cfg.Hosted.OAuthRedirectURL, "/auth/callback")
		if siteBase == "" {
			siteBase = "https://omnomfeeds.com"
		}
		mw := digestmail.New(db, aiClient, cfg.Hosted.ResendAPIKey, siteBase)
		srv.SetDigestWorker(mw)
		go mw.Run(ctx)
		log.Printf("[digestmail] email digest worker started")
	}

	// Patch Tuesday brief generator. Hosted mode + AI required; runs
	// hourly and only does work on calendar-pinned patch days (MS / Adobe
	// 2nd Tue, Oracle CPU Jan/Apr/Jul/Oct 3rd Tue).
	if cfg.Hosted.Enabled && aiClient != nil {
		pw := patchtuesday.New(db, aiClient)
		go pw.Run(ctx)
		log.Printf("[patchtuesday] brief worker started")
	}

	// AI triage worker: generates inline "what? so what?" one-liners
	// for high-score articles. Hosted mode + AI required. Per-article
	// cost is ~$0.0005; cache is forever, cost bounded by article
	// volume not user count.
	if cfg.Hosted.Enabled && aiClient != nil {
		tw := aitriage.New(db, aiClient)
		go tw.Run(ctx)
		log.Printf("[aitriage] triage worker started")
	}

	go func() {
		ticker := time.NewTicker(cfg.PollInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Printf("polling %d normal sources...", len(normalSrcs))
				srv.FetchAll()
			case <-ctx.Done():
				return
			}
		}
	}()

	if len(fastSrcs) > 0 {
		go func() {
			ticker := time.NewTicker(cfg.FastPollInterval())
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					log.Printf("fast-polling %d sources...", len(fastSrcs))
					srv.FetchFast()
				case <-ctx.Done():
					return
				}
			}
		}()
		log.Printf("fast poll: every %v for %d sources", cfg.FastPollInterval(), len(fastSrcs))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		srv.Shutdown()
	}()

	log.Printf("normal poll: every %v for %d sources", cfg.PollInterval(), len(normalSrcs))
	log.Printf("oM noM Security Feeds running at http://localhost:%d", cfg.Port)
	log.Printf("config: %s", cfgPath)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("server: %v", err)
	}
}

// resolveConfigPath picks where secfeed expects its config:
//   1. Positional CLI arg (legacy / dev workflow).
//   2. SECFEED_CONFIG env var.
//   3. OS user config dir + /secfeed/config.json.
//   4. Fall back to ./config.json.
func resolveConfigPath() string {
	if len(os.Args) > 1 && os.Args[1] != "" {
		return os.Args[1]
	}
	if v := os.Getenv("SECFEED_CONFIG"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err == nil && dir != "" {
		return filepath.Join(dir, "secfeed", "config.json")
	}
	return "config.json"
}

// runTUI loads the same config + opens the same SQLite DB the server
// would, then hands off to internal/tui. SQLite WAL handles concurrent
// reads + the occasional TUI write (mark-read, bookmark) cleanly, so
// running this alongside a `secfeed serve` instance is fine.
//
// We also spin up NVD + EPSS clients pointed at the same DB so the
// CVE popover can show CVSS / CWE / EPSS percentile inline. Both
// clients cache against SQLite so first lookups go to the network
// but subsequent are instant.
func runTUI() {
	cfgPath := resolveTUIConfigPath()
	if err := ensureConfigExists(cfgPath); err != nil {
		log.Fatalf("config init: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.DBPath != "" && !filepath.IsAbs(cfg.DBPath) {
		cfg.DBPath = filepath.Join(filepath.Dir(cfgPath), cfg.DBPath)
	}
	db, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	defer db.Close()

	// NVD: use NVD_API_KEY env var if present (raises the rate limit
	// from 5/30s to 50/30s). Without a key the default-throttled
	// client still works, just slower on cold lookups.
	nvd := cve.NewNVDClient(db.DB(), os.Getenv("NVD_API_KEY"))
	epss := cve.NewEPSSClient(db.DB())

	// AI summarizer (BYOK). Anthropic takes precedence if both keys
	// are set since Haiku is cheaper + faster than gpt-4o-mini. If
	// neither key is set, the AI brief modal renders a BYOK hint.
	var summarizer ai.Summarizer
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		summarizer = ai.NewAnthropicClient(key, "", "")
	} else if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		summarizer = ai.NewOpenAIClient(key, "", "")
	}

	// Scorer: a fresh one is fine (it's stateless aside from the KEV
	// catalog, which it loads lazily). The TUI uses this for the
	// score-explainer modal (`e` key).
	scorer := scoring.New()
	scorer.UpdateKEV()

	if err := tui.Run(db, nvd, epss, summarizer, scorer); err != nil {
		log.Fatalf("tui: %v", err)
	}
}

// resolveTUIConfigPath is a tiny variant of resolveConfigPath that
// ignores the "tui" subcommand token at os.Args[1] and looks at
// os.Args[2] for an optional positional config path
// (`secfeed tui /path/to/config.json`). Otherwise it uses the same
// env-var + OS-config-dir fallback as the server mode, so the TUI
// reads the same SQLite the daemon writes to by default.
func resolveTUIConfigPath() string {
	if len(os.Args) > 2 && os.Args[2] != "" {
		return os.Args[2]
	}
	if v := os.Getenv("SECFEED_CONFIG"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err == nil && dir != "" {
		return filepath.Join(dir, "secfeed", "config.json")
	}
	return "config.json"
}

// ensureConfigExists writes the embedded default config to the chosen path
// the first time secfeed is run. It does not overwrite an existing file.
func ensureConfigExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	log.Printf("first run: writing default config to %s", path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, defaultConfigBytes, 0o600)
}
