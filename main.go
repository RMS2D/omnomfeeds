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
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/digestmail"
	"github.com/RMS2D/omnomfeeds/internal/mitre"
	"github.com/RMS2D/omnomfeeds/internal/patchtuesday"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/server"
	"github.com/RMS2D/omnomfeeds/internal/sources"
	"github.com/RMS2D/omnomfeeds/internal/storage"
	"github.com/RMS2D/omnomfeeds/internal/tui"
)

// Explicit allowlist so a stray secret in web/ can't sneak into the binary.
//
//go:embed web/*.html web/*.svg web/*.png web/*.txt web/*.xml
var webFS embed.FS

//go:embed config.default.json
var defaultConfigBytes []byte

// Set via -ldflags at release time.
var version = "dev"

func main() {
	// `secfeed tui` bypasses the fetcher/scoring/server stack.
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
		// Watched-handle list rebuilt each cycle: config.json ∪ curated ∪ per-user subs.
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
		// Always register; handlesFn re-checks each poll, so user adds work without restart.
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

	// BYOK summarizer provider.
	var aiClient ai.Summarizer
	provider := strings.ToLower(strings.TrimSpace(cfg.AI.Provider))
	anthroKey := os.Getenv("ANTHROPIC_API_KEY")
	openaiKey := os.Getenv("OPENAI_API_KEY")
	if provider == "" {
		if anthroKey != "" {
			provider = "anthropic"
		} else if openaiKey != "" {
			provider = "openai"
		}
	}
	switch provider {
	case "anthropic":
		if anthroKey == "" {
			log.Printf("[llm] anthropic selected but ANTHROPIC_API_KEY unset; disabled")
		} else {
			aiClient = ai.NewAnthropicClient(anthroKey, cfg.AI.Model, cfg.AI.Focus)
			log.Printf("[llm] provider :: %s", aiClient.Name())
		}
	case "openai":
		if openaiKey == "" {
			log.Printf("[llm] openai selected but OPENAI_API_KEY unset; disabled")
		} else {
			aiClient = ai.NewOpenAIClient(openaiKey, cfg.AI.Model, cfg.AI.Focus)
			log.Printf("[llm] provider :: %s", aiClient.Name())
		}
	case "":
		// no key set; no summarizer
	default:
		log.Printf("[llm] unknown provider %q (expected anthropic or openai)", provider)
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

	// Sweep TTL'd entries from the in-memory CVE/trending caches.
	srv.StartCacheSweeper(ctx)

	// Daily DB cleanup. First tick +5min after start, then every 24h.
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

	// Pro webhook-alert worker; hosted-mode only.
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

	// Semantic-dedup worker; hosted + LLM provider required.
	if cfg.Hosted.Enabled && aiClient != nil {
		dw := aidedup.New(db, aiClient)
		go dw.Run(ctx)
		log.Printf("[aidedup] semantic-dedup worker started")
	}

	// Email digest worker; needs hosted + LLM + Resend.
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

	// Patch Tuesday brief generator; hourly tick, calendar-gated.
	if cfg.Hosted.Enabled && aiClient != nil {
		pw := patchtuesday.New(db, aiClient)
		go pw.Run(ctx)
		log.Printf("[patchtuesday] brief worker started")
	}

	// Triage worker: inline "what? so what?" lines for high-score articles.
	if cfg.Hosted.Enabled && aiClient != nil {
		tw := aitriage.New(db, aiClient)
		go tw.Run(ctx)
		log.Printf("[triage] worker started")
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

// resolveConfigPath: positional arg → SECFEED_CONFIG → OS config dir → ./config.json.
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

// runTUI loads the same config + DB as the server, then hands off to internal/tui.
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

	// NVD_API_KEY env var raises the rate limit from 5/30s to 50/30s.
	nvd := cve.NewNVDClient(db.DB(), os.Getenv("NVD_API_KEY"))
	epss := cve.NewEPSSClient(db.DB())

	// BYOK summarizer; Anthropic takes precedence when both keys are set.
	var summarizer ai.Summarizer
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		summarizer = ai.NewAnthropicClient(key, "", "")
	} else if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		summarizer = ai.NewOpenAIClient(key, "", "")
	}

	scorer := scoring.New()
	scorer.UpdateKEV()

	if err := tui.Run(db, nvd, epss, summarizer, scorer); err != nil {
		log.Fatalf("tui: %v", err)
	}
}

// resolveTUIConfigPath: like resolveConfigPath but reads os.Args[2] past the "tui" subcommand.
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
