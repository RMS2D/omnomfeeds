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
	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/mitre"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/server"
	"github.com/RMS2D/omnomfeeds/internal/sources"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

//go:embed web
var webFS embed.FS

//go:embed config.default.json
var defaultConfigBytes []byte

// Set via -ldflags at release time.
var version = "dev"

func main() {
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
	if cfg.Bluesky.Enabled && len(cfg.Bluesky.WatchedAccounts) > 0 && bskySrc != nil {
		normalSrcs = append(normalSrcs, sources.NewBlueskyAccounts(cfg.Bluesky.WatchedAccounts, bskySrc))
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
		AI:    aiClient,
	}

	total := len(normalSrcs) + len(fastSrcs)
	srv := server.New(db, normalSrcs, fastSrcs, scorer, cfg, webSubFS, enr)

	log.Printf("oM noM Security Feeds %s :: initial fetch from %d sources (%d fast, %d normal)...", version, total, len(fastSrcs), len(normalSrcs))
	srv.FetchAll()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
