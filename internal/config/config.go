package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type FeedConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Fast bool   `json:"fast,omitempty"`
}
type BazaarConfig struct {
	APIKey string `json:"api_key"`
}
type BlueskyConfig struct {
	Enabled         bool     `json:"enabled"`
	Identifier      string   `json:"identifier"`
	Password        string   `json:"password"`
	SearchTerms     []string `json:"search_terms"`
	WatchedAccounts []string `json:"watched_accounts"`
	PollInterval    int      `json:"poll_interval_minutes"`
}

type MastodonConfig struct {
	Instances []string `json:"instances"`
	Hashtags  []string `json:"hashtags"`
}

type GitHubConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
}

// AIConfig drives the BYOK digest. Provider is "anthropic", "openai", or ""
// (auto-detected by which API key env var is set). Keys are env-only.
type AIConfig struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	Focus    string `json:"focus,omitempty"`
}

// HostedConfig is populated only when HOSTED_MODE=true. All values come from
// env vars, never from config.json, since they're shared infrastructure
// secrets not per-user settings.
type HostedConfig struct {
	Enabled             bool
	OAuthRedirectURL    string
	GoogleClientID      string
	GoogleClientSecret  string
	SessionSecret       string
	StripeSecretKey     string
	StripeWebhookSecret string
	StripePriceID       string
	AnthropicAPIKey     string
	ResendAPIKey        string
	// AdminEmails is the lowercased list of users who can edit the global
	// config surfaces (API keys, sources, watched accounts). Populated from
	// the ADMIN_EMAILS env var (comma-separated). Empty list = no admins;
	// global config is effectively locked from the UI.
	AdminEmails []string
}

// IsAdmin reports whether email is in the configured admin list.
// Case-insensitive. Always false when AdminEmails is empty.
func (h HostedConfig) IsAdmin(email string) bool {
	if email == "" || len(h.AdminEmails) == 0 {
		return false
	}
	e := strings.ToLower(strings.TrimSpace(email))
	for _, a := range h.AdminEmails {
		if a == e {
			return true
		}
	}
	return false
}

type Config struct {
	Port                    int            `json:"port"`
	DBPath                  string         `json:"db_path"`
	PollIntervalMinutes     int            `json:"poll_interval_minutes"`
	FastPollIntervalMinutes int            `json:"fast_poll_interval_minutes"`
	MaxArticlesPerSrc       int            `json:"max_articles_per_source"`
	RSSFeeds                []FeedConfig   `json:"rss_feeds"`
	Subreddits              []string       `json:"subreddits"`
	Bluesky                 BlueskyConfig  `json:"bluesky"`
	Mastodon                MastodonConfig `json:"mastodon"`
	GitHub                  GitHubConfig   `json:"github"`
	MalwareBazaar           BazaarConfig   `json:"malwarebazaar"`
	AI                      AIConfig       `json:"ai"`
	Hosted                  HostedConfig   `json:"-"`
	path                    string         `json:"-"`
}

func (c *Config) PollInterval() time.Duration {
	if c.PollIntervalMinutes <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(c.PollIntervalMinutes) * time.Minute
}

func (c *Config) FastPollInterval() time.Duration {
	if c.FastPollIntervalMinutes <= 0 {
		return 3 * time.Minute
	}
	return time.Duration(c.FastPollIntervalMinutes) * time.Minute
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Port:                8080,
		DBPath:              "secfeed.db",
		PollIntervalMinutes: 10,
		MaxArticlesPerSrc:   50,
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if v := os.Getenv("BLUESKY_APP_PASSWORD"); v != "" {
		cfg.Bluesky.Password = v
	}
	if v := os.Getenv("MALWAREBAZAAR_API_KEY"); v != "" {
		cfg.MalwareBazaar.APIKey = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		cfg.GitHub.Token = v
	}
	cfg.Hosted = loadHostedFromEnv()
	cfg.path = path
	return cfg, nil
}

// loadHostedFromEnv pulls every hosted-mode setting from env vars only.
// Empty values are tolerated; the server will only enable Hosted endpoints
// when both Enabled is true AND the credentials needed for that endpoint
// are set (e.g. Stripe endpoints require StripeSecretKey).
func loadHostedFromEnv() HostedConfig {
	enabled := os.Getenv("HOSTED_MODE") == "true" || os.Getenv("HOSTED_MODE") == "1"
	return HostedConfig{
		Enabled:             enabled,
		OAuthRedirectURL:    os.Getenv("OAUTH_REDIRECT_URL"),
		GoogleClientID:      os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		GoogleClientSecret:  os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		SessionSecret:       os.Getenv("SESSION_SECRET"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripePriceID:       os.Getenv("STRIPE_PRO_PRICE_ID"),
		AnthropicAPIKey:     os.Getenv("ANTHROPIC_API_KEY"),
		ResendAPIKey:        os.Getenv("RESEND_API_KEY"),
		AdminEmails:         parseAdminEmails(os.Getenv("ADMIN_EMAILS")),
	}
}

// parseAdminEmails splits a comma-separated list of admin emails into a
// lowercased + trimmed slice. Empty / whitespace-only entries are dropped.
func parseAdminEmails(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		e := strings.ToLower(strings.TrimSpace(p))
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("no config path set")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0644)
}

func (c *Config) SafeCopy() Config {
	copy := *c
	if copy.Bluesky.Password != "" {
		copy.Bluesky.Password = "********"
	}
	if copy.GitHub.Token != "" {
		copy.GitHub.Token = "********"
	}
	return copy
}
