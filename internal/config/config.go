package config

import (
	"encoding/json"
	"fmt"
	"os"
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
	cfg.path = path
	return cfg, nil
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
