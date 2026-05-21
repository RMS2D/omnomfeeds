package models

import "time"

type Article struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Source      string    `json:"source"`
	SourceType  string    `json:"source_type"` // rss, reddit, bluesky
	Summary     string    `json:"summary"`
	Score       int       `json:"score"`
	Tags        []string  `json:"tags"`
	PublishedAt time.Time `json:"published_at"`
	FetchedAt   time.Time `json:"fetched_at"`
	Read        bool      `json:"read"`
	// Triage is the AI-generated "what? so what?" one-liner. Populated
	// per-request for Pro users from the cached cache (article_ai_triage
	// table). Empty for non-Pro users and for articles that haven't been
	// triaged yet.
	Triage string `json:"triage,omitempty"`
}

type SourceStatus struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	LastFetch time.Time `json:"last_fetch"`
	LastError string    `json:"last_error,omitempty"`
	ItemCount int       `json:"item_count"`
}

type Stats struct {
	TotalArticles   int            `json:"total_articles"`
	UnreadCount     int            `json:"unread_count"`
	SourceBreakdown map[string]int `json:"source_breakdown"`
	TopTags         map[string]int `json:"top_tags"`
	LastUpdated     time.Time      `json:"last_updated"`
}
