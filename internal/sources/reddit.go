package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"time"
)

type RedditSource struct {
	subreddit string
	client    *http.Client
}

func NewReddit(subreddit string) *RedditSource {
	return &RedditSource{
		subreddit: subreddit,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (r *RedditSource) Name() string { return "r/" + r.subreddit }
func (r *RedditSource) Type() string { return "reddit" }

type redditListing struct {
	Data struct {
		Children []struct {
			Data struct {
				Title     string  `json:"title"`
				URL       string  `json:"url"`
				Selftext  string  `json:"selftext"`
				Permalink string  `json:"permalink"`
				Created   float64 `json:"created_utc"`
				Score     int     `json:"score"`
				NumComms  int     `json:"num_comments"`
			} `json:"data"`
		} `json:"children"`
	} `json:"data"`
}

func (r *RedditSource) Fetch(ctx context.Context) ([]models.Article, error) {
	url := fmt.Sprintf("https://www.reddit.com/r/%s/new.json?limit=50", r.subreddit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecFeed/1.0 (security news aggregator)")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("reddit rate limited, will retry next cycle")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("reddit returned status %d", resp.StatusCode)
	}

	var listing redditListing
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, err
	}

	var articles []models.Article
	for _, child := range listing.Data.Children {
		d := child.Data
		summary := d.Selftext
		if len(summary) > 500 {
			summary = summary[:500] + "..."
		}

		link := d.URL
		if link == "" || link == "https://www.reddit.com"+d.Permalink {
			link = "https://www.reddit.com" + d.Permalink
		}

		articles = append(articles, models.Article{
			Title:       d.Title,
			URL:         link,
			Source:      "r/" + r.subreddit,
			SourceType:  "reddit",
			Summary:     summary,
			PublishedAt: time.Unix(int64(d.Created), 0),
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}
