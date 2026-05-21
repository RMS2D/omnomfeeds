package sources

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/mmcdole/gofeed"
)

// Reddit blocks /.json from datacenter IPs (Cloudflare 403s every UA we
// send). The /.rss endpoint on the same subreddits stays open with a
// browser-shaped UA, so we drop down to RSS for parity with the rest of
// the source pipeline. SourceType stays "reddit" so the UI can still
// theme + filter on it distinctly from generic RSS feeds.
type RedditSource struct {
	subreddit string
}

func NewReddit(subreddit string) *RedditSource {
	return &RedditSource{subreddit: subreddit}
}

func (r *RedditSource) Name() string { return "r/" + r.subreddit }
func (r *RedditSource) Type() string { return "reddit" }

func (r *RedditSource) Fetch(ctx context.Context) ([]models.Article, error) {
	url := fmt.Sprintf("https://www.reddit.com/r/%s/new/.rss?limit=50", r.subreddit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Mirror the RSS source's browser UA: anything that looks like a real
	// browser gets the feed; the bare Go default UA gets 403.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/rss+xml, application/xml;q=0.9, */*;q=0.8")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
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

	parser := gofeed.NewParser()
	feed, err := parser.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reddit rss parse: %v", err)
	}

	var articles []models.Article
	for _, item := range feed.Items {
		pub := time.Now()
		if item.PublishedParsed != nil {
			pub = *item.PublishedParsed
		} else if item.UpdatedParsed != nil {
			pub = *item.UpdatedParsed
		}
		summary := stripHTML(item.Description)
		if len(summary) > 500 {
			summary = summary[:500] + "..."
		}
		articles = append(articles, models.Article{
			Title:       item.Title,
			URL:         item.Link,
			Source:      "r/" + r.subreddit,
			SourceType:  "reddit",
			Summary:     summary,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}
