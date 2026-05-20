package sources

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
)

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

type RSSSource struct {
	name string
	url  string
}

func NewRSS(name, url string) *RSSSource {
	return &RSSSource{name: name, url: url}
}

func (r *RSSSource) Name() string { return r.name }
func (r *RSSSource) Type() string { return "rss" }

func (r *RSSSource) Fetch(ctx context.Context) ([]models.Article, error) {
	// 1. Manually build the request to spoof a full desktop browser
	req, err := http.NewRequestWithContext(ctx, "GET", r.url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// 2. Execute the request
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	// 3. Pass the raw body to gofeed for parsing
	parser := gofeed.NewParser()
	feed, err := parser.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("feed parsing error: %v", err)
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
			Source:      r.name,
			SourceType:  "rss",
			Summary:     summary,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}

func stripHTML(s string) string {
	s = htmlTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}
