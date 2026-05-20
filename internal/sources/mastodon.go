package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"time"
)

type MastodonSource struct {
	instance string
	keywords []string
	client   *http.Client
}

func NewMastodon(instance string, keywords []string) *MastodonSource {
	return &MastodonSource{
		instance: instance,
		keywords: keywords,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *MastodonSource) Name() string { return "Mastodon:" + m.instance }
func (m *MastodonSource) Type() string { return "mastodon" }

type mastodonStatus struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	CreatedAt string `json:"created_at"`
	Content   string `json:"content"`
	Language  string `json:"language"`
	Tags      []struct {
		Name string `json:"name"`
	} `json:"tags"`
	Account struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Acct        string `json:"acct"`
	} `json:"account"`
	Reblog *mastodonStatus `json:"reblog"`
}

func (m *MastodonSource) Fetch(ctx context.Context) ([]models.Article, error) {
	seen := make(map[string]bool)
	var articles []models.Article

	trendPosts, err := m.fetchTrending(ctx)
	if err != nil {
		log.Printf("[%s] trending: %v", m.Name(), err)
	} else {
		for _, a := range trendPosts {
			if seen[a.URL] {
				continue
			}
			seen[a.URL] = true
			articles = append(articles, a)
		}
	}

	for _, kw := range m.keywords {
		searchPosts, err := m.fetchSearch(ctx, kw)
		if err != nil {
			log.Printf("[%s] search '%s': %v", m.Name(), kw, err)
			break
		}
		for _, a := range searchPosts {
			if seen[a.URL] {
				continue
			}
			seen[a.URL] = true
			articles = append(articles, a)
		}
		time.Sleep(300 * time.Millisecond)
	}

	return articles, nil
}

func (m *MastodonSource) fetchTrending(ctx context.Context) ([]models.Article, error) {
	endpoint := fmt.Sprintf("https://%s/api/v1/trends/statuses?limit=40", m.instance)
	return m.fetchEndpoint(ctx, endpoint)
}

func (m *MastodonSource) fetchSearch(ctx context.Context, query string) ([]models.Article, error) {
	endpoint := fmt.Sprintf("https://%s/api/v2/search?q=%s&type=statuses&limit=20",
		m.instance, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecFeed/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 422 {
		return nil, fmt.Errorf("search requires auth (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("mastodon returned %d", resp.StatusCode)
	}

	var result struct {
		Statuses []mastodonStatus `json:"statuses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return m.convertStatuses(result.Statuses), nil
}

func (m *MastodonSource) fetchEndpoint(ctx context.Context, endpoint string) ([]models.Article, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecFeed/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("mastodon returned %d", resp.StatusCode)
	}

	var statuses []mastodonStatus
	if err := json.NewDecoder(resp.Body).Decode(&statuses); err != nil {
		return nil, err
	}

	return m.convertStatuses(statuses), nil
}

func (m *MastodonSource) convertStatuses(statuses []mastodonStatus) []models.Article {
	var articles []models.Article
	for _, s := range statuses {
		post := s
		if s.Reblog != nil {
			post = *s.Reblog
		}

		lang := post.Language
		if lang == "" {
			lang = s.Language
		}
		if lang != "" && lang != "en" {
			continue
		}

		pub, _ := time.Parse(time.RFC3339, post.CreatedAt)
		if pub.IsZero() {
			pub = time.Now()
		}

		text := stripHTML(post.Content)
		title := text
		if len(title) > 140 {
			title = title[:140] + "..."
		}

		author := post.Account.DisplayName
		if author == "" {
			author = post.Account.Username
		}

		articles = append(articles, models.Article{
			Title:       fmt.Sprintf("[%s] %s", author, title),
			URL:         post.URL,
			Source:      "Mastodon:" + m.instance,
			SourceType:  "mastodon",
			Summary:     text,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles
}
