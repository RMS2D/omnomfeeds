package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"sync"
	"time"
)

type BlueskySource struct {
	searchTerms []string
	identifier  string
	password    string
	client      *http.Client

	mu          sync.Mutex
	accessJwt   string
	tokenExpiry time.Time
}

func NewBluesky(searchTerms []string, identifier, password string) *BlueskySource {
	return &BlueskySource{
		searchTerms: searchTerms,
		identifier:  identifier,
		password:    password,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (b *BlueskySource) Name() string { return "Bluesky" }
func (b *BlueskySource) Type() string { return "bluesky" }

type bskySessionResp struct {
	AccessJwt string `json:"accessJwt"`
	DID       string `json:"did"`
}

type bskySearchResp struct {
	Posts []struct {
		URI    string `json:"uri"`
		Author struct {
			Handle      string `json:"handle"`
			DisplayName string `json:"displayName"`
		} `json:"author"`
		Record struct {
			Text      string   `json:"text"`
			CreatedAt string   `json:"createdAt"`
			Langs     []string `json:"langs"`
		} `json:"record"`
	} `json:"posts"`
}

func (b *BlueskySource) authenticate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{
		"identifier": b.identifier,
		"password":   b.password,
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://bsky.social/xrpc/com.atproto.server.createSession",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SecFeed/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("auth failed: status %d (check identifier/password in config)", resp.StatusCode)
	}

	var session bskySessionResp
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return err
	}

	b.mu.Lock()
	b.accessJwt = session.AccessJwt
	b.tokenExpiry = time.Now().Add(90 * time.Minute)
	b.mu.Unlock()

	return nil
}

func (b *BlueskySource) getToken(ctx context.Context) (string, error) {
	b.mu.Lock()
	token := b.accessJwt
	expired := time.Now().After(b.tokenExpiry)
	b.mu.Unlock()

	if token != "" && !expired {
		return token, nil
	}

	if err := b.authenticate(ctx); err != nil {
		return "", err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accessJwt, nil
}

func (b *BlueskySource) Fetch(ctx context.Context) ([]models.Article, error) {
	if b.identifier == "" || b.password == "" {
		return nil, fmt.Errorf("bluesky requires auth -- set identifier and password in config (free account at bsky.app)")
	}

	token, err := b.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	seen := make(map[string]bool)
	var articles []models.Article
	errors := 0

	for _, term := range b.searchTerms {
		posts, err := b.search(ctx, term, token)
		if err != nil {
			errors++
			if errors <= 3 {
				log.Printf("[Bluesky] search '%s': %v", term, err)
			}
			if errors > 10 {
				break
			}
			continue
		}
		for _, a := range posts {
			if seen[a.URL] {
				continue
			}
			seen[a.URL] = true
			articles = append(articles, a)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if errors > 3 {
		log.Printf("[Bluesky] %d/%d search terms failed", errors, len(b.searchTerms))
	}
	return articles, nil
}

func (b *BlueskySource) search(ctx context.Context, query, token string) ([]models.Article, error) {
	endpoint := fmt.Sprintf(
		"https://bsky.social/xrpc/app.bsky.feed.searchPosts?q=%s&limit=25&sort=latest",
		url.QueryEscape(query),
	)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "SecFeed/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		b.mu.Lock()
		b.accessJwt = ""
		b.mu.Unlock()
		return nil, fmt.Errorf("token expired, will re-auth next cycle")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result bskySearchResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var articles []models.Article
	for _, post := range result.Posts {
		if len(post.Record.Langs) > 0 && !containsLang(post.Record.Langs, "en") {
			continue
		}

		pub, _ := time.Parse(time.RFC3339, post.Record.CreatedAt)
		if pub.IsZero() {
			pub = time.Now()
		}

		parts := strings.Split(post.URI, "/")
		webURL := fmt.Sprintf("https://bsky.app/profile/%s/post/%s",
			post.Author.Handle, parts[len(parts)-1])

		title := post.Record.Text
		if len(title) > 120 {
			title = title[:120] + "..."
		}

		author := post.Author.DisplayName
		if author == "" {
			author = post.Author.Handle
		}

		articles = append(articles, models.Article{
			Title:       fmt.Sprintf("[%s] %s", author, title),
			URL:         webURL,
			Source:      "Bluesky",
			SourceType:  "bluesky",
			Summary:     post.Record.Text,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}

func containsLang(langs []string, target string) bool {
	for _, l := range langs {
		if strings.HasPrefix(l, target) {
			return true
		}
	}
	return false
}
