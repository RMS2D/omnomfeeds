package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/models"
)

// badHandleSkip is how long we ignore a handle that returned 400 (HandleNotFound,
// renamed, deactivated). After this window we retry once; if it 400s again, skip
// is reset and we wait another window. Stops every poll from re-logging dead
// accounts the user added via the curated picker.
const badHandleSkip = 24 * time.Hour

type BlueskyAccountsSource struct {
	// handlesFn is called fresh at every Fetch so newly-subscribed handles
	// (added via the per-user UI between polls) are picked up without a
	// restart. The static-list form is gone.
	handlesFn func() []string
	auth      *BlueskySource
	client    *http.Client

	badMu    sync.Mutex
	badUntil map[string]time.Time
}

func NewBlueskyAccounts(handlesFn func() []string, auth *BlueskySource) *BlueskyAccountsSource {
	return &BlueskyAccountsSource{
		handlesFn: handlesFn,
		auth:      auth,
		client:    &http.Client{Timeout: 15 * time.Second},
		badUntil:  make(map[string]time.Time),
	}
}

func (b *BlueskyAccountsSource) markBad(handle string) {
	b.badMu.Lock()
	b.badUntil[handle] = time.Now().Add(badHandleSkip)
	b.badMu.Unlock()
}

func (b *BlueskyAccountsSource) isBad(handle string) bool {
	b.badMu.Lock()
	defer b.badMu.Unlock()
	t, ok := b.badUntil[handle]
	if !ok {
		return false
	}
	if time.Now().After(t) {
		delete(b.badUntil, handle)
		return false
	}
	return true
}

func (b *BlueskyAccountsSource) Name() string { return "Bluesky:accounts" }
func (b *BlueskyAccountsSource) Type() string { return "bluesky" }

type bskyFeedResp struct {
	Feed []struct {
		Post struct {
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
		} `json:"post"`
	} `json:"feed"`
}

func (b *BlueskyAccountsSource) Fetch(ctx context.Context) ([]models.Article, error) {
	if b.auth == nil || b.auth.identifier == "" {
		return nil, fmt.Errorf("bluesky auth required for account feeds")
	}

	token, err := b.auth.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	seen := make(map[string]bool)
	var articles []models.Article

	handles := b.handlesFn()
	for _, handle := range handles {
		if b.isBad(handle) {
			continue
		}
		posts, err := b.fetchAccount(ctx, handle, token)
		if err != nil {
			// 400 typically means HandleNotFound (renamed / deleted). Cache the
			// skip so subsequent polls don't keep retrying + logging the same
			// dead handle for the next 24h.
			if strings.Contains(err.Error(), "status 400") {
				b.markBad(handle)
				log.Printf("[Bluesky:accounts] %s: handle not found, skipping for 24h", handle)
				continue
			}
			log.Printf("[Bluesky:accounts] %s: %v", handle, err)
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

	return articles, nil
}

func (b *BlueskyAccountsSource) fetchAccount(ctx context.Context, handle, token string) ([]models.Article, error) {
	endpoint := fmt.Sprintf(
		"https://bsky.social/xrpc/app.bsky.feed.getAuthorFeed?actor=%s&limit=30&filter=posts_no_replies",
		url.QueryEscape(handle),
	)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result bskyFeedResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}

	var articles []models.Article
	for _, item := range result.Feed {
		post := item.Post
		if len(post.Record.Langs) > 0 && !containsLang(post.Record.Langs, "en") {
			continue
		}

		pub, _ := time.Parse(time.RFC3339, post.Record.CreatedAt)
		if pub.IsZero() {
			pub = time.Now()
		}

		parts := strings.Split(post.URI, "/")
		webURL := fmt.Sprintf("https://bsky.app/profile/%s/post/%s",
			url.PathEscape(post.Author.Handle), url.PathEscape(parts[len(parts)-1]))

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
			Source:      "Bluesky:@" + handle,
			SourceType:  "bluesky",
			Summary:     post.Record.Text,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}
