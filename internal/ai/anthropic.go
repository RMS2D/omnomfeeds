package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const anthropicAPI = "https://api.anthropic.com/v1/messages"

// AnthropicClient talks to /v1/messages. We default to claude-haiku-4-5 because
// the digest is short-context + low-latency-tolerant; users can pin a stronger
// model in config if they want richer prose.
type AnthropicClient struct {
	apiKey string
	model  string
	focus  string
	client *http.Client
}

func NewAnthropicClient(apiKey, model, focus string) *AnthropicClient {
	if model == "" {
		model = "claude-haiku-4-5"
	}
	return &AnthropicClient{
		apiKey: apiKey,
		model:  model,
		focus:  focus,
		client: &http.Client{Timeout: 90 * time.Second},
	}
}

func (a *AnthropicClient) Name() string { return "anthropic:" + a.model }

func (a *AnthropicClient) Summarize(ctx context.Context, articles []Article) (string, error) {
	return a.complete(ctx, BuildPrompt(articles, a.focus), 1500)
}

// ExplainCVE returns a 3-bullet deep-dive on a single CVE. ~150 tokens out
// keeps the cost at well under a tenth of a cent per call; the worker
// caches per CVE id so each CVE costs at most once across all Pro users.
func (a *AnthropicClient) ExplainCVE(ctx context.Context, cve CVEDetail) (string, error) {
	return a.complete(ctx, BuildCVEPrompt(cve), 350)
}

// ExplainArticle returns 2-3 lines summarising a single article. Cached
// per article.id so every Pro user who clicks "explain" on the same item
// pays the LLM call only once across the whole deployment.
func (a *AnthropicClient) ExplainArticle(ctx context.Context, art Article) (string, error) {
	return a.complete(ctx, BuildArticlePrompt(art), 250)
}

// TriageArticle returns a single-sentence "what? so what?" line for
// inline rendering next to the article title in the reader. Cached
// per article.id forever, so the cost is bounded to ~$0.0005 per new
// article that crosses the score threshold.
func (a *AnthropicClient) TriageArticle(ctx context.Context, art Article) (string, error) {
	return a.complete(ctx, BuildTriagePrompt(art), 80)
}

// ClusterArticles groups semantic duplicates in a batch. ~500-1500 input
// tokens depending on batch size + ~200 out. One call per fetch cycle
// gives the whole deployment a less-noisy feed.
func (a *AnthropicClient) ClusterArticles(ctx context.Context, items []ClusterItem) ([]ClusterGroup, error) {
	if len(items) == 0 {
		return nil, nil
	}
	text, err := a.complete(ctx, BuildClusterPrompt(items), 700)
	if err != nil {
		return nil, err
	}
	return ParseClusterResponse(text)
}

// RankForProfile re-orders a batch of articles by relevance to a free-
// form user-supplied profile. Output is just a sorted id list; the
// caller maps it back to articles.
func (a *AnthropicClient) RankForProfile(ctx context.Context, profile string, items []ClusterItem) ([]int64, error) {
	if profile == "" || len(items) == 0 {
		return nil, nil
	}
	text, err := a.complete(ctx, BuildRankPrompt(profile, items), 700)
	if err != nil {
		return nil, err
	}
	return ParseRankResponse(text)
}

func (a *AnthropicClient) complete(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if a.apiKey == "" {
		return "", fmt.Errorf("anthropic: no API key configured")
	}
	body := map[string]any{
		"model":      a.model,
		"max_tokens": maxTokens,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", anthropicAPI, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("anthropic: status %d :: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	for _, c := range out.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: no text in response")
}
