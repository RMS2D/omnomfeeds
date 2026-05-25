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

const openaiAPI = "https://api.openai.com/v1/chat/completions"

// OpenAIClient talks to /v1/chat/completions. Defaults to gpt-4o-mini for the
// same reasons we default to Haiku on Anthropic: cheap, fast, plenty for a
// ~400-word brief.
type OpenAIClient struct {
	apiKey string
	model  string
	focus  string
	client *http.Client
}

func NewOpenAIClient(apiKey, model, focus string) *OpenAIClient {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &OpenAIClient{
		apiKey: apiKey,
		model:  model,
		focus:  focus,
		client: &http.Client{Timeout: 90 * time.Second},
	}
}

func (o *OpenAIClient) Name() string { return "openai:" + o.model }

func (o *OpenAIClient) Summarize(ctx context.Context, articles []Article) (string, error) {
	return o.complete(ctx, BuildPrompt(articles, o.focus), 1500)
}

// ExplainCVE matches the Anthropic implementation: 3-bullet deep-dive on
// a single CVE. ~150 output tokens; the storage layer caches per CVE id.
func (o *OpenAIClient) ExplainCVE(ctx context.Context, cve CVEDetail) (string, error) {
	return o.complete(ctx, BuildCVEPrompt(cve), 350)
}

// ExplainArticle: 2-3 line plain-English summary of a single article.
// Cached per article.id by the caller.
func (o *OpenAIClient) ExplainArticle(ctx context.Context, art Article) (string, error) {
	return o.complete(ctx, BuildArticlePrompt(art), 250)
}

// TriageArticle: inline one-sentence "what? so what?" line.
// Cached per article.id by the caller.
func (o *OpenAIClient) TriageArticle(ctx context.Context, art Article) (string, error) {
	return o.complete(ctx, BuildTriagePrompt(art), 80)
}

// ClusterArticles: semantic-dedup batch call. Matches the Anthropic impl.
func (o *OpenAIClient) ClusterArticles(ctx context.Context, items []ClusterItem) ([]ClusterGroup, error) {
	if len(items) == 0 {
		return nil, nil
	}
	text, err := o.complete(ctx, BuildClusterPrompt(items), 700)
	if err != nil {
		return nil, err
	}
	return ParseClusterResponse(text)
}

// RankForProfile: re-sort articles by relevance to a user profile.
func (o *OpenAIClient) RankForProfile(ctx context.Context, profile string, items []ClusterItem) ([]int64, error) {
	if profile == "" || len(items) == 0 {
		return nil, nil
	}
	text, err := o.complete(ctx, BuildRankPrompt(profile, items), 700)
	if err != nil {
		return nil, err
	}
	return ParseRankResponse(text)
}

func (o *OpenAIClient) complete(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if o.apiKey == "" {
		return "", fmt.Errorf("openai: no API key configured")
	}
	body := map[string]any{
		"model": o.model,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
		"max_tokens": maxTokens,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", openaiAPI, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("openai: status %d :: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}
