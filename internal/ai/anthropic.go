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
	if a.apiKey == "" {
		return "", fmt.Errorf("anthropic: no API key configured")
	}
	prompt := BuildPrompt(articles, a.focus)
	body := map[string]any{
		"model":      a.model,
		"max_tokens": 1500,
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
