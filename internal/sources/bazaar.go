package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"time"
)

type MalwareBazaarSource struct {
	client *http.Client
	apiKey string
}

func NewMalwareBazaar(apiKey string) *MalwareBazaarSource {
	return &MalwareBazaarSource{
		client: &http.Client{Timeout: 15 * time.Second},
		apiKey: strings.TrimSpace(apiKey),
	}
}

func (m *MalwareBazaarSource) Name() string { return "MalwareBazaar" }
func (m *MalwareBazaarSource) Type() string { return "ioc_feed" }

type bazaarResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		Sha256Hash string   `json:"sha256_hash"`
		FirstSeen  string   `json:"first_seen"`
		FileName   string   `json:"file_name"`
		FileType   string   `json:"file_type"`
		Signature  string   `json:"signature"`
		FileSize   int      `json:"file_size"`
		Imphash    string   `json:"imphash"`
		Tlsh       string   `json:"tlsh"`
		Telfhash   string   `json:"telfhash"`
		Tags       []string `json:"tags"`
		YaraRules  []struct {
			RuleName    string `json:"rule_name"`
			Description string `json:"description"`
			Author      string `json:"author"`
		} `json:"yara_rules"`
	} `json:"data"`
}

func (m *MalwareBazaarSource) Fetch(ctx context.Context) ([]models.Article, error) {
	if m.apiKey == "" {
		return nil, fmt.Errorf("API key is completely empty! Go failed to read it from config.json")
	}

	data := url.Values{}
	data.Set("query", "get_recent")
	data.Set("selector", "100")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://mb-api.abuse.ch/api/v1/", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Auth-Key", m.apiKey)
	req.Header.Set("API-KEY", m.apiKey)
	req.Header.Set("API-Key", m.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("malwarebazaar returned %d", resp.StatusCode)
	}

	var result bazaarResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.QueryStatus != "ok" {
		return nil, fmt.Errorf("api status: %s", result.QueryStatus)
	}

	var articles []models.Article
	for _, item := range result.Data {
		validTypes := map[string]bool{"exe": true, "dll": true, "ps1": true, "vbs": true, "msi": true, "sys": true, "elf": true, "macho": true}
		if !validTypes[item.FileType] {
			continue
		}

		pub, _ := time.Parse("2006-01-02 15:04:05", item.FirstSeen)
		if pub.IsZero() {
			pub = time.Now()
		}

		var yaraNames []string
		var yaraDescriptions []string

		for _, yr := range item.YaraRules {
			yaraNames = append(yaraNames, yr.RuleName)
			desc := yr.RuleName
			if yr.Description != "" && yr.Description != "none" {
				desc += fmt.Sprintf(" (%s)", yr.Description)
			}
			yaraDescriptions = append(yaraDescriptions, desc)
		}

		sig := item.Signature
		if (sig == "" || sig == "Unknown Family") && len(item.YaraRules) > 0 {
			sig = "YARA: " + item.YaraRules[0].RuleName
		} else if sig == "" {
			sig = "Unknown Family"
		}

		var tags []string
		tags = append(tags, "sha256:"+item.Sha256Hash)
		tags = append(tags, "artifact:"+item.FileType)
		for _, t := range item.Tags {
			tags = append(tags, t)
		}
		for _, y := range yaraNames {
			tags = append(tags, "yara:"+y)
		}

		// --- NEW: Build a rich, analyst-focused summary ---
		var details []string
		if item.FileSize > 0 {
			details = append(details, fmt.Sprintf("Size: %d KB", item.FileSize/1024))
		}
		if item.Imphash != "" {
			details = append(details, "ImpHash: "+item.Imphash)
		}
		if item.Telfhash != "" {
			details = append(details, "TelfHash: "+item.Telfhash) // ELF specific hash
		} else if item.Tlsh != "" {
			details = append(details, "TLSH: "+item.Tlsh)
		}

		summary := strings.Join(details, " | ")
		if len(yaraDescriptions) > 0 {
			summary += "\n\nYARA: " + strings.Join(yaraDescriptions, ", ")
		}
		// Fallback if no extra data exists
		if summary == "" {
			summary = fmt.Sprintf("New %s payload detected on MalwareBazaar.", item.FileType)
		}

		articles = append(articles, models.Article{
			Title:       fmt.Sprintf("[%s] %s", sig, item.FileName),
			URL:         "https://bazaar.abuse.ch/sample/" + item.Sha256Hash,
			Source:      "MalwareBazaar",
			SourceType:  "ioc_feed",
			Summary:     summary,
			Score:       50,
			Tags:        tags,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}

	return articles, nil
}
