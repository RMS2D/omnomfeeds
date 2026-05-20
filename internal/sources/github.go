package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"time"
)

type GitHubAdvisorySource struct {
	client *http.Client
	token  string
}

func NewGitHubAdvisory(token string) *GitHubAdvisorySource {
	return &GitHubAdvisorySource{
		client: &http.Client{Timeout: 15 * time.Second},
		token:  token,
	}
}

func (g *GitHubAdvisorySource) Name() string { return "GitHub Advisories" }
func (g *GitHubAdvisorySource) Type() string { return "github" }

type ghAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	CVSS            json.RawMessage `json:"cvss"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string          `json:"vulnerable_version_range"`
		FirstPatchedVersion    json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

func (g *GitHubAdvisorySource) Fetch(ctx context.Context) ([]models.Article, error) {
	var all []models.Article

	for _, severity := range []string{"critical", "high"} {
		articles, err := g.fetchBySeverity(ctx, severity)
		if err != nil {
			log.Printf("[GitHub Advisories] %s: %v", severity, err)
			continue
		}
		all = append(all, articles...)
		time.Sleep(500 * time.Millisecond)
	}

	return all, nil
}

func (g *GitHubAdvisorySource) fetchBySeverity(ctx context.Context, severity string) ([]models.Article, error) {
	endpoint := fmt.Sprintf(
		"https://api.github.com/advisories?type=reviewed&severity=%s&per_page=30&sort=published&direction=desc",
		severity,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SecFeed/1.0")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		return nil, fmt.Errorf("github returned %d (rate-limit-remaining: %s)", resp.StatusCode, remaining)
	}

	var advisories []ghAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, err
	}

	var articles []models.Article
	for _, adv := range advisories {
		pub, _ := time.Parse(time.RFC3339, adv.PublishedAt)
		if pub.IsZero() {
			pub, _ = time.Parse(time.RFC3339, adv.UpdatedAt)
		}
		if pub.IsZero() {
			pub = time.Now()
		}

		var cveIDs []string
		for _, id := range adv.Identifiers {
			if id.Type == "CVE" {
				cveIDs = append(cveIDs, id.Value)
			}
		}

		title := adv.Summary
		if len(cveIDs) > 0 {
			title = fmt.Sprintf("[%s] %s", strings.Join(cveIDs, ", "), adv.Summary)
		}

		summary := adv.Description
		if len(summary) > 500 {
			summary = summary[:500] + "..."
		}

		var cvss struct {
			Score float64 `json:"score"`
		}
		if len(adv.CVSS) > 0 {
			json.Unmarshal(adv.CVSS, &cvss)
		}
		if cvss.Score > 0 {
			summary = fmt.Sprintf("[CVSS %.1f / %s] %s", cvss.Score, strings.ToUpper(adv.Severity), summary)
		}

		var pkgs []string
		for _, v := range adv.Vulnerabilities {
			if v.Package.Name != "" {
				pkgs = append(pkgs, v.Package.Ecosystem+"/"+v.Package.Name)
			}
		}
		if len(pkgs) > 0 {
			summary += "\nAffected: " + strings.Join(pkgs, ", ")
		}

		articles = append(articles, models.Article{
			Title:       title,
			URL:         adv.HTMLURL,
			Source:      "GitHub Advisories",
			SourceType:  "github",
			Summary:     summary,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}

	return articles, nil
}

type GitHubPoCSource struct {
	client  *http.Client
	token   string
	queries []string
}

func NewGitHubPoC(token string) *GitHubPoCSource {
	return &GitHubPoCSource{
		client: &http.Client{Timeout: 15 * time.Second},
		token:  token,
		queries: []string{
			"\"wdac bypass\"", "\"applocker bypass\"", "\"edr evasion\"",
			"\"edr bypass\"", "\"amsi bypass\"", "byovd",
		},
	}
}

func (g *GitHubPoCSource) Name() string { return "GitHub PoCs" }
func (g *GitHubPoCSource) Type() string { return "github" }

type ghRepoSearch struct {
	Items []struct {
		Name        string `json:"name"`
		FullName    string `json:"full_name"`
		HTMLURL     string `json:"html_url"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
		PushedAt    string `json:"pushed_at"`
		Owner       struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"items"`
}

func (g *GitHubPoCSource) Fetch(ctx context.Context) ([]models.Article, error) {
	var all []models.Article

	// We only want PoCs created or pushed to in the last 7 days
	recentDate := time.Now().Add(-7 * 24 * time.Hour).Format("2006-01-02")

	for _, query := range g.queries {
		// e.g., "wdac bypass" pushed:>202X-XX-XX
		q := fmt.Sprintf("%s pushed:>%s", query, recentDate)
		endpoint := fmt.Sprintf(
			"https://api.github.com/search/repositories?q=%s&sort=updated&order=desc&per_page=10",
			url.QueryEscape(q),
		)

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "SecFeed/1.0")
		if g.token != "" {
			req.Header.Set("Authorization", "Bearer "+g.token)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}

		var result ghRepoSearch
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		for _, repo := range result.Items {
			pub, _ := time.Parse(time.RFC3339, repo.PushedAt)
			if pub.IsZero() {
				pub = time.Now()
			}

			summary := repo.Description
			if summary == "" {
				summary = "No description provided."
			}

			all = append(all, models.Article{
				Title:       fmt.Sprintf("[%s] %s", repo.Owner.Login, repo.Name),
				URL:         repo.HTMLURL,
				Source:      "GitHub PoCs",
				SourceType:  "github",
				Summary:     summary,
				PublishedAt: pub,
				FetchedAt:   time.Now(),
			})
		}
		// Respect GitHub Search API rate limits
		time.Sleep(2 * time.Second)
	}

	return all, nil
}
