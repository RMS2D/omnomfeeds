// Package ai provides the BYOK digest. Backends implement Summarizer.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// jsonUnmarshal is the underlying parser; kept in this file so the shim
// stays a one-liner.
func jsonUnmarshal(s string, dst any) error { return json.Unmarshal([]byte(s), dst) }

// Article is the per-item payload the prompt builder consumes.
type Article struct {
	Title   string
	Score   int
	Tags    []string
	Source  string
	Summary string
}

// CVEDetail is the payload sent to ExplainCVE. The model gets the
// authoritative description + CVSS + EPSS + KEV status and writes a
// 3-bullet plain-English summary scoped to "what is it / who's affected /
// what to do."
type CVEDetail struct {
	ID             string
	Description    string
	CVSSScore      float64
	CVSSSeverity   string
	EPSSScore      float64 // 0..1
	EPSSPercentile float64
	KEV            bool
	CWE            string
}

// ClusterItem is the slim per-article payload sent to ClusterArticles.
// id is the article's int64 PK; the LLM reads title + brief summary and
// returns groups referencing the same ids.
type ClusterItem struct {
	ID      int64
	Title   string
	Summary string
}

// ClusterGroup is one set of semantic duplicates the LLM produced. Primary
// is the id of the article the others should reference via duplicate_of.
type ClusterGroup struct {
	Primary int64
	Dupes   []int64
}

// Summarizer is the provider-agnostic interface.
type Summarizer interface {
	Summarize(ctx context.Context, articles []Article) (string, error)
	ExplainCVE(ctx context.Context, cve CVEDetail) (string, error)
	ExplainArticle(ctx context.Context, a Article) (string, error)
	TriageArticle(ctx context.Context, a Article) (string, error)
	ClusterArticles(ctx context.Context, items []ClusterItem) ([]ClusterGroup, error)
	RankForProfile(ctx context.Context, profile string, items []ClusterItem) ([]int64, error)
	Name() string // e.g. "anthropic:claude-haiku-4-5"
}

// BuildRankPrompt asks the model to re-sort articles by relevance to a
// short user-supplied profile description. Output is a JSON array of ids
// in descending relevance.
func BuildRankPrompt(profile string, items []ClusterItem) string {
	var b strings.Builder
	for _, it := range items {
		title := strings.ReplaceAll(it.Title, "\n", " ")
		if len(title) > 180 {
			title = title[:180] + "..."
		}
		summary := strings.ReplaceAll(it.Summary, "\n", " ")
		if len(summary) > 180 {
			summary = summary[:180] + "..."
		}
		fmt.Fprintf(&b, "%d: %s\n   %s\n", it.ID, title, summary)
	}
	prof := strings.TrimSpace(profile)
	if len(prof) > 500 {
		prof = prof[:500] + "..."
	}
	return `You are re-sorting a security news feed for one specific reader.

Reader profile:
` + prof + `

Articles below have an id, title, and short summary. Sort them by
relevance to the reader, MOST RELEVANT FIRST. Use the profile to weigh
each item; tie-break by general security significance.

Return ONLY a JSON array of ids in your chosen order. No prose, no
markdown. Example shape:

[1234, 5678, 9012]

Include every id exactly once. If you genuinely can't tell, append the
unsure ones at the end in any order.

Articles:

` + b.String()
}

// ParseRankResponse extracts the ids array from a personalization
// response. Same fence/extraction strategy as ParseClusterResponse.
func ParseRankResponse(s string) ([]int64, error) {
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no json array in response")
	}
	js := s[start : end+1]
	var ids []int64
	if err := jsonUnmarshalShim(js, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// BuildClusterPrompt asks the model to group articles that describe the
// same underlying incident. Output is a strict JSON array; we parse it
// with encoding/json. Anything we can't parse is treated as "no clusters
// this batch."
func BuildClusterPrompt(items []ClusterItem) string {
	var b strings.Builder
	for _, it := range items {
		title := strings.ReplaceAll(it.Title, "\n", " ")
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		summary := strings.ReplaceAll(it.Summary, "\n", " ")
		if len(summary) > 240 {
			summary = summary[:240] + "..."
		}
		fmt.Fprintf(&b, "%d: %s\n   %s\n", it.ID, title, summary)
	}
	return `You are deduping security news articles. The list below has
articles that may describe the same incident from multiple sources. Group
articles together ONLY when they're clearly about the same event - same
CVE, same campaign, same disclosure, same incident.

When grouping:
- Pick the article id with the most informative title as the "primary".
- List all other ids in the group as "dupes" of that primary.
- Articles about the same TOPIC but DIFFERENT incidents stay separate.
- A single-article group (no real dupes found) should NOT be included.
- If you're unsure, do not group.

Return ONLY a JSON array. No prose, no markdown. The shape is:

[{"primary": 1234, "dupes": [5678, 9012]}, {"primary": 4567, "dupes": [8901]}]

If there are no duplicates in the batch, return: []

Articles:

` + b.String()
}

// ParseClusterResponse pulls the JSON array out of an LLM response. Models
// sometimes wrap output in code fences or chatter; we extract the first
// JSON array we find and decode it.
func ParseClusterResponse(s string) ([]ClusterGroup, error) {
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no json array in response")
	}
	js := s[start : end+1]
	var raw []struct {
		Primary int64   `json:"primary"`
		Dupes   []int64 `json:"dupes"`
	}
	if err := jsonUnmarshalShim(js, &raw); err != nil {
		return nil, err
	}
	out := make([]ClusterGroup, 0, len(raw))
	for _, g := range raw {
		if g.Primary == 0 || len(g.Dupes) == 0 {
			continue
		}
		out = append(out, ClusterGroup{Primary: g.Primary, Dupes: g.Dupes})
	}
	return out, nil
}

// jsonUnmarshalShim lets ParseClusterResponse stay decoupled from the
// encoding/json import in callers that may want to mock it.
func jsonUnmarshalShim(s string, dst any) error {
	return jsonUnmarshal(s, dst)
}

// BuildArticlePrompt is the "explain this one article" prompt. Output is
// 2-3 plain-text lines: bug class / who's affected / what to do.
func BuildArticlePrompt(a Article) string {
	title := strings.ReplaceAll(a.Title, "\n", " ")
	if len(title) > 240 {
		title = title[:240] + "..."
	}
	summary := strings.ReplaceAll(a.Summary, "\n", " ")
	if len(summary) > 1600 {
		summary = summary[:1600] + "..."
	}
	tags := strings.Join(a.Tags, ", ")
	if len(tags) > 200 {
		tags = tags[:200] + "..."
	}
	return `You are a security engineer briefing a colleague. Read the
article below and write 2-3 short plain-text lines summarising:

1. What this is (one short sentence: the actual security thing - bug class,
   tool, campaign, technique, advisory, etc).
2. Who needs to care (the audience or environment that should pay attention).
3. What to do today (action, mitigation, reading, or "no action needed,
   awareness only").

Constraints:
- 2 to 3 lines total. Each line a sentence. No bullet syntax. No markdown.
- No em-dashes anywhere. Use " - " or ". " or ":" as separators.
- Under 70 words total.
- If the article is too thin (e.g. a link with no useful summary), say so
  honestly in one line rather than guessing.

Article data:

Title: ` + title + `
Source: ` + a.Source + `
Score: ` + fmt.Sprintf("%d", a.Score) + `
Tags: ` + tags + `
Summary: ` + summary
}

// BuildTriagePrompt produces the inline "what? so what?" one-liner shown
// next to each Pro article in the list view. Single sentence, terse.
// Optimised for skimming - the reader should know in 5 seconds whether
// to click the article.
func BuildTriagePrompt(a Article) string {
	title := strings.ReplaceAll(a.Title, "\n", " ")
	if len(title) > 200 {
		title = title[:200] + "..."
	}
	summary := strings.ReplaceAll(a.Summary, "\n", " ")
	if len(summary) > 800 {
		summary = summary[:800] + "..."
	}
	tags := strings.Join(a.Tags, ", ")
	if len(tags) > 160 {
		tags = tags[:160] + "..."
	}
	return `You are a triage editor for a security news reader. Read the
article and write ONE short plain-text sentence (under 22 words) that
tells the reader why this matters or doesn't matter - the "what? so
what?" line they'd see in a SOC stand-up.

Constraints:
- ONE sentence. Under 22 words. No bullets, no markdown, no quotes.
- No em-dashes. Use commas or "; " as separators.
- Start with the substance, not "This article..." or "The post...".
- If the article is too thin to triage (e.g. a link with no useful body),
  reply exactly: thin context. open to assess.

Article data:

Title: ` + title + `
Source: ` + a.Source + `
Tags: ` + tags + `
Summary: ` + summary
}

// BuildCVEPrompt produces the deep-dive instruction. Plain text out, no
// markdown so the frontend can render it line-by-line with the rest of
// the dark-theme styling.
func BuildCVEPrompt(c CVEDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CVE: %s\n", c.ID)
	if c.Description != "" {
		d := c.Description
		if len(d) > 1200 {
			d = d[:1200] + "..."
		}
		fmt.Fprintf(&b, "NVD description: %s\n", d)
	}
	if c.CVSSScore > 0 {
		fmt.Fprintf(&b, "CVSS v3 score: %.1f (%s)\n", c.CVSSScore, c.CVSSSeverity)
	}
	if c.EPSSScore > 0 {
		fmt.Fprintf(&b, "EPSS: %.1f%% (%.0fth percentile)\n", c.EPSSScore*100, c.EPSSPercentile*100)
	}
	if c.KEV {
		fmt.Fprintf(&b, "CISA KEV: yes (actively exploited per CISA's Known Exploited Vulnerabilities catalog)\n")
	}
	if c.CWE != "" {
		fmt.Fprintf(&b, "Weakness: %s\n", c.CWE)
	}

	return `You are a security engineer briefing a colleague. Read the
data below and write exactly three bullets, in this order:

1. What it is (one short sentence: the affected product / component +
   the bug class - e.g. heap overflow, auth bypass, RCE).
2. Who needs to care (deployments / surfaces / preconditions that have
   to be true for this to bite). Be concrete.
3. What to do today (patch reference if available, mitigation if not,
   detection hint if relevant).

Constraints:
- Three bullets. No more, no less. Use "- " as the bullet prefix.
- Plain text. No markdown headers, no bold, no asterisks.
- No em-dashes anywhere. Use " - " or ". " as separators.
- Total under 110 words.
- If the data is too thin to write a useful bullet, say so honestly
  in that bullet rather than guessing.

Data:

` + b.String()
}

// MaxArticles caps how many items we send to the model.
const MaxArticles = 40

// DefaultFocus when AIConfig.Focus is empty.
const DefaultFocus = "general cybersecurity (vulnerability research, threat intel, " +
	"cloud + web + endpoint + mobile security, identity, supply chain)"

// BuildPrompt builds the digest instruction + compact article list for the model.
func BuildPrompt(articles []Article, focus string) string {
	if len(articles) > MaxArticles {
		articles = articles[:MaxArticles]
	}
	if strings.TrimSpace(focus) == "" {
		focus = DefaultFocus
	}
	var b strings.Builder
	for _, a := range articles {
		tags := strings.Join(a.Tags, ", ")
		if len(tags) > 140 {
			tags = tags[:140] + "..."
		}
		title := strings.ReplaceAll(a.Title, "\n", " ")
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		fmt.Fprintf(&b, "- [score %02d] %s\n  source: %s\n  tags: %s\n", a.Score, title, a.Source, tags)
	}

	return `You are a security analyst writing a daily intel brief for a reader
whose focus is: ` + focus + `.

Below are the top ` + fmt.Sprintf("%d", len(articles)) + ` security articles from the last 24 hours,
sorted by relevance score:

` + b.String() + `

Write an intel brief that:

1. Opens with any KEV-listed (actively-exploited) CVEs - these are the most urgent.
2. Groups related items - same CVE, same threat actor, same campaign, same technique family.
3. Calls out new techniques, PoCs, tooling, or research worth reading today.
4. Covers the full spread of what landed: web, cloud, mobile, identity, endpoint,
   supply chain, threat intel. Do not over-index on any single domain unless
   that is where most of today's signal actually is.
5. Ends with 3 to 5 specific TODO items the reader should investigate today.

Constraints:

- Plain text only. No markdown headers. No bullet syntax with asterisks. No bold/italic.
- No em-dashes anywhere. Use " - " or ". " or ": " as separators instead.
- No "I" / "we" voice. Write as a brief, not a personal note.
- Around 300-450 words total.
- If two items are about the same CVE or actor, mention each only once.`
}
