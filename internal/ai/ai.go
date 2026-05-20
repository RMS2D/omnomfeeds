// Package ai provides the BYOK digest. Backends implement Summarizer.
package ai

import (
	"context"
	"fmt"
	"strings"
)

// Article is the per-item payload the prompt builder consumes.
type Article struct {
	Title   string
	Score   int
	Tags    []string
	Source  string
	Summary string
}

// Summarizer is the provider-agnostic interface.
type Summarizer interface {
	Summarize(ctx context.Context, articles []Article) (string, error)
	Name() string // e.g. "anthropic:claude-haiku-4-5"
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
