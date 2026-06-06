// Package digestmail sends scheduled email digests (daily / weekly) to opted-in
// Pro users. Reuses the summarizer + Resend client; worker ticks every 30 min.
package digestmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

const resendAPI = "https://api.resend.com/emails"

type Worker struct {
	store        *storage.Store
	ai           ai.Summarizer
	resendAPIKey string
	from         string
	siteBase     string
	interval     time.Duration

	httpc *http.Client

	mu       sync.Mutex
	lastTick time.Time
}

func New(store *storage.Store, summarizer ai.Summarizer, resendAPIKey, siteBase string) *Worker {
	return &Worker{
		store:        store,
		ai:           summarizer,
		resendAPIKey: resendAPIKey,
		from:         "oM noM Security Feeds <noreply@omnomfeeds.com>",
		siteBase:     strings.TrimRight(siteBase, "/"),
		interval:     30 * time.Minute,
		httpc:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	w.mu.Lock()
	w.lastTick = time.Now()
	w.mu.Unlock()

	if w.resendAPIKey == "" || w.ai == nil {
		return
	}
	due, err := w.store.ListEmailDigestDue()
	if err != nil {
		log.Printf("[digestmail] list due: %v", err)
		return
	}
	if len(due) == 0 {
		return
	}

	// Generate the digest body once per tick - same content for every
	// subscriber. Avoid N LLM calls per tick.
	body, err := w.generateDigest(ctx)
	if err != nil {
		log.Printf("[digestmail] generate digest: %v", err)
		return
	}

	sent := 0
	for _, p := range due {
		if p.Email == "" {
			continue
		}
		if err := w.send(ctx, p.Email, body); err != nil {
			log.Printf("[digestmail] send to %s: %v", p.Email, err)
			continue
		}
		if err := w.store.MarkEmailDigestSent(p.UserID, time.Now()); err != nil {
			log.Printf("[digestmail] mark sent for %s: %v", p.UserID, err)
		}
		sent++
	}
	if sent > 0 {
		log.Printf("[digestmail] sent %d email digest(s)", sent)
	}
}

func (w *Worker) generateDigest(ctx context.Context) (digestBody, error) {
	// Pull the same shape of articles the in-app digest uses.
	type articleLite struct {
		ID      int64
		Title   string
		URL     string
		Source  string
		Score   int
		Tags    string
		Summary string
	}
	rows, err := w.store.DB().Query(
		`SELECT id, title, url, source, score, tags, COALESCE(summary,'')
		   FROM articles
		  WHERE fetched_at >= datetime('now', '-1 day')
		    AND duplicate_of IS NULL
		    AND score >= 5
		  ORDER BY score DESC
		  LIMIT 60`,
	)
	if err != nil {
		return digestBody{}, err
	}
	defer rows.Close()
	var arts []ai.Article
	var sourceLinks []sourceLink
	for rows.Next() {
		var a articleLite
		if err := rows.Scan(&a.ID, &a.Title, &a.URL, &a.Source, &a.Score, &a.Tags, &a.Summary); err != nil {
			return digestBody{}, err
		}
		var tags []string
		_ = json.Unmarshal([]byte(a.Tags), &tags)
		arts = append(arts, ai.Article{
			Title:   a.Title,
			Score:   a.Score,
			Tags:    tags,
			Source:  a.Source,
			Summary: a.Summary,
		})
		sourceLinks = append(sourceLinks, sourceLink{Title: a.Title, URL: a.URL, Source: a.Source, Score: a.Score})
	}
	if len(arts) == 0 {
		return digestBody{}, fmt.Errorf("no articles to summarise")
	}
	// Cap for the summarizer prompt; source-link list stays larger for the email footer.
	aiArts := arts
	if len(aiArts) > ai.MaxArticles {
		aiArts = aiArts[:ai.MaxArticles]
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	text, err := w.ai.Summarize(cctx, aiArts)
	if err != nil {
		return digestBody{}, err
	}
	// Top-15 picks by score for the link list.
	sort.SliceStable(sourceLinks, func(i, j int) bool { return sourceLinks[i].Score > sourceLinks[j].Score })
	if len(sourceLinks) > 15 {
		sourceLinks = sourceLinks[:15]
	}
	return digestBody{Brief: text, Picks: sourceLinks, Generated: time.Now()}, nil
}

type sourceLink struct {
	Title  string
	URL    string
	Source string
	Score  int
}

type digestBody struct {
	Brief     string
	Picks     []sourceLink
	Generated time.Time
}

// SendNow generates a fresh digest and emails it to a single recipient,
// bypassing the cooldown / opt-in checks the periodic tick uses. Returns
// a hard error if the worker isn't fully configured (Resend / summarizer) or
// any step fails. Used by the admin "send test" endpoint.
func (w *Worker) SendNow(ctx context.Context, to string) error {
	if w.resendAPIKey == "" {
		return errors.New("RESEND_API_KEY not configured")
	}
	if w.ai == nil {
		return errors.New("summarizer provider not configured")
	}
	body, err := w.generateDigest(ctx)
	if err != nil {
		return err
	}
	return w.send(ctx, to, body)
}

func (w *Worker) send(ctx context.Context, to string, body digestBody) error {
	subject := "[oM noM] daily security digest - " + body.Generated.Format("2006-01-02")
	textBody := body.Brief + "\n\n--\n\nTop picks (last 24h):\n\n"
	for i, p := range body.Picks {
		textBody += fmt.Sprintf("%d. [%02d] %s\n   %s\n   %s\n\n", i+1, p.Score, p.Title, p.Source, p.URL)
	}
	textBody += "Manage your digest schedule at " + w.siteBase + "/app (Config (c) → Profile)\n"

	htmlBody := buildHTMLBody(body, w.siteBase)

	payload, _ := json.Marshal(map[string]any{
		"from":    w.from,
		"to":      []string{to},
		"subject": subject,
		"text":    textBody,
		"html":    htmlBody,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", resendAPI, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.resendAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("resend: status %d :: %s", resp.StatusCode, string(b))
	}
	return nil
}

func buildHTMLBody(body digestBody, siteBase string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#15171c;color:#e9ebf0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:15px;line-height:1.65;">`)
	b.WriteString(`<table cellpadding="0" cellspacing="0" border="0" style="max-width:640px;margin:0 auto;">`)
	b.WriteString(`<tr><td style="padding:0 0 18px;font-family:'JetBrains Mono',monospace;color:#2dd49c;font-size:13px;letter-spacing:0.6px;">~~~_o) oM noM Security Feeds</td></tr>`)
	b.WriteString(`<tr><td style="padding:0 0 8px;color:#ffffff;font-size:20px;font-weight:600;">Daily intel brief - ` + body.Generated.Format("Mon, Jan 2 2006") + `</td></tr>`)
	b.WriteString(`<tr><td style="padding:0 0 22px;color:#e9ebf0;white-space:pre-wrap;">` + escapeHTML(body.Brief) + `</td></tr>`)
	b.WriteString(`<tr><td style="padding:14px 0 6px;color:#56d3e0;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.6px;border-top:1px solid #2b3039;text-transform:uppercase;">// top picks</td></tr>`)
	for i, p := range body.Picks {
		b.WriteString(fmt.Sprintf(`<tr><td style="padding:8px 0;border-bottom:1px solid #2b3039;"><div style="font-size:11px;color:#b8c4d4;font-family:'JetBrains Mono',monospace;">%d &middot; score %02d &middot; %s</div><a href="%s" style="color:#56d3e0;text-decoration:none;font-weight:600;">%s</a></td></tr>`,
			i+1, p.Score, escapeHTML(p.Source), escapeHTML(p.URL), escapeHTML(p.Title)))
	}
	b.WriteString(`<tr><td style="padding:22px 0 0;color:#b8c4d4;font-size:11px;font-family:'JetBrains Mono',monospace;">manage your digest schedule at <a href="` + siteBase + `/app" style="color:#56d3e0;">` + siteBase + `/app</a> (Config (c) → Profile)</td></tr>`)
	b.WriteString(`</table></body></html>`)
	return b.String()
}

func escapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}
