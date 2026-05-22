// Package alerts is the Pro webhook-fire worker. SSRF-guarded, HTTPS-only,
// short timeout, alert_fires dedup table for restart idempotency.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Worker holds the dependencies the alert loop needs.
type Worker struct {
	store    *storage.Store
	httpc    *http.Client
	interval time.Duration
	// lookbackOverlap is how far back the worker reaches each tick beyond
	// the previous tick's cutoff. Generous so we don't miss articles
	// fetched during a restart.
	lookbackOverlap time.Duration
	// siteBase is the public URL used when building "open in app" links
	// inside webhook payloads.
	siteBase string

	mu   sync.Mutex
	last time.Time
}

// New returns a Worker with sensible defaults. siteBase is the public root
// (e.g. "https://omnomfeeds.com") for building deep links in payloads.
func New(store *storage.Store, siteBase string) *Worker {
	return &Worker{
		store:           store,
		httpc:           newSSRFGuardedClient(),
		interval:        60 * time.Second,
		lookbackOverlap: 10 * time.Minute,
		siteBase:        strings.TrimRight(siteBase, "/"),
	}
}

// newSSRFGuardedClient validates resolved IPs at socket-open time and on
// every redirect to close the DNS-rebinding window.
func newSSRFGuardedClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			// Reject the dial if ANY resolved IP is on the blocklist.
			for _, ip := range ips {
				if isForbiddenIP(ip) {
					return nil, fmt.Errorf("webhook dial blocked: %s resolves to disallowed address %s", host, ip.String())
				}
			}
			// Connect directly to the validated IP so the dialer can't re-resolve.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Re-validate each redirect's host; http.Client resolves the target itself.
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			host := req.URL.Hostname()
			if host == "" {
				return errors.New("redirect URL missing host")
			}
			ips, err := net.DefaultResolver.LookupIP(req.Context(), "ip", host)
			if err != nil {
				// DNS failure on redirect = fail closed.
				return fmt.Errorf("redirect blocked: dns lookup for %s failed: %w", host, err)
			}
			for _, ip := range ips {
				if isForbiddenIP(ip) {
					return fmt.Errorf("redirect blocked: %s resolves to %s", host, ip.String())
				}
			}
			return nil
		},
	}
}

// isForbiddenIP rejects loopback, RFC1918, link-local (incl. 169.254.169.254), multicast, unspecified.
func isForbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// Run blocks until ctx is cancelled, ticking once per interval. Should be
// launched as `go worker.Run(ctx)` from main.
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
	cutoff := w.last
	w.mu.Unlock()
	if cutoff.IsZero() {
		cutoff = time.Now().Add(-w.lookbackOverlap)
	} else {
		cutoff = cutoff.Add(-w.lookbackOverlap)
	}

	rules, err := w.store.ListEnabledAlertRules()
	if err != nil {
		log.Printf("[alerts] list rules: %v", err)
		return
	}
	if len(rules) == 0 {
		w.mu.Lock()
		w.last = time.Now()
		w.mu.Unlock()
		return
	}

	articles, err := w.store.ArticlesForAlerts(cutoff)
	if err != nil {
		log.Printf("[alerts] list articles since %s: %v", cutoff.Format(time.RFC3339), err)
		return
	}
	if len(articles) == 0 {
		w.mu.Lock()
		w.last = time.Now()
		w.mu.Unlock()
		return
	}

	fires := 0
	for ri := range rules {
		r := &rules[ri]
		for ai := range articles {
			a := &articles[ai]
			if !storage.ArticleMatchesRule(a, r) {
				continue
			}
			already, err := w.store.AlreadyFired(r.ID, int64(a.ID))
			if err != nil {
				log.Printf("[alerts] dedup check rule=%s article=%d: %v", r.ID, a.ID, err)
				continue
			}
			if already {
				continue
			}
			if err := w.send(ctx, r, a); err != nil {
				log.Printf("[alerts] send rule=%s article=%d: %v", r.ID, a.ID, err)
				continue
			}
			if err := w.store.RecordFire(r.ID, int64(a.ID)); err != nil {
				log.Printf("[alerts] record fire rule=%s article=%d: %v", r.ID, a.ID, err)
			}
			fires++
		}
	}
	if fires > 0 {
		log.Printf("[alerts] fired %d webhook(s) across %d rule(s) / %d article(s)", fires, len(rules), len(articles))
	}

	w.mu.Lock()
	w.last = time.Now()
	w.mu.Unlock()
}

// SendTest fires a synthetic alert at the given webhook URL using the
// channel-appropriate formatter. Used by admins to validate webhook
// delivery end-to-end without waiting for a real KEV publish.
func (w *Worker) SendTest(ctx context.Context, channel, target, kind string) error {
	if kind == "" {
		kind = "kev"
	}
	a := &models.Article{
		ID:          0,
		Title:       fmt.Sprintf("[TEST] CVE-2026-00001 - sample %s alert from oM noM admin", strings.ToUpper(kind)),
		URL:         w.siteBase + "/",
		Source:      "test",
		Score:       50,
		Summary:     "Synthetic webhook fired from /admin to validate the alert pipeline. Real alerts will look like this with the real article title and URL.",
		PublishedAt: time.Now(),
	}
	r := &storage.AlertRule{
		ID:            "admin-test",
		Kind:          kind,
		Pattern:       "admin test",
		Channel:       channel,
		ChannelTarget: target,
	}
	return w.send(ctx, r, a)
}

// send dispatches one alert with channel-appropriate body formatting.
func (w *Worker) send(ctx context.Context, r *storage.AlertRule, a *models.Article) error {
	if err := validateWebhookURL(r.ChannelTarget); err != nil {
		return err
	}
	var body []byte
	switch r.Channel {
	case "slack":
		body = formatSlack(r, a, w.siteBase)
	case "discord":
		body = formatDiscord(r, a, w.siteBase)
	default:
		body = formatGeneric(r, a, w.siteBase)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.ChannelTarget, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1 (+https://omnomfeeds.com)")
	resp, err := w.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// validateWebhookURL is the pre-flight UX check. Real SSRF defense
// is in newSSRFGuardedClient's DialContext + CheckRedirect.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return errors.New("webhook URL required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return errors.New("webhook URL must be https")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("webhook URL missing host")
	}
	// If the user typed an IP literal directly, check it. We don't do
	// LookupIP here because DNS failures shouldn't block a save and the
	// dial-time guard owns the live check.
	if ip := net.ParseIP(host); ip != nil && isForbiddenIP(ip) {
		return fmt.Errorf("webhook URL points at disallowed address %s", ip.String())
	}
	return nil
}

// --- formatters ---

func ruleLabel(r *storage.AlertRule) string {
	switch r.Kind {
	case "kev":
		return "KEV"
	case "keyword":
		return "Saved alert"
	case "cve":
		return "CVE alert"
	case "tag":
		return "Tag alert"
	default:
		return r.Kind
	}
}

func ruleSubtitle(r *storage.AlertRule) string {
	if r.Kind == "kev" {
		return "CISA KEV catalog addition"
	}
	if r.Pattern != "" {
		return r.Kind + " match: " + r.Pattern
	}
	return r.Kind
}

func formatSlack(r *storage.AlertRule, a *models.Article, base string) []byte {
	// Slack incoming-webhook payload. Block Kit gives us a clean two-line
	// presentation: bolded title with a labeled tag, then the URL.
	deepLink := base + "/app?search=" + url.QueryEscape(a.Title)
	body := map[string]any{
		"text": fmt.Sprintf("[%s] %s", strings.ToUpper(ruleLabel(r)), a.Title),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*[%s]* %s\n_%s_", ruleLabel(r), a.Title, ruleSubtitle(r)),
				},
			},
			{
				"type": "context",
				"elements": []map[string]any{
					{"type": "mrkdwn", "text": fmt.Sprintf("<%s|source> · <%s|open in feed> · score %d", a.URL, deepLink, a.Score)},
				},
			},
		},
	}
	out, _ := json.Marshal(body)
	return out
}

func formatDiscord(r *storage.AlertRule, a *models.Article, base string) []byte {
	deepLink := base + "/app?search=" + url.QueryEscape(a.Title)
	body := map[string]any{
		"username":   "oM noM Feeds",
		"avatar_url": base + "/favicon.ico",
		"content":    fmt.Sprintf("**[%s]** %s", ruleLabel(r), a.Title),
		"embeds": []map[string]any{
			{
				"title":       a.Title,
				"url":         a.URL,
				"description": truncate(a.Summary, 280) + fmt.Sprintf("\n\n[open in feed](%s) · score %d", deepLink, a.Score),
				"color":       3893160, // accent green in decimal
				"footer":      map[string]any{"text": ruleSubtitle(r)},
			},
		},
	}
	out, _ := json.Marshal(body)
	return out
}

func formatGeneric(r *storage.AlertRule, a *models.Article, base string) []byte {
	body := map[string]any{
		"event":   "alert",
		"rule": map[string]any{
			"id":      r.ID,
			"kind":    r.Kind,
			"pattern": r.Pattern,
		},
		"article": map[string]any{
			"id":           a.ID,
			"title":        a.Title,
			"url":          a.URL,
			"source":       a.Source,
			"source_type":  a.SourceType,
			"summary":      a.Summary,
			"score":        a.Score,
			"tags":         a.Tags,
			"published_at": a.PublishedAt.Format(time.RFC3339),
			"deep_link":    base + "/app?search=" + url.QueryEscape(a.Title),
		},
	}
	out, _ := json.Marshal(body)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "..."
}
