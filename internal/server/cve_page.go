package server

import (
	"context"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/analytics"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// cvePageCache stores rendered HTML per CVE ID. The page combines NVD,
// EPSS, KEV, OTX, source consensus, timeline, and the article list. The
// build cost is dominated by the NVD round-trip (cold ~200ms, cached
// instant) plus our own article scan; we cache for 30 minutes so a
// trending CVE doesn't repeatedly hit NVD as it gets shared.
type cvePageCacheEntry struct {
	body   []byte
	expiry time.Time
	status int
}

var (
	cvePageMu    sync.Mutex
	cvePageCache = map[string]cvePageCacheEntry{}
)

const cvePageCacheTTL = 30 * time.Minute

// cveIDPattern accepts CVE-YYYY-NNNN+ format (year + at least 4 digits).
// Case is normalised to upper internally.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// handleCVEPage serves the public per-CVE landing page at /cve/{id}.
// Server-side rendered so Google indexes the actual content. Path takes
// CVE IDs in any case; we normalise to upper and redirect lower-case
// requests to the canonical form (case-insensitive but consistent URL).
func (s *Server) handleCVEPage(w http.ResponseWriter, r *http.Request, webFS fs.FS) {
	raw := strings.TrimPrefix(r.URL.Path, "/cve/")
	raw = strings.Trim(raw, "/")
	if raw == "" {
		// Bare /cve/ - redirect to /trending which is the closest sibling.
		http.Redirect(w, r, "/trending", http.StatusSeeOther)
		return
	}
	upper := strings.ToUpper(raw)
	if !cveIDPattern.MatchString(upper) {
		serveNotFound(w, r, webFS)
		return
	}
	if upper != raw {
		// Canonicalise case so we don't fragment cache + Google index by case.
		http.Redirect(w, r, "/cve/"+upper, http.StatusMovedPermanently)
		return
	}

	cvePageMu.Lock()
	if e, ok := cvePageCache[upper]; ok && time.Now().Before(e.expiry) {
		body := e.body
		status := e.status
		cvePageMu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=600")
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		w.Write(body)
		return
	}
	cvePageMu.Unlock()

	body, status := s.renderCVEPage(r.Context(), upper)
	cvePageMu.Lock()
	cvePageCache[upper] = cvePageCacheEntry{body: body, status: status, expiry: time.Now().Add(cvePageCacheTTL)}
	cvePageMu.Unlock()

	s.emit(w, r, analytics.EvPageView, "/cve/"+upper, nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.WriteHeader(status)
	w.Write(body)
}

// renderCVEPage builds the HTML for one CVE. Returns the body + the
// HTTP status it should be served with (404 when we have no data at all,
// 200 otherwise). Fans the 4 expensive fetches out to goroutines (NVD,
// OTX, and three storage queries) so cold renders are bounded by the
// slowest single call rather than their sum.
func (s *Server) renderCVEPage(ctx context.Context, id string) ([]byte, int) {
	type nvdResult struct {
		desc, cwe, published, lastMod string
		cvssScore                     float64
		cvssSev, cvssVec              string
		found                         bool
	}
	type otxResult struct {
		pulses, recent int
		found          bool
	}

	var nvd nvdResult
	var otx otxResult
	var consensusRaw []storage.CVEConsensusRow
	var timelineRaw []storage.CVETimelineEvent
	var articlesRaw []models.Article

	var wg sync.WaitGroup

	// NVD - the slowest external call; cap at 10s.
	if s.enrich != nil && s.enrich.NVD != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nvdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if d, err := s.enrich.NVD.Get(nvdCtx, id); err == nil {
				nvd.desc = d.Description
				nvd.cvssScore = d.CVSSv3Score
				nvd.cvssSev = d.CVSSv3Severity
				nvd.cvssVec = d.CVSSv3Vector
				nvd.cwe = d.CWE
				nvd.published = d.Published
				nvd.lastMod = d.LastModified
				nvd.found = true
			}
		}()
	}

	// OTX - best-effort; cap at 5s (was 8, but OTX caches aggressively
	// upstream so this is enough for the cold case).
	if s.enrich != nil && s.enrich.OTX != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			otxCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if o, err := s.enrich.OTX.Get(otxCtx, id); err == nil && o != nil {
				otx.pulses = o.PulseCount
				otx.recent = o.RecentCount
				otx.found = true
			}
		}()
	}

	// Three local storage queries in parallel.
	wg.Add(3)
	go func() { defer wg.Done(); consensusRaw, _ = s.store.CVEConsensus(id, 90) }()
	go func() { defer wg.Done(); timelineRaw, _ = s.store.CVETimeline(id) }()
	go func() { defer wg.Done(); articlesRaw, _ = s.store.ArticlesForCVE(id, 50) }()

	// EPSS + KEV are local-only lookups; they're cheap enough that the
	// goroutine overhead would dominate.
	var epssScore, epssPct float64
	var hasEPSS bool
	if s.enrich != nil && s.enrich.EPSS != nil {
		if e := s.enrich.EPSS.Get(id); e != nil {
			epssScore = e.Score
			epssPct = e.Percentile
			hasEPSS = true
		}
	}
	isKEV := s.scorer != nil && s.scorer.IsKEV(id)

	wg.Wait()

	// If neither NVD nor our own corpus knows about this CVE, surface a
	// 404 with the themed not-found page rather than render an empty
	// shell. Search engines will treat this as "page not found" too.
	if !nvd.found && len(articlesRaw) == 0 {
		return s.renderCVENotFound(id), http.StatusNotFound
	}

	// Convert storage types to the renderer's local types so the renderer
	// doesn't import the storage / models packages.
	consensus := make([]consensusRowMin, 0, len(consensusRaw))
	for _, c := range consensusRaw {
		consensus = append(consensus, consensusRowMin{Source: c.Source, Count: c.Count})
	}
	timeline := make([]timelineEventMin, 0, len(timelineRaw))
	for _, e := range timelineRaw {
		timeline = append(timeline, timelineEventMin{At: e.At.UTC().Format(time.RFC3339), Label: e.Label})
	}
	articles := make([]articleMin, 0, len(articlesRaw))
	for _, a := range articlesRaw {
		articles = append(articles, articleMin{Title: a.Title, URL: a.URL, Source: a.Source, PublishedAt: a.PublishedAt})
	}

	return s.renderCVEPageHTML(id, nvd, otx, epssScore, epssPct, hasEPSS, isKEV, consensus, timeline, articles), http.StatusOK
}

func (s *Server) renderCVENotFound(id string) []byte {
	var b strings.Builder
	writeCVEHead(&b, id, "No data on this CVE - oM noM Security Feeds", "We don't have NVD data or any article mentions for "+id+". It may not exist, or it may be too new for our index.")
	b.WriteString(`<div class="wrap"><div class="hero"><div class="eyebrow">:: not found ::</div><h1>`)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`</h1><p class="lead">We don't have NVD metadata or any article mentions for this CVE-ID. It may be brand-new, mistyped, or outside our index. <a href="/trending">See trending CVEs</a> instead.</p></div></div>`)
	writeCVEFoot(&b)
	return []byte(b.String())
}

func (s *Server) renderCVEPageHTML(
	id string,
	nvd struct {
		desc, cwe, published, lastMod string
		cvssScore                     float64
		cvssSev, cvssVec              string
		found                         bool
	},
	otx struct {
		pulses, recent int
		found          bool
	},
	epssScore, epssPct float64,
	hasEPSS, isKEV bool,
	consensus []consensusRowMin,
	timeline []timelineEventMin,
	articles []articleMin,
) []byte {
	var b strings.Builder

	// Title + meta description: optimised for search-engine snippets.
	title := id + " - "
	if isKEV {
		title += "Actively Exploited (CISA KEV)"
	} else if hasEPSS && epssPct >= 0.5 {
		title += fmt.Sprintf("EPSS %s percentile", fmtPct(epssPct))
	} else {
		title += "Vulnerability context"
	}
	title += " - oM noM Security Feeds"

	metaDesc := id + ". "
	if nvd.cvssSev != "" && nvd.cvssScore > 0 {
		metaDesc += fmt.Sprintf("CVSS %.1f (%s). ", nvd.cvssScore, nvd.cvssSev)
	}
	if isKEV {
		metaDesc += "In CISA KEV - actively exploited. "
	}
	if hasEPSS {
		metaDesc += "EPSS " + fmtPct(epssPct) + ". "
	}
	if len(articles) > 0 {
		metaDesc += fmt.Sprintf("%d source mentions tracked.", len(articles))
	}

	writeCVEHead(&b, id, title, metaDesc)

	b.WriteString(`<div class="wrap"><div class="hero"><div class="eyebrow">:: vulnerability context ::</div><h1>`)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`</h1>`)

	// Chip strip: KEV, CVSS, EPSS, CWE, OTX.
	b.WriteString(`<div class="chips">`)
	if isKEV {
		b.WriteString(`<span class="chip kev" title="In the CISA Known Exploited Vulnerabilities catalog">CISA KEV - actively exploited</span>`)
	}
	if nvd.cvssScore > 0 {
		sev := strings.ToUpper(nvd.cvssSev)
		cls := "med"
		if nvd.cvssScore >= 9 {
			cls = "crit"
		} else if nvd.cvssScore >= 7 {
			cls = "high"
		} else if nvd.cvssScore < 4 {
			cls = "low"
		}
		fmt.Fprintf(&b, `<span class="chip cvss %s">CVSS %.1f %s</span>`, cls, nvd.cvssScore, html.EscapeString(sev))
	}
	if hasEPSS {
		cls := "epss"
		if epssPct >= 0.9 {
			cls = "epss hot"
		} else if epssPct >= 0.5 {
			cls = "epss warn"
		}
		fmt.Fprintf(&b, `<span class="chip %s" title="EPSS exploit prediction percentile">EPSS %s</span>`, cls, html.EscapeString(fmtPct(epssPct)))
	}
	if nvd.cwe != "" {
		fmt.Fprintf(&b, `<span class="chip cwe">%s</span>`, html.EscapeString(nvd.cwe))
	}
	if otx.found && otx.pulses > 0 {
		fmt.Fprintf(&b, `<span class="chip otx" title="AlienVault OTX threat-intel pulses">OTX %d pulse%s</span>`, otx.pulses, plural(otx.pulses))
	}
	b.WriteString(`</div>`)

	// NVD description block.
	if nvd.desc != "" {
		b.WriteString(`<p class="lead">`)
		desc := nvd.desc
		if len(desc) > 800 {
			desc = desc[:800] + "..."
		}
		b.WriteString(html.EscapeString(desc))
		b.WriteString(`</p>`)
	}
	if nvd.published != "" || nvd.lastMod != "" {
		b.WriteString(`<div class="meta-line">`)
		if nvd.published != "" {
			b.WriteString(`Published <strong>`)
			b.WriteString(html.EscapeString(shortDate(nvd.published)))
			b.WriteString(`</strong>`)
		}
		if nvd.lastMod != "" && nvd.lastMod != nvd.published {
			b.WriteString(` &middot; last modified <strong>`)
			b.WriteString(html.EscapeString(shortDate(nvd.lastMod)))
			b.WriteString(`</strong>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)

	// Two-column grid: details on left, articles on right.
	b.WriteString(`<div class="grid">`)

	// Details panel.
	b.WriteString(`<section class="panel"><h2>:: details ::</h2><dl class="kv">`)
	if isKEV {
		b.WriteString(`<dt>CISA KEV status</dt><dd class="hot">In catalog - actively exploited</dd>`)
	} else {
		b.WriteString(`<dt>CISA KEV status</dt><dd class="dim">Not in catalog</dd>`)
	}
	if nvd.cvssScore > 0 {
		fmt.Fprintf(&b, `<dt>CVSS v3</dt><dd>%.1f / %s</dd>`, nvd.cvssScore, html.EscapeString(nvd.cvssSev))
	}
	if nvd.cvssVec != "" {
		fmt.Fprintf(&b, `<dt>CVSS vector</dt><dd class="mono">%s</dd>`, html.EscapeString(nvd.cvssVec))
	}
	if hasEPSS {
		fmt.Fprintf(&b, `<dt>EPSS</dt><dd>%s percentile (score %.4f)</dd>`, html.EscapeString(fmtPct(epssPct)), epssScore)
	}
	if nvd.cwe != "" {
		fmt.Fprintf(&b, `<dt>CWE</dt><dd>%s</dd>`, html.EscapeString(nvd.cwe))
	}
	if otx.found {
		fmt.Fprintf(&b, `<dt>OTX pulses</dt><dd>%d total, %d recent</dd>`, otx.pulses, otx.recent)
	}
	b.WriteString(`</dl>`)
	b.WriteString(`<div class="ext-links"><a href="https://nvd.nist.gov/vuln/detail/`)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`" target="_blank" rel="noopener">View on NVD &rarr;</a> &middot; <a href="https://www.cve.org/CVERecord?id=`)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`" target="_blank" rel="noopener">cve.org</a></div></section>`)

	// Timeline.
	if len(timeline) > 0 {
		b.WriteString(`<section class="panel"><h2>:: timeline ::</h2><ul class="timeline">`)
		for _, e := range timeline {
			fmt.Fprintf(&b, `<li><span class="t">%s</span><span class="d">%s</span></li>`,
				html.EscapeString(shortDate(e.At)), html.EscapeString(e.Label))
		}
		b.WriteString(`</ul></section>`)
	}

	// Articles panel.
	b.WriteString(`<section class="panel articles"><h2>:: source mentions <span class="count">`)
	fmt.Fprintf(&b, `%d`, len(articles))
	b.WriteString(`</span> ::</h2>`)
	if len(articles) == 0 {
		b.WriteString(`<div class="empty">No articles in our index mention this CVE yet.</div>`)
	} else {
		b.WriteString(`<ul class="articles-list">`)
		max := len(articles)
		if max > 30 {
			max = 30
		}
		for _, a := range articles[:max] {
			b.WriteString(`<li><a href="`)
			b.WriteString(html.EscapeString(a.URL))
			b.WriteString(`" target="_blank" rel="noopener"><span class="ti">`)
			title := a.Title
			if len(title) > 130 {
				title = title[:130] + "..."
			}
			b.WriteString(html.EscapeString(title))
			b.WriteString(`</span><span class="ml"><span class="src">`)
			b.WriteString(html.EscapeString(a.Source))
			b.WriteString(`</span> &middot; <span class="ago">`)
			b.WriteString(html.EscapeString(relativeTime(a.PublishedAt)))
			b.WriteString(`</span></span></a></li>`)
		}
		b.WriteString(`</ul>`)
		if len(articles) > max {
			b.WriteString(`<div class="more-note">+`)
			fmt.Fprintf(&b, `%d`, len(articles)-max)
			b.WriteString(` more in the reader</div>`)
		}
	}
	b.WriteString(`</section>`)

	// Consensus panel (which sources are talking).
	if len(consensus) > 0 {
		b.WriteString(`<section class="panel"><h2>:: source consensus ::</h2><ul class="consensus">`)
		max := len(consensus)
		if max > 15 {
			max = 15
		}
		for _, c := range consensus[:max] {
			fmt.Fprintf(&b, `<li><span class="src">%s</span><span class="cnt">%d&times;</span></li>`,
				html.EscapeString(c.Source), c.Count)
		}
		b.WriteString(`</ul>`)
		if len(consensus) > max {
			b.WriteString(`<div class="more-note">+`)
			fmt.Fprintf(&b, `%d`, len(consensus)-max)
			b.WriteString(` more sources</div>`)
		}
		b.WriteString(`</section>`)
	}

	b.WriteString(`</div>`) // .grid

	// Pro CTA.
	b.WriteString(`<div class="cta-strip"><div class="cs-msg">Want the AI-generated 3-bullet summary of `)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`, plus webhook alerts when KEV is updated? <strong>Pro is $10/mo.</strong></div><div class="cs-actions"><a class="btn btn-secondary" href="/app?cve=`)
	b.WriteString(html.EscapeString(id))
	b.WriteString(`">Open in reader</a><a class="btn btn-primary" href="/pro">See Pro &rarr;</a></div></div>`)

	writeCVEFoot(&b)
	return []byte(b.String())
}

// Helper types so the renderer doesn't bind tightly to storage internals.
// We map from the real storage types to these in the handler boundary.
type consensusRowMin struct {
	Source string
	Count  int
}
type timelineEventMin struct {
	At    string
	Label string
}
type articleMin struct {
	Title       string
	URL         string
	Source      string
	PublishedAt time.Time
}

// fmtPct returns "92%" / "99%+" / "0.5%" style human-friendly strings
// from a 0-1 EPSS percentile float.
func fmtPct(p float64) string {
	if p <= 0 {
		return "-"
	}
	v := p * 100
	if v >= 99 {
		return "99%+"
	}
	if v >= 10 {
		return fmt.Sprintf("%d%%", int(v+0.5))
	}
	return fmt.Sprintf("%.1f%%", v)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortDate(s string) string {
	// Accept ISO 8601 / NVD / SQLite formats; return YYYY-MM-DD on success,
	// or the original on parse failure.
	if s == "" {
		return ""
	}
	if i := strings.Index(s, " m=+"); i > 0 {
		s = s[:i]
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05 -0700 MST", "2006-01-02T15:04:05.000", "2006-01-02 15:04:05", "2006-01-02"}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func relativeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	if d < 30*24*time.Hour {
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.UTC().Format("2006-01-02")
}

// sitemapCVECache holds the rendered sitemap XML. Generation is cheap
// (~10ms) but the page is hit by crawlers, not humans, so 1h cache is
// fine even when our top-CVE set shifts.
type sitemapCVECacheT struct {
	body   []byte
	expiry time.Time
	mu     sync.Mutex
}

var sitemapCVECache = &sitemapCVECacheT{}

const sitemapCVECacheTTL = 1 * time.Hour

// handleSitemapCVEs serves /sitemap-cves.xml - a dynamic sitemap of the
// top 500 most-mentioned CVE IDs. Crawler-facing only; humans go through
// the main sitemap.xml which references this one.
func (s *Server) handleSitemapCVEs(w http.ResponseWriter, r *http.Request) {
	sitemapCVECache.mu.Lock()
	if sitemapCVECache.body != nil && time.Now().Before(sitemapCVECache.expiry) {
		body := sitemapCVECache.body
		sitemapCVECache.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(body)
		return
	}
	sitemapCVECache.mu.Unlock()

	cves, err := s.store.TopMentionedCVEs(500)
	if err != nil {
		http.Error(w, "sitemap unavailable", http.StatusServiceUnavailable)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, c := range cves {
		if !cveIDPattern.MatchString(c) {
			continue
		}
		fmt.Fprintf(&b, "  <url><loc>https://omnomfeeds.com/cve/%s</loc><changefreq>daily</changefreq><priority>0.6</priority></url>\n", html.EscapeString(c))
	}
	b.WriteString(`</urlset>` + "\n")
	body := []byte(b.String())

	sitemapCVECache.mu.Lock()
	sitemapCVECache.body = body
	sitemapCVECache.expiry = time.Now().Add(sitemapCVECacheTTL)
	sitemapCVECache.mu.Unlock()

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(body)
}

// writeCVEHead writes the <head> + opening <body> + top nav. Inlines all
// CSS to keep the per-CVE pages self-contained (one HTTP request per
// page is fine for SEO; no shared CSS file to cache-bust on every
// theme tweak).
func writeCVEHead(b *strings.Builder, cveID, title, metaDesc string) {
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title><meta name="description" content="`)
	b.WriteString(html.EscapeString(metaDesc))
	b.WriteString(`"><link rel="canonical" href="https://omnomfeeds.com/cve/`)
	b.WriteString(html.EscapeString(cveID))
	b.WriteString(`"><link rel="icon" type="image/svg+xml" href="/favicon.svg"><meta property="og:title" content="`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`"><meta property="og:description" content="`)
	b.WriteString(html.EscapeString(metaDesc))
	b.WriteString(`"><meta property="og:type" content="website"><meta property="og:url" content="https://omnomfeeds.com/cve/`)
	b.WriteString(html.EscapeString(cveID))
	b.WriteString(`"><meta property="og:image" content="https://omnomfeeds.com/og-cover.png"><meta name="twitter:card" content="summary_large_image"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">`)
	b.WriteString(cvePageCSS)
	b.WriteString(`</head><body><div class="top"><div class="brand"><svg class="worm-sprite" viewBox="0 0 36 28" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><circle cx="5" cy="17" r="3.0" class="seg s3"/><circle cx="10" cy="16" r="3.6" class="seg s2"/><circle cx="16" cy="14" r="4.4" class="seg s1"/><circle cx="24" cy="13" r="5.4" class="head"/><circle cx="25" cy="11" r="1.4" class="eye"/><circle cx="25.5" cy="10.5" r="0.5" class="glint"/><ellipse cx="28" cy="14.5" rx="2.2" ry="0.6" class="mouth"/></svg> oM noM Security Feeds <span class="tag">cve</span></div><nav class="top-nav"><a href="/">about</a><a href="/trending">trending</a><a href="/pre-kev">pre-kev</a><a href="/api">api</a><a href="/app">reader</a><a href="/pro">pro</a></nav></div>`)
}

func writeCVEFoot(b *strings.Builder) {
	b.WriteString(`<footer><span>oM noM Security Feeds &middot; MIT licensed &middot; <a href="/api">public API</a> available</span><span><a href="/trending">Trending</a> &middot; <a href="/pre-kev">Pre-KEV</a> &middot; <a href="/feed.xml">RSS</a> &middot; <a href="https://github.com/RMS2D/omnomfeeds">GitHub</a></span></footer></body></html>`)
}

// cvePageCSS is the entire stylesheet for the per-CVE page, inlined into
// the <head>. Keeps each page self-contained.
const cvePageCSS = `<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e14;--bg-card:#14191f;--bg-row:#11161d;--border:#2a3340;--text:#e6ecf5;--text-dim:#b8c4d4;--text-bright:#fff;--accent:#00e5a0;--accent-cyan:#56e2ff;--accent-amber:#ffb547;--score-crit:#ff4d6a}
html,body{background:var(--bg);color:var(--text);font-family:'Space Grotesk',system-ui,sans-serif;font-size:14px;line-height:1.55;min-height:100vh}
a{color:var(--accent-cyan);text-decoration:none}
a:hover{color:var(--accent)}
code,.mono{font-family:'JetBrains Mono',monospace}
.top{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card);gap:16px;flex-wrap:wrap}
.brand{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-bright);font-weight:600;letter-spacing:.4px;display:flex;align-items:center;gap:10px}
.brand .worm-sprite{width:32px;height:25px;flex-shrink:0;animation:wb 2.4s ease-in-out infinite;filter:drop-shadow(0 0 5px rgba(0,229,160,.35))}
.brand .worm-sprite .seg,.brand .worm-sprite .head{fill:var(--accent)}
.brand .worm-sprite .seg.s3{opacity:.35}
.brand .worm-sprite .seg.s2{opacity:.6}
.brand .worm-sprite .seg.s1{opacity:.85}
.brand .worm-sprite .eye{fill:var(--bg)}
.brand .worm-sprite .glint{fill:var(--accent-cyan)}
.brand .worm-sprite .mouth{fill:var(--bg)}
@keyframes wb{0%,100%{transform:translateY(0)}50%{transform:translateY(-1.5px)}}
.brand .tag{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:1.4px;text-transform:uppercase;background:rgba(0,229,160,.12);border:1px solid var(--accent);color:var(--accent);padding:1px 6px;border-radius:2px;margin-left:6px}
nav.top-nav{display:flex;gap:18px;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.6px;text-transform:uppercase}
nav.top-nav a{color:var(--text-dim)}
nav.top-nav a:hover{color:var(--accent-cyan)}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 80px}
.hero{margin-bottom:18px}
.eyebrow{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1.4px;text-transform:uppercase;color:var(--accent-cyan);margin-bottom:8px}
h1{font-size:34px;line-height:1.1;letter-spacing:-.3px;color:var(--text-bright);margin-bottom:14px;font-family:'JetBrains Mono',monospace}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.chip{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.6px;padding:5px 11px;border-radius:3px;border:1px solid var(--border);background:var(--bg-row);color:var(--text-dim)}
.chip.kev{background:rgba(255,77,106,.12);border-color:var(--score-crit);color:var(--score-crit);font-weight:600;text-transform:uppercase}
.chip.cvss.crit{background:rgba(255,77,106,.12);border-color:var(--score-crit);color:var(--score-crit);font-weight:600}
.chip.cvss.high{background:rgba(255,181,71,.10);border-color:rgba(255,181,71,.55);color:var(--accent-amber);font-weight:600}
.chip.cvss.med{background:rgba(86,226,255,.08);border-color:rgba(86,226,255,.4);color:var(--accent-cyan)}
.chip.cvss.low{background:rgba(0,229,160,.08);border-color:rgba(0,229,160,.4);color:var(--accent)}
.chip.epss{background:rgba(86,226,255,.06);border-color:rgba(86,226,255,.32);color:var(--accent-cyan)}
.chip.epss.warn{background:rgba(255,181,71,.10);border-color:rgba(255,181,71,.55);color:var(--accent-amber);font-weight:600}
.chip.epss.hot{background:rgba(255,77,106,.12);border-color:var(--score-crit);color:var(--score-crit);font-weight:600}
.chip.cwe,.chip.otx{color:var(--text-dim)}
.lead{font-size:15.5px;color:var(--text);max-width:840px;line-height:1.6;margin-bottom:8px}
.meta-line{color:var(--text-dim);font-size:12px;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
.meta-line strong{color:var(--text)}
.grid{display:grid;grid-template-columns:1fr 1.4fr;gap:16px;margin-top:22px}
.grid .articles{grid-column:1/-1}
@media (max-width:820px){.grid{grid-template-columns:1fr}}
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:5px;padding:18px 20px}
.panel h2{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1.2px;color:var(--accent-cyan);text-transform:uppercase;margin-bottom:12px;font-weight:600}
.panel h2 .count{color:var(--accent);font-size:10px;margin-left:6px}
dl.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13px}
dl.kv dt{color:var(--text-dim);font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.5px;text-transform:uppercase;padding-top:3px}
dl.kv dd{color:var(--text)}
dl.kv dd.hot{color:var(--score-crit);font-weight:600}
dl.kv dd.dim{color:var(--text-dim)}
dl.kv dd.mono{font-family:'JetBrains Mono',monospace;font-size:11.5px;word-break:break-all;color:var(--text-dim)}
.ext-links{margin-top:14px;padding-top:12px;border-top:1px dashed var(--border);font-family:'JetBrains Mono',monospace;font-size:11px}
ul.timeline{list-style:none;padding:0}
ul.timeline li{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--bg-row);font-size:13px}
ul.timeline li:last-child{border-bottom:none}
ul.timeline .t{font-family:'JetBrains Mono',monospace;color:var(--text-dim);font-size:11px;min-width:90px;padding-top:2px}
ul.timeline .d{color:var(--text)}
ul.articles-list{list-style:none;padding:0}
ul.articles-list li{padding:10px 0;border-bottom:1px solid var(--bg-row)}
ul.articles-list li:last-child{border-bottom:none}
ul.articles-list a{display:flex;justify-content:space-between;gap:14px;align-items:baseline}
ul.articles-list .ti{color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
ul.articles-list a:hover .ti{color:var(--accent-cyan)}
ul.articles-list .ml{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-dim);white-space:nowrap}
ul.articles-list .src{color:var(--accent-cyan)}
ul.articles-list .ago{color:var(--text-dim);margin-left:6px}
ul.consensus{list-style:none;padding:0;font-size:13px}
ul.consensus li{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--bg-row)}
ul.consensus li:last-child{border-bottom:none}
ul.consensus .src{color:var(--text)}
ul.consensus .cnt{color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:12px}
.empty{padding:14px 0;color:var(--text-dim);font-style:italic;font-size:13px}
.more-note{margin-top:10px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);font-style:italic}
.cta-strip{margin-top:28px;padding:16px 20px;background:linear-gradient(180deg,rgba(0,229,160,.04),rgba(0,229,160,.01));border:1px solid rgba(0,229,160,.22);border-left:2px solid var(--accent);border-radius:4px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.cta-strip .cs-msg{color:var(--text);font-size:14px}
.cta-strip .cs-msg strong{color:var(--text-bright)}
.cta-strip .cs-actions{display:flex;gap:10px;align-items:center}
.cta-strip a.btn{display:inline-flex;align-items:center;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.8px;text-transform:uppercase;padding:8px 16px;border-radius:3px;font-weight:600}
.cta-strip a.btn-primary{background:var(--accent);color:var(--bg)}
.cta-strip a.btn-primary:hover{background:var(--accent-cyan)}
.cta-strip a.btn-secondary{border:1px solid var(--border);color:var(--text)}
.cta-strip a.btn-secondary:hover{border-color:var(--accent);color:var(--accent)}
footer{margin-top:48px;padding-top:22px;border-top:1px solid var(--border);display:flex;justify-content:space-between;flex-wrap:wrap;gap:14px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-width:1080px;margin-left:auto;margin-right:auto;padding-left:24px;padding-right:24px;padding-bottom:24px}
footer a{color:var(--text-dim)}
footer a:hover{color:var(--accent-cyan)}
</style>`
