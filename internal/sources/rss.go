package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/http"
	"regexp"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	utls "github.com/refraction-networking/utls"
)

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

var rssDialer = &net.Dialer{Timeout: 10 * time.Second}

// rssDialTLS performs the TLS handshake using a Chrome ClientHelloSpec
// from uTLS instead of Go's default crypto/tls fingerprint. Akamai
// (Microsoft Security blog, others) fingerprints Go's TLS handshake
// (JA3/JA4) and either RST_STREAM-s the h2 stream or silently drops
// the h1.1 connection even with a browser User-Agent. Matching Chrome's
// fingerprint makes the request indistinguishable from a real browser
// at the TLS layer. ALPN is trimmed to h1.1 only so the http.Transport
// (which has h2 disabled) speaks the protocol the conn negotiated.
// ALPN values aren't part of the JA3 hash, so the fingerprint match
// holds.
func rssDialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rawConn, err := rssDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := uconn.ApplyPreset(&spec); err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

// rssTransport is the underlying http.Transport pairing the uTLS Chrome
// spec dialer with HTTP/1.1-only behaviour. Exposed at package scope so
// the retry wrapper can call CloseIdleConnections() to evict a poisoned
// pool entry between attempts. IdleConnTimeout shortened from 90s to 30s
// so a flaky cached connection clears within a single 3-minute fetch
// cycle instead of getting reused for 30+ minutes.
var rssTransport = &http.Transport{
	DialTLSContext:      rssDialTLS,
	TLSNextProto:        map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	ForceAttemptHTTP2:   false,
	MaxIdleConns:        32,
	MaxIdleConnsPerHost: 4,
	IdleConnTimeout:     30 * time.Second,
}

var rssClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: rssTransport,
}

// transientNetErrPatterns are error-string substrings we treat as
// "retry-on-fresh-connection". Most come from net/http and
// golang.org/x/net/http2 - flat-string match keeps us decoupled from
// those packages' internal error types.
var transientNetErrPatterns = []string{
	"stream error",       // golang.org/x/net/http2 stream-level error frame
	"INTERNAL_ERROR",     // H2 INTERNAL_ERROR specifically (Microsoft case)
	"connection reset",   // peer RST mid-stream
	"unexpected EOF",     // pool entry closed under us
	"broken pipe",        // write to closed connection
	"use of closed network connection", // races with idle eviction
	"i/o timeout",        // sometimes a stuck connection looks like this
}

func isTransientFetchErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, p := range transientNetErrPatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// doRSSRequest fires the HTTP request through rssClient with one retry
// on transient errors. Between attempts we force-evict any idle pooled
// connections - the most common cause of these errors is a bad cached
// connection from a flaky load-balancer (Microsoft Akamai is the
// repeat offender). The retry uses a fresh dial via DialTLSContext.
func doRSSRequest(req *http.Request) (*http.Response, error) {
	resp, err := rssClient.Do(req)
	if err == nil {
		return resp, nil
	}
	if !isTransientFetchErr(err) {
		return resp, err
	}
	// Clear the pool, sleep briefly, retry once on a fresh connection.
	rssTransport.CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)
	// Build a fresh request with the same context + headers since the
	// original may have a partially-consumed body. RSS requests are
	// GETs with no body so a shallow clone is safe.
	retry := req.Clone(req.Context())
	return rssClient.Do(retry)
}

type RSSSource struct {
	name string
	url  string
}

func NewRSS(name, url string) *RSSSource {
	return &RSSSource{name: name, url: url}
}

func (r *RSSSource) Name() string { return r.name }
func (r *RSSSource) Type() string { return "rss" }

func (r *RSSSource) Fetch(ctx context.Context) ([]models.Article, error) {
	// 1. Manually build the request to spoof a full desktop browser
	req, err := http.NewRequestWithContext(ctx, "GET", r.url, nil)
	if err != nil {
		return nil, err
	}

	// Match the header set a real Chrome navigation sends. Akamai bot
	// mitigation checks for sec-ch-ua / sec-fetch-* presence; a UA that
	// claims to be Chrome but doesn't ship these is flagged immediately.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="123", "Not:A-Brand";v="8"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	// 2. Execute the request via the retry wrapper. doRSSRequest handles
	// the transient-error class (h2 stream errors, pool poisoning, peer
	// resets) by clearing idle connections and dialling a fresh one.
	resp, err := doRSSRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	// 3. Pass the raw body to gofeed for parsing
	parser := gofeed.NewParser()
	feed, err := parser.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("feed parsing error: %v", err)
	}

	var articles []models.Article
	for _, item := range feed.Items {
		// Skip sponsored content the feed pretends is news. Dark Reading,
		// SC Magazine, and a few others stuff these into the main feed.
		// They typically have no stable pubDate and rotating tracking
		// URLs, so without this filter they republish themselves every
		// fetch cycle and pin to the top via ORDER BY published_at DESC.
		if isSponsoredTitle(item.Title) {
			continue
		}

		pub := time.Now()
		if item.PublishedParsed != nil {
			pub = *item.PublishedParsed
		} else if item.UpdatedParsed != nil {
			pub = *item.UpdatedParsed
		}
		// Clamp future pubDates to now. Some feeds (event calendars,
		// pre-published advisories) put a future date in pubDate, which
		// pins the item to the top of an ORDER BY published_at DESC list
		// and renders as "just now" forever. A small grace window
		// tolerates clock skew between this host and the feed origin.
		if pub.After(time.Now().Add(2 * time.Hour)) {
			pub = time.Now()
		}

		summary := stripHTML(item.Description)
		if len(summary) > 500 {
			summary = summary[:500] + "..."
		}

		articles = append(articles, models.Article{
			Title:       item.Title,
			URL:         item.Link,
			Source:      r.name,
			SourceType:  "rss",
			Summary:     summary,
			PublishedAt: pub,
			FetchedAt:   time.Now(),
		})
	}
	return articles, nil
}

func stripHTML(s string) string {
	s = htmlTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}

// sponsoredPrefixes are the bracketed labels Dark Reading and similar
// industry sites use to mark non-editorial content. Match is case
// insensitive and only on a leading bracketed token, so a legit article
// like "Inside the [Virtual Event] panel: lessons learned" won't trip.
var sponsoredPrefixes = []string{
	"[virtual event]",
	"[webinar]",
	"[sponsored]",
	"[whitepaper]",
	"[white paper]",
	"[ebook]",
	"[research report]",
	"[partner perspectives]",
	"[on-demand webinar]",
}

func isSponsoredTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	for _, p := range sponsoredPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}
