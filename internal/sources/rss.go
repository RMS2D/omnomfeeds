package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/mmcdole/gofeed"
	utls "github.com/refraction-networking/utls"
)

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

var rssDialer = &net.Dialer{Timeout: 10 * time.Second}

// rssDialTLS handshakes with a Chrome uTLS ClientHelloSpec so Akamai's
// JA3/JA4 fingerprinting doesn't drop us. ALPN trimmed to h1.1 only.
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

// rssTransport pairs the uTLS dialer with h1.1-only. Exposed so retries
// can CloseIdleConnections() to evict poisoned pool entries. Idle 30s.
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

// transientHTTPStatuses: retry on fresh conn. 404 included because Akamai
// edge-cache flaps. 403 excluded: bot blocks don't change on retry.
var transientHTTPStatuses = map[int]bool{
	http.StatusRequestTimeout:     true, // 408
	http.StatusTooManyRequests:    true, // 429
	http.StatusInternalServerError: true, // 500
	http.StatusBadGateway:         true, // 502
	http.StatusServiceUnavailable: true, // 503
	http.StatusGatewayTimeout:     true, // 504
	http.StatusNotFound:           true, // 404 (CDN flake)
}

// doRSSRequest fires the HTTP request through rssClient with one retry
// on transient errors. Two retry classes:
//
//   - Network-layer transients (stream errors, EOFs, resets) - covered
//     by isTransientFetchErr. Usually pool poisoning.
//   - HTTP-status transients (5xx, 429, 408, 404) - covered by
//     transientHTTPStatuses. Usually CDN flapping.
//
// Between attempts we force-evict idle pooled connections so the retry
// uses a fresh dial. RSS requests are GETs so cloning the request is
// safe (no body to re-stream).
func doRSSRequest(req *http.Request) (*http.Response, error) {
	resp, err := rssClient.Do(req)
	// Network-layer transient: retry on fresh dial.
	if err != nil {
		if !isTransientFetchErr(err) {
			return resp, err
		}
		rssTransport.CloseIdleConnections()
		time.Sleep(200 * time.Millisecond)
		retry := req.Clone(req.Context())
		return rssClient.Do(retry)
	}
	// HTTP-status transient: drain + close the first body, evict the
	// connection (since the server may have associated it with a stale
	// CDN edge), retry once. Backoff is longer for 429 to respect any
	// implicit rate hint.
	if transientHTTPStatuses[resp.StatusCode] {
		drainAndClose(resp)
		rssTransport.CloseIdleConnections()
		sleep := 250 * time.Millisecond
		if resp.StatusCode == http.StatusTooManyRequests {
			sleep = 1500 * time.Millisecond
		}
		time.Sleep(sleep)
		retry := req.Clone(req.Context())
		return rssClient.Do(retry)
	}
	return resp, nil
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	// Drain so the connection can return to the pool cleanly even
	// though we're about to evict it. Cheap belt-and-braces.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`)
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

	// 10 MB cap so a hostile feed can't OOM the daemon.
	parser := gofeed.NewParser()
	feed, err := parser.Parse(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("feed parsing error: %v", err)
	}

	var articles []models.Article
	for _, item := range feed.Items {
		// Skip sponsored items: unstable pubDates + rotating URLs make
		// them republish every cycle and pin to the top.
		if isSponsoredTitle(item.Title) {
			continue
		}

		pub := time.Now()
		if item.PublishedParsed != nil {
			pub = *item.PublishedParsed
		} else if item.UpdatedParsed != nil {
			pub = *item.UpdatedParsed
		}
		// Clamp future pubDates to now (event calendars / pre-pub advisories
		// would pin to top forever). Small grace window for clock skew.
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
