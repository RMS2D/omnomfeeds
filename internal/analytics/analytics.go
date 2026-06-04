// Package analytics is the in-house event log. Anonymous traffic dedupes via
// session cookie; signed-in users join by user_id. ip_hash + user_agent are
// captured per event for admin-only abuse / bot-detection views; never
// displayed in plaintext.
package analytics

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event names. Keep this list canonical so the dashboard can rely on
// exact strings. Add new ones here, not at the call site.
const (
	EvPageView            = "page_view"
	EvArticleOpen         = "article_open"
	EvCVEModalOpen        = "cve_modal_open"
	EvAttackExport        = "attack_export"
	EvActorChipOpen       = "actor_chip_open"
	EvMalwareChipOpen     = "malware_chip_open"
	EvBookmarkAdd         = "bookmark_add"
	EvProView             = "pro_view"
	EvProCheckoutStart    = "pro_checkout_start"
	EvProSubscribeSuccess = "pro_subscribe_success"
	EvProSubscribeRenew   = "pro_subscribe_renew"
	EvDigestLinkClick     = "digest_link_click"
	EvWebhookFired        = "webhook_fired"
)

// SessionCookieName is the opaque per-browser identifier. Httponly,
// Samesite=Lax, ~30 day TTL. Set only on the first hit; we never read
// the value beyond passing it back into Emit().
const SessionCookieName = "omn_sid"

// Analytics is the package handle. One per process; safe for concurrent use.
type Analytics struct {
	db *sql.DB
}

func New(db *sql.DB) *Analytics {
	if db == nil {
		return nil
	}
	return &Analytics{db: db}
}

// Emit writes one event. Failures are logged, never returned - analytics must
// never break a user-facing request. ipHash may be nil (server-to-server
// events). userAgent may be empty. Events from IPs listed in
// ANALYTICS_EXCLUDE_IPS are dropped at the write boundary so operator
// activity never enters the dashboard.
func (a *Analytics) Emit(userID, session, event, ref string, meta any, ipHash []byte, userAgent string) {
	if a == nil || a.db == nil || event == "" {
		return
	}
	if isExcludedIPHash(ipHash) {
		return
	}
	var metaStr sql.NullString
	switch v := meta.(type) {
	case nil:
		// leave NULL
	case string:
		if v != "" {
			metaStr = sql.NullString{String: v, Valid: true}
		}
	default:
		b, err := json.Marshal(v)
		if err == nil {
			metaStr = sql.NullString{String: string(b), Valid: true}
		}
	}
	var userIDArg, sessionArg, refArg, uaArg sql.NullString
	if userID != "" {
		userIDArg = sql.NullString{String: userID, Valid: true}
	}
	if session != "" {
		sessionArg = sql.NullString{String: session, Valid: true}
	}
	if ref != "" {
		refArg = sql.NullString{String: ref, Valid: true}
	}
	if userAgent != "" {
		if len(userAgent) > 400 {
			userAgent = userAgent[:400]
		}
		uaArg = sql.NullString{String: userAgent, Valid: true}
	}
	var ipArg any
	if len(ipHash) > 0 {
		ipArg = ipHash
	}
	_, err := a.db.Exec(
		`INSERT INTO events (user_id, session, event, ref, meta, ip_hash, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userIDArg, sessionArg, event, refArg, metaStr, ipArg, uaArg,
	)
	if err != nil {
		log.Printf("[analytics] emit %s: %v", event, err)
	}
}

// trustedProxyNets is the parsed TRUSTED_PROXY_CIDR list. Defaults to
// loopback so XFF from localhost is honoured (dev mode behind Caddy).
var (
	trustedProxyOnce sync.Once
	trustedProxyNets []*net.IPNet
)

func loadTrustedProxies() {
	raw := os.Getenv("TRUSTED_PROXY_CIDR")
	if raw == "" {
		raw = "127.0.0.0/8,::1/128"
	}
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			trustedProxyNets = append(trustedProxyNets, n)
		}
	}
}

func remoteIsTrusted(addr string) bool {
	trustedProxyOnce.Do(loadTrustedProxies)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// excludedIPHashes is the parsed ANALYTICS_EXCLUDE_IPS list, hex-encoded for
// O(1) lookup. Populated lazily on first call so test code can set the env
// var before constructing an Analytics instance.
var (
	excludedIPHashes     map[string]struct{}
	excludedIPHashesOnce sync.Once
)

func loadExcludedIPHashes() {
	raw := os.Getenv("ANALYTICS_EXCLUDE_IPS")
	if raw == "" {
		return
	}
	excludedIPHashes = map[string]struct{}{}
	for _, ip := range strings.Split(raw, ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		sum := sha256.Sum256([]byte(ip))
		excludedIPHashes[hex.EncodeToString(sum[:])] = struct{}{}
	}
}

func isExcludedIPHash(h []byte) bool {
	excludedIPHashesOnce.Do(loadExcludedIPHashes)
	if len(excludedIPHashes) == 0 || len(h) == 0 {
		return false
	}
	_, ok := excludedIPHashes[hex.EncodeToString(h)]
	return ok
}

// HashIPFromRequest returns the SHA-256 of the originating IP. Honours
// X-Forwarded-For only when r.RemoteAddr is in TRUSTED_PROXY_CIDR; otherwise
// the socket peer wins. Returns nil if no IP can be derived.
func HashIPFromRequest(r *http.Request) []byte {
	if r == nil {
		return nil
	}
	var ip string
	if remoteIsTrusted(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.Index(xff, ","); comma > 0 {
				xff = xff[:comma]
			}
			ip = strings.TrimSpace(xff)
		}
	}
	if ip == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		} else {
			ip = r.RemoteAddr
		}
	}
	if ip == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(ip))
	return sum[:]
}

// EnsureSession reads the omn_sid cookie or sets a fresh one. Returns the
// session token to pass to Emit. Set Secure when called over TLS; httponly
// always; samesite=lax keeps the cookie out of cross-site POSTs but lets
// it ride normal navigations.
func (a *Analytics) EnsureSession(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(SessionCookieName); err == nil && validSession(c.Value) {
		return c.Value
	}
	tok := newSessionToken()
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    tok,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	return tok
}

// SessionFromRequest is the read-only variant - reads the existing cookie,
// returns "" if absent. For places where we don't want to set a cookie
// (background workers re-using a context, JSON API calls from scripts).
func SessionFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && validSession(c.Value) {
		return c.Value
	}
	return ""
}

func newSessionToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Falling back here would defeat the dedup purpose. Better to
		// emit with an empty session than a deterministic value.
		return ""
	}
	return hex.EncodeToString(b[:])
}

func validSession(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Summary is the single payload the dashboard renders. One round trip;
// the dashboard does no further fan-out.
type Summary struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	WindowDays    int               `json:"window_days"`
	Active        ActiveCounts      `json:"active"`
	Funnel        ProFunnel         `json:"funnel"`
	EventCounts   map[string]int    `json:"event_counts"`
	TopArticles   []TopRef          `json:"top_articles"`
	TopCVEs       []TopRef          `json:"top_cves"`
	TopActors     []TopRef          `json:"top_actors"`
	TopMalware    []TopRef          `json:"top_malware"`
	TopPaths      []TopRef          `json:"top_paths"` // page_view breakdown by path
	AttackExports []DayCount        `json:"attack_exports_daily"`
	DailyVolume   []DayCount        `json:"daily_volume"`
	Hourly        []HourCount       `json:"hourly_24"`    // last 7d, bucketed by UTC hour
	SinceLaunch    SinceLaunchTotals `json:"since_launch"`    // raw totals so sparse windows still tell a story
	BotSignals     BotSignals        `json:"bot_signals"`     // distinct-IP + UA-family breakdown
	PublicSurfaces []SurfaceRow      `json:"public_surfaces"` // engagement per public/free page
}

// SurfaceRow is a per-path engagement slice. Browser-shaped views filters
// out the bot UAs surfaced in BotSignals so the human-traffic number is
// directly comparable across surfaces.
type SurfaceRow struct {
	Path                string `json:"path"`
	Views               int    `json:"views"`
	BrowserViews        int    `json:"browser_views"`
	CapturedUAViews     int    `json:"captured_ua_views"` // denominator for browser_share
	DistinctSessions    int    `json:"distinct_sessions"`
	DistinctIPs         int    `json:"distinct_ips"`
	ViewsPerSession     string `json:"views_per_session"`
	BrowserSharePercent string `json:"browser_share"`
}

// BotSignals exposes the abuse-detection slice of the events table. All
// IP rows are reduced to a 12-hex-char hash prefix so the admin view can
// distinguish IPs without surfacing reversible identifiers.
type BotSignals struct {
	WindowEvents      int        `json:"window_events"`
	CapturedUAEvents  int        `json:"captured_ua_events"` // events in window with non-NULL user_agent
	DistinctIPs       int        `json:"distinct_ips"`
	EventsFromTopN    int        `json:"events_from_top_n"` // events accounted for by TopIPs
	SingleSessionIPs  int        `json:"single_session_ips"`
	MultiSessionIPs   int        `json:"multi_session_ips"`
	BotUAEvents       int        `json:"bot_ua_events"`
	BrowserUAEvents   int        `json:"browser_ua_events"`
	EmptyUAEvents     int        `json:"empty_ua_events"`
	TopIPs            []IPRow    `json:"top_ips"`
	UAFamilies        []UARow    `json:"ua_families"`
	SessionsPerIP     []DistRow  `json:"sessions_per_ip"`
}

type IPRow struct {
	IDPrefix  string `json:"id_prefix"` // 12 hex chars of SHA-256(IP)
	Events    int    `json:"events"`
	Sessions  int    `json:"sessions"`
	UAFamily  string `json:"ua_family"` // dominant family for this IP
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type UARow struct {
	Family string `json:"family"`
	Events int    `json:"events"`
}

type DistRow struct {
	Bucket string `json:"bucket"` // "1", "2-5", "6-20", "21+"
	IPs    int    `json:"ips"`
}

type ActiveCounts struct {
	DAU       int `json:"dau"`        // distinct (user_id|session) in last 24h
	WAU       int `json:"wau"`        // last 7d
	MAU       int `json:"mau"`        // last 30d
	ProActive int `json:"pro_active"` // current paying users from users.pro_until
}

type ProFunnel struct {
	Views      int `json:"views"`
	Checkouts  int `json:"checkouts"`
	Subscribes int `json:"subscribes"`
}

type TopRef struct {
	Ref   string `json:"ref"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type DayCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type HourCount struct {
	Hour  int `json:"hour"` // 0-23 UTC
	Count int `json:"count"`
}

type SinceLaunchTotals struct {
	Events     int64 `json:"events"`
	Sessions   int64 `json:"sessions"`
	SignedIn   int64 `json:"signed_in"`
	FirstEvent int64 `json:"first_event_unix"` // 0 if no events yet
}

// internalEmails are operator accounts whose activity should not pollute
// the dashboard. Includes their pre-login anon sessions (any session
// ever linked to one of these user_ids gets filtered too). Edit this
// list to add or remove operators. Empty list disables filtering.
var internalEmails = []string{
	"rms2ds@gmail.com",
	"darks@outlook.com",
	"rms2ds@gmail.com",
}

// excludeFilter holds pre-quoted SQL list literals for operator accounts.
// IDs come from our DB but we still strip non-[A-Za-z0-9-] as a guard.
type excludeFilter struct {
	UserIDList  string // SQL list literal: 'uuid1','uuid2'
	SessionList string // SQL list literal: 'hex1','hex2'
	HasUsers    bool
	HasSessions bool
}

// safeID strips anything other than alphanumerics + dash from an id so
// it can't break out of a quoted SQL literal. User IDs are UUIDs and
// session tokens are hex - the strip is a no-op in the happy case.
var idScrubber = regexp.MustCompile(`[^a-zA-Z0-9-]`)

func quoteList(values []string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		clean := idScrubber.ReplaceAllString(v, "")
		if clean == "" {
			continue
		}
		out = append(out, "'"+clean+"'")
	}
	return strings.Join(out, ",")
}

func (a *Analytics) buildExcludeFilter() *excludeFilter {
	ef := &excludeFilter{}
	if len(internalEmails) == 0 {
		return ef
	}
	// Resolve emails -> user_ids using parameterised query (user-supplied
	// values stay out of the SQL string here).
	args := make([]any, len(internalEmails))
	ph := make([]string, len(internalEmails))
	for i, e := range internalEmails {
		args[i] = e
		ph[i] = "?"
	}
	rows, err := a.db.Query(`SELECT id FROM users WHERE email IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return ef
	}
	var userIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			userIDs = append(userIDs, id)
		}
	}
	rows.Close()
	if len(userIDs) == 0 {
		return ef
	}
	ef.UserIDList = quoteList(userIDs)
	ef.HasUsers = ef.UserIDList != ""

	// Collect every session token that's ever appeared alongside one of
	// those user_ids. Catches the pre-login anon browsing from the same
	// browser the operator later signed in from.
	srows, err := a.db.Query(`SELECT DISTINCT session FROM events
		WHERE user_id IN (` + ef.UserIDList + `) AND session IS NOT NULL AND session != ''`)
	if err != nil {
		return ef
	}
	var sessions []string
	for srows.Next() {
		var s string
		if srows.Scan(&s) == nil {
			sessions = append(sessions, s)
		}
	}
	srows.Close()
	if len(sessions) > 0 {
		ef.SessionList = quoteList(sessions)
		ef.HasSessions = ef.SessionList != ""
	}
	return ef
}

// Clause returns an SQL fragment that appends to a WHERE on the events
// table (or a query alias of it). Empty when nothing to exclude. alias
// is "" for un-aliased queries, "a" / "e" / etc. for aliased ones.
func (ef *excludeFilter) Clause(alias string) string {
	if ef == nil || !ef.HasUsers {
		return ""
	}
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	out := " AND (" + prefix + "user_id IS NULL OR " + prefix + "user_id NOT IN (" + ef.UserIDList + "))"
	if ef.HasSessions {
		out += " AND (" + prefix + "session IS NULL OR " + prefix + "session NOT IN (" + ef.SessionList + "))"
	}
	return out
}

// BuildSummary computes everything the dashboard needs in one place. Caller
// passes days for the rollup window (7, 30, 90). 0 defaults to 30.
func (a *Analytics) BuildSummary(days int) (*Summary, error) {
	if a == nil || a.db == nil {
		return nil, errors.New("analytics not initialised")
	}
	if days <= 0 {
		days = 30
	}
	s := &Summary{
		GeneratedAt: time.Now().UTC(),
		WindowDays:  days,
		EventCounts: map[string]int{},
	}
	ef := a.buildExcludeFilter()
	if err := a.fillActive(s, ef); err != nil {
		return nil, err
	}
	if err := a.fillFunnel(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillEventCounts(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillTopRef(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillDailyVolume(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillAttackExports(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillTopPaths(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillHourly(s, ef); err != nil {
		return nil, err
	}
	if err := a.fillSinceLaunch(s, ef); err != nil {
		return nil, err
	}
	if err := a.fillBotSignals(s, days, ef); err != nil {
		return nil, err
	}
	if err := a.fillPublicSurfaces(s, days, ef); err != nil {
		return nil, err
	}
	return s, nil
}

// uaFamily buckets a User-Agent string for the dashboard. The list is
// intentionally short - we want signal, not a fingerprinting engine.
func uaFamily(ua string) string {
	if ua == "" {
		return "empty"
	}
	low := strings.ToLower(ua)
	// Bots and crawlers first - many include "Mozilla" later in the string
	// so the bot heuristics have to win the order.
	botMarkers := []string{
		"bot", "crawl", "spider", "slurp", "fetch", "monitor",
		"check_http", "uptimerobot", "pingdom", "statuspage",
		"semrush", "ahrefs", "mj12", "dotbot", "petalbot",
		"gptbot", "claudebot", "perplexity", "anthropic", "openai",
		"bytespider", "amazonbot", "applebot", "yandex", "baidu",
		"facebook", "twitter", "linkedin", "pinterest", "discord",
		"telegram", "slack", "whatsapp",
		"go-http-client", "python-requests", "python-urllib", "scrapy",
		"curl/", "wget/", "httpie", "okhttp", "axios", "node-fetch",
		"libwww-perl", "java/", "ruby", "headless",
	}
	for _, m := range botMarkers {
		if strings.Contains(low, m) {
			return "bot"
		}
	}
	switch {
	case strings.Contains(low, "firefox"):
		return "firefox"
	case strings.Contains(low, "edg/") || strings.Contains(low, "edge/"):
		return "edge"
	case strings.Contains(low, "chrome"):
		return "chrome"
	case strings.Contains(low, "safari"):
		return "safari"
	}
	return "other"
}

func isBotFamily(f string) bool { return f == "bot" }
func isBrowserFamily(f string) bool {
	switch f {
	case "firefox", "chrome", "edge", "safari":
		return true
	}
	return false
}

// fillBotSignals derives the abuse-detection view. Events older than this
// change have NULL ip_hash so they're naturally excluded from the IP
// aggregates; total counts reflect the windowed event volume regardless.
func (a *Analytics) fillBotSignals(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	excl := ef.Clause("")

	// Total event count in the window. Includes pre-migration rows so the
	// "of N total events, X% have UA captured" callout works.
	totalQ := `SELECT COUNT(*) FROM events WHERE ts >= datetime('now', ?)` + excl
	if err := a.db.QueryRow(totalQ, since).Scan(&s.BotSignals.WindowEvents); err != nil {
		return err
	}

	// UA family breakdown - only over events that HAVE a UA captured. The
	// NULL/empty rows are a migration artifact (pre-deploy events), not a
	// real "empty UA" signal, so we exclude them from this breakdown to
	// keep the dashboard honest.
	uaQ := `
		SELECT user_agent, COUNT(*)
		FROM events
		WHERE ts >= datetime('now', ?)
		  AND user_agent IS NOT NULL
		  AND user_agent != ''` + excl + `
		GROUP BY user_agent
	`
	uaRows, err := a.db.Query(uaQ, since)
	if err != nil {
		return err
	}
	famCounts := map[string]int{}
	for uaRows.Next() {
		var ua string
		var n int
		if err := uaRows.Scan(&ua, &n); err != nil {
			uaRows.Close()
			return err
		}
		fam := uaFamily(ua)
		famCounts[fam] += n
		s.BotSignals.CapturedUAEvents += n
		switch {
		case isBotFamily(fam):
			s.BotSignals.BotUAEvents += n
		case isBrowserFamily(fam):
			s.BotSignals.BrowserUAEvents += n
		}
	}
	uaRows.Close()
	// EmptyUAEvents is the migration-artifact gap: total window events that
	// don't yet have a UA. Useful as a "fraction we can classify" signal.
	s.BotSignals.EmptyUAEvents = s.BotSignals.WindowEvents - s.BotSignals.CapturedUAEvents
	for fam, n := range famCounts {
		s.BotSignals.UAFamilies = append(s.BotSignals.UAFamilies, UARow{Family: fam, Events: n})
	}
	sort.Slice(s.BotSignals.UAFamilies, func(i, j int) bool {
		return s.BotSignals.UAFamilies[i].Events > s.BotSignals.UAFamilies[j].Events
	})

	// Per-IP rollup. ip_hash is NULL for legacy rows; filter those out so
	// distinct-IP counts mean "since the migration".
	ipQ := `
		SELECT ip_hash,
		       COUNT(*) AS events,
		       COUNT(DISTINCT session) AS sessions,
		       MIN(ts) AS first_seen,
		       MAX(ts) AS last_seen
		FROM events
		WHERE ts >= datetime('now', ?)
		  AND ip_hash IS NOT NULL` + excl + `
		GROUP BY ip_hash
		ORDER BY events DESC
	`
	rows, err := a.db.Query(ipQ, since)
	if err != nil {
		return err
	}
	defer rows.Close()

	const topN = 25
	rank := 0
	type ipAgg struct {
		hash       []byte
		events     int
		sessions   int
		firstSeen  string
		lastSeen   string
	}
	var topIPs []ipAgg
	sessionsBuckets := map[string]int{"1": 0, "2-5": 0, "6-20": 0, "21+": 0}
	for rows.Next() {
		var hash []byte
		var events, sessions int
		var first, last string
		if err := rows.Scan(&hash, &events, &sessions, &first, &last); err != nil {
			return err
		}
		s.BotSignals.DistinctIPs++
		switch {
		case sessions <= 1:
			s.BotSignals.SingleSessionIPs++
			sessionsBuckets["1"]++
		case sessions <= 5:
			s.BotSignals.MultiSessionIPs++
			sessionsBuckets["2-5"]++
		case sessions <= 20:
			s.BotSignals.MultiSessionIPs++
			sessionsBuckets["6-20"]++
		default:
			s.BotSignals.MultiSessionIPs++
			sessionsBuckets["21+"]++
		}
		if rank < topN {
			topIPs = append(topIPs, ipAgg{
				hash: append([]byte(nil), hash...), events: events,
				sessions: sessions, firstSeen: first, lastSeen: last,
			})
			s.BotSignals.EventsFromTopN += events
			rank++
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, b := range []string{"1", "2-5", "6-20", "21+"} {
		s.BotSignals.SessionsPerIP = append(s.BotSignals.SessionsPerIP, DistRow{Bucket: b, IPs: sessionsBuckets[b]})
	}

	// Per-top-IP dominant UA family lookup. One query per IP keeps this
	// readable; topN=25 so the cost is bounded.
	for _, ip := range topIPs {
		fam := a.dominantUAFamily(ip.hash, since, excl)
		s.BotSignals.TopIPs = append(s.BotSignals.TopIPs, IPRow{
			IDPrefix:  hex.EncodeToString(ip.hash[:6]),
			Events:    ip.events,
			Sessions:  ip.sessions,
			UAFamily:  fam,
			FirstSeen: ip.firstSeen,
			LastSeen:  ip.lastSeen,
		})
	}
	return nil
}

func (a *Analytics) dominantUAFamily(ipHash []byte, since, excl string) string {
	q := `
		SELECT COALESCE(user_agent, ''), COUNT(*) AS n
		FROM events
		WHERE ip_hash = ?
		  AND ts >= datetime('now', ?)` + excl + `
		GROUP BY COALESCE(user_agent, '')
		ORDER BY n DESC
		LIMIT 5
	`
	rows, err := a.db.Query(q, ipHash, since)
	if err != nil {
		return "unknown"
	}
	defer rows.Close()
	famCounts := map[string]int{}
	for rows.Next() {
		var ua string
		var n int
		if err := rows.Scan(&ua, &n); err != nil {
			continue
		}
		famCounts[uaFamily(ua)] += n
	}
	best := "unknown"
	bestN := -1
	for fam, n := range famCounts {
		if n > bestN {
			best, bestN = fam, n
		}
	}
	return best
}

// fillTopPaths breaks down page_view events by the path stashed in ref.
// Useful operator signal for "where do visitors actually go" - which is
// often more interesting than which articles get clicked.
func (a *Analytics) fillTopPaths(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	q := `
		SELECT ref, COUNT(*) FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)
		  AND ref IS NOT NULL AND ref != ''` + ef.Clause("") + `
		GROUP BY ref ORDER BY COUNT(*) DESC LIMIT 15
	`
	rows, err := a.db.Query(q, EvPageView, since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ref string
		var n int
		if err := rows.Scan(&ref, &n); err != nil {
			return err
		}
		s.TopPaths = append(s.TopPaths, TopRef{Ref: ref, Label: ref, Count: n})
	}
	return rows.Err()
}

// fillHourly returns a 24-bucket histogram of event counts grouped by
// UTC hour of day, over the last 7 days. With only a day or two of data
// it still tells you when your users hit; with more data the shape
// stabilises into a daily rhythm.
func (a *Analytics) fillHourly(s *Summary, ef *excludeFilter) error {
	buckets := make(map[int]int, 24)
	q := `
		SELECT CAST(strftime('%H', ts) AS INTEGER) AS hr, COUNT(*)
		FROM events
		WHERE ts >= datetime('now', '-7 days')` + ef.Clause("") + `
		GROUP BY hr
	`
	rows, err := a.db.Query(q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hr, n int
		if err := rows.Scan(&hr, &n); err != nil {
			return err
		}
		buckets[hr] = n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.Hourly = make([]HourCount, 24)
	for h := 0; h < 24; h++ {
		s.Hourly[h] = HourCount{Hour: h, Count: buckets[h]}
	}
	return nil
}

// fillSinceLaunch pulls raw totals across the entire events table so the
// dashboard can show "all time" stats alongside windowed ones. Means a
// 30-day-window screenshot still conveys total scale.
func (a *Analytics) fillSinceLaunch(s *Summary, ef *excludeFilter) error {
	var firstTS sql.NullString
	excl := ef.Clause("")
	q := `
		SELECT
		  (SELECT COUNT(*) FROM events WHERE 1=1` + excl + `),
		  (SELECT COUNT(DISTINCT session) FROM events WHERE session IS NOT NULL` + excl + `),
		  (SELECT COUNT(DISTINCT user_id) FROM events WHERE user_id IS NOT NULL` + excl + `),
		  (SELECT MIN(ts) FROM events WHERE 1=1` + excl + `)
	`
	if err := a.db.QueryRow(q).Scan(&s.SinceLaunch.Events, &s.SinceLaunch.Sessions, &s.SinceLaunch.SignedIn, &firstTS); err != nil {
		return err
	}
	if firstTS.Valid && firstTS.String != "" {
		// SQLite returns the default DATETIME format here.
		layouts := []string{
			"2006-01-02 15:04:05",
			"2006-01-02 15:04:05.999999999",
			time.RFC3339,
		}
		for _, l := range layouts {
			if t, err := time.Parse(l, firstTS.String); err == nil {
				s.SinceLaunch.FirstEvent = t.Unix()
				break
			}
		}
	}
	return nil
}

func (a *Analytics) fillActive(s *Summary, ef *excludeFilter) error {
	excl := ef.Clause("")
	q := `
		SELECT
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-1 day')
		       AND COALESCE(user_id, session) IS NOT NULL` + excl + `),
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-7 days')
		       AND COALESCE(user_id, session) IS NOT NULL` + excl + `),
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-30 days')
		       AND COALESCE(user_id, session) IS NOT NULL` + excl + `),
		  (SELECT COUNT(*) FROM users
		     WHERE pro_until IS NOT NULL AND pro_until > datetime('now'))
	`
	row := a.db.QueryRow(q)
	return row.Scan(&s.Active.DAU, &s.Active.WAU, &s.Active.MAU, &s.Active.ProActive)
}

func (a *Analytics) fillFunnel(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	q := `
		SELECT
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END),
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END),
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END)
		FROM events
		WHERE ts >= datetime('now', ?)` + ef.Clause("")
	row := a.db.QueryRow(q, EvProView, EvProCheckoutStart, EvProSubscribeSuccess, since)
	var v, c, sub sql.NullInt64
	if err := row.Scan(&v, &c, &sub); err != nil {
		return err
	}
	s.Funnel.Views = int(v.Int64)
	s.Funnel.Checkouts = int(c.Int64)
	s.Funnel.Subscribes = int(sub.Int64)
	return nil
}

func (a *Analytics) fillEventCounts(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	q := `
		SELECT event, COUNT(*) FROM events
		WHERE ts >= datetime('now', ?)` + ef.Clause("") + `
		GROUP BY event ORDER BY COUNT(*) DESC
	`
	rows, err := a.db.Query(q, since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ev string
		var n int
		if err := rows.Scan(&ev, &n); err != nil {
			return err
		}
		s.EventCounts[ev] = n
	}
	return rows.Err()
}

func (a *Analytics) fillTopRef(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)

	// Top articles: join to articles table for title + source so the
	// dashboard can render something legible rather than a bare ID.
	artQ := `
		SELECT e.ref, COALESCE(a.title, ''), COALESCE(a.source, ''), COUNT(*) AS n
		FROM events e
		LEFT JOIN articles a ON a.id = CAST(e.ref AS INTEGER)
		WHERE e.event = ?
		  AND e.ts >= datetime('now', ?)
		  AND e.ref IS NOT NULL AND e.ref != ''` + ef.Clause("e") + `
		GROUP BY e.ref
		ORDER BY n DESC
		LIMIT 20
	`
	articleRows, err := a.db.Query(artQ, EvArticleOpen, since)
	if err != nil {
		return err
	}
	defer articleRows.Close()
	for articleRows.Next() {
		var ref, title, source string
		var n int
		if err := articleRows.Scan(&ref, &title, &source, &n); err != nil {
			return err
		}
		label := title
		if source != "" {
			label = source + " · " + title
		}
		if label == "" {
			label = "article #" + ref
		}
		s.TopArticles = append(s.TopArticles, TopRef{Ref: ref, Label: label, Count: n})
	}
	if err := articleRows.Err(); err != nil {
		return err
	}

	// Top CVEs, actors, malware: simple group-by-ref. Labels match the ref.
	cves, err := a.topByEvent(EvCVEModalOpen, since, 20, ef)
	if err != nil {
		return err
	}
	s.TopCVEs = cves

	actors, err := a.topByEvent(EvActorChipOpen, since, 15, ef)
	if err != nil {
		return err
	}
	s.TopActors = actors

	malware, err := a.topByEvent(EvMalwareChipOpen, since, 15, ef)
	if err != nil {
		return err
	}
	s.TopMalware = malware
	return nil
}

func (a *Analytics) topByEvent(event, since string, limit int, ef *excludeFilter) ([]TopRef, error) {
	q := `
		SELECT ref, COUNT(*) AS n FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)
		  AND ref IS NOT NULL AND ref != ''` + ef.Clause("") + `
		GROUP BY ref ORDER BY n DESC LIMIT ?
	`
	rows, err := a.db.Query(q, event, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TopRef
	for rows.Next() {
		var ref string
		var n int
		if err := rows.Scan(&ref, &n); err != nil {
			return nil, err
		}
		out = append(out, TopRef{Ref: ref, Label: ref, Count: n})
	}
	return out, rows.Err()
}

func (a *Analytics) fillDailyVolume(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	q := `
		SELECT date(ts) AS d, COUNT(*) FROM events
		WHERE ts >= datetime('now', ?)` + ef.Clause("") + `
		GROUP BY d ORDER BY d ASC
	`
	rows, err := a.db.Query(q, since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return err
		}
		s.DailyVolume = append(s.DailyVolume, DayCount{Date: d, Count: n})
	}
	return rows.Err()
}

func (a *Analytics) fillAttackExports(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	q := `
		SELECT date(ts) AS d, COUNT(*) FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)` + ef.Clause("") + `
		GROUP BY d ORDER BY d ASC
	`
	rows, err := a.db.Query(q, EvAttackExport, since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return err
		}
		s.AttackExports = append(s.AttackExports, DayCount{Date: d, Count: n})
	}
	return rows.Err()
}

// surfacePaths drives the public-engagement view. Two flavours:
//   - exact: one row per literal path (e.g. /live, /trending)
//   - cve:   one aggregated row across every /cve/<id> hit
//
// Add a surface here when a new public-facing route gets meaningful
// traffic; remove when it stops mattering.
var surfacePaths = []struct {
	Label  string
	Match  string // either "exact" or "cve" - cve uses LIKE '/cve/%'
	Source string // SQL literal for the matcher
}{
	{Label: "/", Match: "exact", Source: "/"},
	{Label: "/live", Match: "exact", Source: "/live"},
	{Label: "/trending", Match: "exact", Source: "/trending"},
	{Label: "/pre-kev", Match: "exact", Source: "/pre-kev"},
	{Label: "/api", Match: "exact", Source: "/api"},
	{Label: "/cve/*", Match: "cve", Source: ""},
	{Label: "/app", Match: "exact", Source: "/app"},
	{Label: "/pro", Match: "exact", Source: "/pro"},
}

// fillPublicSurfaces computes per-path engagement. Browser-shaped views
// uses the same UA bucketer as BotSignals so the two views agree on
// "is this human traffic". Sessions and IPs are distinct counts.
func (a *Analytics) fillPublicSurfaces(s *Summary, days int, ef *excludeFilter) error {
	since := fmt.Sprintf("-%d days", days)
	excl := ef.Clause("")

	for _, sp := range surfacePaths {
		var where string
		var args []any
		if sp.Match == "cve" {
			where = "ref LIKE '/cve/%'"
		} else {
			where = "ref = ?"
			args = append(args, sp.Source)
		}
		args = append(args, since)

		// One pass collects total + distinct counts; second pass collects
		// per-row UAs so we can classify browser vs bot views consistently
		// with BotSignals. Total path event count is bounded so streaming
		// the rows for UA bucketing is acceptable.
		q := `
			SELECT COUNT(*),
			       COUNT(DISTINCT session),
			       COUNT(DISTINCT ip_hash)
			FROM events
			WHERE event = 'page_view'
			  AND ` + where + `
			  AND ts >= datetime('now', ?)` + excl
		var views, sessions, ips int
		if err := a.db.QueryRow(q, args...).Scan(&views, &sessions, &ips); err != nil {
			return err
		}

		// Browser share is computed over events that HAVE a UA only.
		// Pre-migration rows (NULL UA) are excluded so the denominator
		// reflects what we can actually classify.
		var browser, captured int
		if views > 0 {
			uaQ := `
				SELECT user_agent, COUNT(*)
				FROM events
				WHERE event = 'page_view'
				  AND ` + where + `
				  AND ts >= datetime('now', ?)
				  AND user_agent IS NOT NULL
				  AND user_agent != ''` + excl + `
				GROUP BY user_agent
			`
			uaRows, err := a.db.Query(uaQ, args...)
			if err != nil {
				return err
			}
			for uaRows.Next() {
				var ua string
				var n int
				if err := uaRows.Scan(&ua, &n); err != nil {
					uaRows.Close()
					return err
				}
				captured += n
				if isBrowserFamily(uaFamily(ua)) {
					browser += n
				}
			}
			uaRows.Close()
		}

		vps := "-"
		if sessions > 0 {
			vps = fmt.Sprintf("%.1f", float64(views)/float64(sessions))
		}
		share := "-"
		if captured > 0 {
			share = fmt.Sprintf("%.0f%%", 100.0*float64(browser)/float64(captured))
		}
		s.PublicSurfaces = append(s.PublicSurfaces, SurfaceRow{
			Path:                sp.Label,
			Views:               views,
			BrowserViews:        browser,
			CapturedUAViews:     captured,
			DistinctSessions:    sessions,
			DistinctIPs:         ips,
			ViewsPerSession:     vps,
			BrowserSharePercent: share,
		})
	}
	return nil
}
