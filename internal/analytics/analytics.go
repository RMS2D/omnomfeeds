// Package analytics is the in-house event log. We capture which features
// users actually touch so we know what's worth keeping and what's worth
// killing. No third-party JS, no IPs, no UAs. Anonymous traffic is
// de-duplicated via an opaque session cookie. Signed-in users are
// recorded by user_id alongside the same session cookie so we can stitch
// pre-login activity to a converted account.
//
// Volumes are intentionally modest: a few events per page view. SQLite
// WAL handles the write rate at our scale without batching. If this ever
// changes, switch Emit() to push onto a channel that a goroutine drains
// into a multi-row INSERT.
package analytics

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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

// Emit writes one event. Failures are logged, never returned to the caller -
// analytics must never break a user-facing request. meta may be nil, a
// string, or any JSON-serialisable value; non-string values are marshalled.
func (a *Analytics) Emit(userID, session, event, ref string, meta any) {
	if a == nil || a.db == nil || event == "" {
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
	var userIDArg, sessionArg, refArg sql.NullString
	if userID != "" {
		userIDArg = sql.NullString{String: userID, Valid: true}
	}
	if session != "" {
		sessionArg = sql.NullString{String: session, Valid: true}
	}
	if ref != "" {
		refArg = sql.NullString{String: ref, Valid: true}
	}
	_, err := a.db.Exec(
		`INSERT INTO events (user_id, session, event, ref, meta) VALUES (?, ?, ?, ?, ?)`,
		userIDArg, sessionArg, event, refArg, metaStr,
	)
	if err != nil {
		log.Printf("[analytics] emit %s: %v", event, err)
	}
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

// --- Query API (used by the admin dashboard) ---

// Summary is the single payload the dashboard renders. One round trip;
// the dashboard does no further fan-out.
type Summary struct {
	GeneratedAt   time.Time              `json:"generated_at"`
	WindowDays    int                    `json:"window_days"`
	Active        ActiveCounts           `json:"active"`
	Funnel        ProFunnel              `json:"funnel"`
	EventCounts   map[string]int         `json:"event_counts"`
	TopArticles   []TopRef               `json:"top_articles"`
	TopCVEs       []TopRef               `json:"top_cves"`
	TopActors     []TopRef               `json:"top_actors"`
	TopMalware    []TopRef               `json:"top_malware"`
	TopPaths      []TopRef               `json:"top_paths"`       // page_view breakdown by path
	AttackExports []DayCount             `json:"attack_exports_daily"`
	DailyVolume   []DayCount             `json:"daily_volume"`
	Hourly        []HourCount            `json:"hourly_24"`       // last 7d, bucketed by UTC hour
	SinceLaunch   SinceLaunchTotals      `json:"since_launch"`    // raw totals so sparse windows still tell a story
}

type ActiveCounts struct {
	DAU       int `json:"dau"`        // distinct (user_id|session) in last 24h
	WAU       int `json:"wau"`        // last 7d
	MAU       int `json:"mau"`        // last 30d
	ProActive int `json:"pro_active"` // current paying users from users.pro_until
}

type ProFunnel struct {
	Views     int `json:"views"`
	Checkouts int `json:"checkouts"`
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
	Hour  int `json:"hour"`  // 0-23 UTC
	Count int `json:"count"`
}

type SinceLaunchTotals struct {
	Events     int64 `json:"events"`
	Sessions   int64 `json:"sessions"`
	SignedIn   int64 `json:"signed_in"`
	FirstEvent int64 `json:"first_event_unix"` // 0 if no events yet
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
	if err := a.fillActive(s); err != nil {
		return nil, err
	}
	if err := a.fillFunnel(s, days); err != nil {
		return nil, err
	}
	if err := a.fillEventCounts(s, days); err != nil {
		return nil, err
	}
	if err := a.fillTopRef(s, days); err != nil {
		return nil, err
	}
	if err := a.fillDailyVolume(s, days); err != nil {
		return nil, err
	}
	if err := a.fillAttackExports(s, days); err != nil {
		return nil, err
	}
	if err := a.fillTopPaths(s, days); err != nil {
		return nil, err
	}
	if err := a.fillHourly(s); err != nil {
		return nil, err
	}
	if err := a.fillSinceLaunch(s); err != nil {
		return nil, err
	}
	return s, nil
}

// fillTopPaths breaks down page_view events by the path stashed in ref.
// Useful operator signal for "where do visitors actually go" - which is
// often more interesting than which articles get clicked.
func (a *Analytics) fillTopPaths(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)
	rows, err := a.db.Query(`
		SELECT ref, COUNT(*) FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)
		  AND ref IS NOT NULL AND ref != ''
		GROUP BY ref ORDER BY COUNT(*) DESC LIMIT 15
	`, EvPageView, since)
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
func (a *Analytics) fillHourly(s *Summary) error {
	buckets := make(map[int]int, 24)
	rows, err := a.db.Query(`
		SELECT CAST(strftime('%H', ts) AS INTEGER) AS hr, COUNT(*)
		FROM events
		WHERE ts >= datetime('now', '-7 days')
		GROUP BY hr
	`)
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
func (a *Analytics) fillSinceLaunch(s *Summary) error {
	var firstTS sql.NullString
	if err := a.db.QueryRow(`
		SELECT
		  (SELECT COUNT(*) FROM events),
		  (SELECT COUNT(DISTINCT session) FROM events WHERE session IS NOT NULL),
		  (SELECT COUNT(DISTINCT user_id) FROM events WHERE user_id IS NOT NULL),
		  (SELECT MIN(ts) FROM events)
	`).Scan(&s.SinceLaunch.Events, &s.SinceLaunch.Sessions, &s.SinceLaunch.SignedIn, &firstTS); err != nil {
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

func (a *Analytics) fillActive(s *Summary) error {
	row := a.db.QueryRow(`
		SELECT
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-1 day')
		       AND COALESCE(user_id, session) IS NOT NULL),
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-7 days')
		       AND COALESCE(user_id, session) IS NOT NULL),
		  (SELECT COUNT(DISTINCT COALESCE(user_id, session))
		     FROM events WHERE ts >= datetime('now','-30 days')
		       AND COALESCE(user_id, session) IS NOT NULL),
		  (SELECT COUNT(*) FROM users
		     WHERE pro_until IS NOT NULL AND pro_until > datetime('now'))
	`)
	return row.Scan(&s.Active.DAU, &s.Active.WAU, &s.Active.MAU, &s.Active.ProActive)
}

func (a *Analytics) fillFunnel(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)
	row := a.db.QueryRow(`
		SELECT
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END),
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END),
		  SUM(CASE WHEN event = ? THEN 1 ELSE 0 END)
		FROM events
		WHERE ts >= datetime('now', ?)
	`, EvProView, EvProCheckoutStart, EvProSubscribeSuccess, since)
	var v, c, sub sql.NullInt64
	if err := row.Scan(&v, &c, &sub); err != nil {
		return err
	}
	s.Funnel.Views = int(v.Int64)
	s.Funnel.Checkouts = int(c.Int64)
	s.Funnel.Subscribes = int(sub.Int64)
	return nil
}

func (a *Analytics) fillEventCounts(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)
	rows, err := a.db.Query(`
		SELECT event, COUNT(*) FROM events
		WHERE ts >= datetime('now', ?)
		GROUP BY event ORDER BY COUNT(*) DESC
	`, since)
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

func (a *Analytics) fillTopRef(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)

	// Top articles: join to articles table for title + source so the
	// dashboard can render something legible rather than a bare ID.
	articleRows, err := a.db.Query(`
		SELECT e.ref, COALESCE(a.title, ''), COALESCE(a.source, ''), COUNT(*) AS n
		FROM events e
		LEFT JOIN articles a ON a.id = CAST(e.ref AS INTEGER)
		WHERE e.event = ?
		  AND e.ts >= datetime('now', ?)
		  AND e.ref IS NOT NULL AND e.ref != ''
		GROUP BY e.ref
		ORDER BY n DESC
		LIMIT 20
	`, EvArticleOpen, since)
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
	cves, err := a.topByEvent(EvCVEModalOpen, since, 20)
	if err != nil {
		return err
	}
	s.TopCVEs = cves

	actors, err := a.topByEvent(EvActorChipOpen, since, 15)
	if err != nil {
		return err
	}
	s.TopActors = actors

	malware, err := a.topByEvent(EvMalwareChipOpen, since, 15)
	if err != nil {
		return err
	}
	s.TopMalware = malware
	return nil
}

func (a *Analytics) topByEvent(event, since string, limit int) ([]TopRef, error) {
	rows, err := a.db.Query(`
		SELECT ref, COUNT(*) AS n FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)
		  AND ref IS NOT NULL AND ref != ''
		GROUP BY ref ORDER BY n DESC LIMIT ?
	`, event, since, limit)
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

func (a *Analytics) fillDailyVolume(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)
	rows, err := a.db.Query(`
		SELECT date(ts) AS d, COUNT(*) FROM events
		WHERE ts >= datetime('now', ?)
		GROUP BY d ORDER BY d ASC
	`, since)
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

func (a *Analytics) fillAttackExports(s *Summary, days int) error {
	since := fmt.Sprintf("-%d days", days)
	rows, err := a.db.Query(`
		SELECT date(ts) AS d, COUNT(*) FROM events
		WHERE event = ?
		  AND ts >= datetime('now', ?)
		GROUP BY d ORDER BY d ASC
	`, EvAttackExport, since)
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
