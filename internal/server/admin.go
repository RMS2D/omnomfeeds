package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"runtime"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/auth"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Admin dashboard: a separate /admin page + /api/admin/stats JSON feed.
// Both are gated by the same checks: signed-in + IsAdmin per the
// ADMIN_EMAILS env. Anonymous visitors get bounced to /login.html;
// signed-in non-admins get bounced to /app.

// processStart is captured once at first import so uptime is real.
var processStart = time.Now()

// handleAdminPage serves web/admin.html with an HTML-level redirect for
// non-admins so the dashboard shell never reaches them. The JSON endpoint
// behind it ALSO enforces admin, so a hand-crafted XHR can't sidestep this.
func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request, webFS fs.FS) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login.html?next=/admin", http.StatusSeeOther)
		return
	}
	if !u.IsAdmin {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	serveEmbeddedFile(w, r, webFS, "admin.html")
}

type adminStatsResp struct {
	Service struct {
		UptimeSec  int64  `json:"uptime_sec"`
		StartedAt  string `json:"started_at"`
		HostedMode bool   `json:"hosted_mode"`
		GoVersion  string `json:"go_version"`
		Goroutines int    `json:"goroutines"`
		MemMB      uint64 `json:"mem_mb"`
	} `json:"service"`

	Users struct {
		Total        int `json:"total"`
		Last7Days    int `json:"last_7_days"`
		ProActive    int `json:"pro_active"`
		MagicLinks24 int `json:"magic_links_last_24h"`
	} `json:"users"`

	Articles struct {
		Total int `json:"total"`
		Day   int `json:"last_24h"`
	} `json:"articles"`

	Sources struct {
		Total     int                    `json:"total"`
		Erroring  int                    `json:"erroring"`
		Stale     int                    `json:"stale"`
		PerSource []*models.SourceStatus `json:"per_source"`
	} `json:"sources"`

	RecentSignups []adminUserRow `json:"recent_signups"`
	ProUsers      []adminUserRow `json:"pro_users"`
}

type adminUserRow struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	IDProvider  string `json:"id_provider"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at"`
	ProUntil    string `json:"pro_until,omitempty"`
}

func packAdminUser(u storage.AdminUserRow) adminUserRow {
	r := adminUserRow{
		ID:          u.ID,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		IDProvider:  u.IDProvider,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339),
		LastSeenAt:  u.LastSeenAt.UTC().Format(time.RFC3339),
	}
	if u.ProUntil != nil {
		r.ProUntil = u.ProUntil.UTC().Format(time.RFC3339)
	}
	return r
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	resp := adminStatsResp{}

	resp.Service.UptimeSec = int64(time.Since(processStart).Seconds())
	resp.Service.StartedAt = processStart.UTC().Format(time.RFC3339)
	resp.Service.HostedMode = s.cfg.Hosted.Enabled
	resp.Service.GoVersion = runtime.Version()
	resp.Service.Goroutines = runtime.NumGoroutine()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	resp.Service.MemMB = ms.Alloc / 1024 / 1024

	stats := s.store.CountAdminStats()
	resp.Users.Total = stats.TotalUsers
	resp.Users.Last7Days = stats.UsersLast7Days
	resp.Users.ProActive = stats.ProActiveCount
	resp.Users.MagicLinks24 = stats.MagicLinksLast24h
	resp.Articles.Total = stats.ArticlesTotal
	resp.Articles.Day = stats.ArticlesLast24h

	now := time.Now()
	erroring, stale := 0, 0
	s.statusMu.RLock()
	per := make([]*models.SourceStatus, 0, len(s.status))
	for _, st := range s.status {
		per = append(per, st)
		if st.LastError != "" {
			erroring++
		}
		if !st.LastFetch.IsZero() && now.Sub(st.LastFetch) > 30*time.Minute {
			stale++
		}
	}
	s.statusMu.RUnlock()
	resp.Sources.Total = len(per)
	resp.Sources.Erroring = erroring
	resp.Sources.Stale = stale
	resp.Sources.PerSource = per

	if rows, err := s.store.RecentSignups(25); err == nil {
		resp.RecentSignups = make([]adminUserRow, 0, len(rows))
		for _, u := range rows {
			resp.RecentSignups = append(resp.RecentSignups, packAdminUser(u))
		}
	}
	if rows, err := s.store.ProSubscribers(100); err == nil {
		resp.ProUsers = make([]adminUserRow, 0, len(rows))
		for _, u := range rows {
			resp.ProUsers = append(resp.ProUsers, packAdminUser(u))
		}
	}

	writeJSON(w, 200, resp)
}

// uptimeHuman renders a duration as "3d 4h 12m". Exposed for any future
// server-rendered admin email digest; the dashboard JSON ships raw seconds
// and formats client-side.
func uptimeHuman(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

var _ = uptimeHuman
