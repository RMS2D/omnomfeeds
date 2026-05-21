package server

import (
	"net/http"
	"strconv"

	"github.com/RMS2D/omnomfeeds/internal/analytics"
	"github.com/RMS2D/omnomfeeds/internal/auth"
)

// emit is the per-request analytics shim. It pulls the user (if any) and
// the session token from the request and forwards to analytics.Emit. Safe
// to call on every handler entry - the analytics field is nil-safe.
//
// Callers should pass an empty ref for "no associated entity" events
// (page_view, pro_view) and a domain-specific string otherwise
// (article_id as decimal, cve_id, actor_slug).
func (s *Server) emit(w http.ResponseWriter, r *http.Request, event, ref string, meta any) {
	if s.analytics == nil {
		return
	}
	var userID string
	if u := auth.UserFromContext(r.Context()); u != nil {
		userID = u.ID
	}
	// Read-only read first so health probes and bots don't get cookies
	// they didn't ask for. Set a cookie only if we already have a session
	// or the caller asked us to via EnsureSession upstream.
	session := analytics.SessionFromRequest(r)
	if session == "" && w != nil {
		session = s.analytics.EnsureSession(w, r)
	}
	s.analytics.Emit(userID, session, event, ref, meta)
}

// handleAdminAnalyticsSummary returns the dashboard's single JSON payload.
// Window comes from ?days= (defaults to 30, clamped to 365).
func (s *Server) handleAdminAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	if s.analytics == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "analytics disabled"})
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	sum, err := s.analytics.BuildSummary(days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
