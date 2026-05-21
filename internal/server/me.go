package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/analytics"
	"github.com/RMS2D/omnomfeeds/internal/auth"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Per-user state sync endpoints. All require an authenticated session and
// are wired in server.New() behind auth.RequireUser. The frontend mirrors
// localStorage state up here so the same account on a second device picks
// up settings, bookmarks, and read marks.

// Bounded body size; settings + bookmark JSON payloads should never grow
// past this. Keeps memory predictable per request.
const meMaxBody = 256 * 1024

// --- Settings (single opaque JSON blob) ---

func (s *Server) handleMeSettings(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		blob, err := s.store.GetSettings(u.ID)
		if err != nil {
			http.Error(w, "settings read failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(blob))
	case http.MethodPut:
		body, err := readBoundedJSON(w, r)
		if err != nil {
			return
		}
		if err := s.store.PutSettings(u.ID, string(body)); err != nil {
			http.Error(w, "settings write failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// --- Bookmarks ---

func (s *Server) handleMeBookmarks(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		ids, err := s.store.ListBookmarkIDs(u.ID)
		if err != nil {
			http.Error(w, "bookmark read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"ids": ids})

	case http.MethodPost:
		id, err := decodeArticleID(w, r)
		if err != nil {
			return
		}
		if err := s.store.AddBookmark(u.ID, id); err != nil {
			http.Error(w, "bookmark write failed", http.StatusInternalServerError)
			return
		}
		s.emit(w, r, analytics.EvBookmarkAdd, strconv.FormatInt(id, 10), nil)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		// Accept the id either in the URL path (/api/me/bookmarks/123) or
		// as ?id=123, so the frontend can use either calling style.
		idStr := strings.TrimPrefix(r.URL.Path, "/api/me/bookmarks/")
		if idStr == r.URL.Path || idStr == "" {
			idStr = r.URL.Query().Get("id")
		}
		id, perr := strconv.ParseInt(idStr, 10, 64)
		if perr != nil {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := s.store.RemoveBookmark(u.ID, id); err != nil {
			http.Error(w, "bookmark delete failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "GET, POST, or DELETE only", http.StatusMethodNotAllowed)
	}
}

// --- Read state ---

func (s *Server) handleMeRead(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		ids, err := s.store.ListReadIDs(u.ID, 0)
		if err != nil {
			http.Error(w, "read state read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"ids": ids})

	case http.MethodPost:
		id, err := decodeArticleID(w, r)
		if err != nil {
			return
		}
		if err := s.store.MarkReadForUser(u.ID, id); err != nil {
			http.Error(w, "read state write failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// --- Per-user Bluesky watched accounts ---

// handleMeBskyAccounts owns the per-user watched-handle list.
//   GET  -> {"handles": [...]}
//   POST {"action":"add","handle":"x.bsky.social"}        -> add one
//   POST {"action":"remove","handle":"x.bsky.social"}     -> remove one
//   POST {"action":"add_bulk","handles":["a","b","c"]}    -> batch add
//
// Free-tier intentional: curating your own researcher list is the
// fastest path to value for a new signup. Pro is reserved for features
// with ongoing per-user infrastructure cost (custom webhook alerts,
// digest email, AI personalisation). Storage is capped per user (see
// userBskyAccountsCap) so we can't be DoS'd by a runaway script.
const userBskyAccountsCap = 100

func (s *Server) handleMeBskyAccounts(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		handles, err := s.store.ListUserBskyAccounts(u.ID)
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"handles": handles})

	case http.MethodPost:
		var body struct {
			Action  string   `json:"action"`
			Handle  string   `json:"handle"`
			Handles []string `json:"handles"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// Pre-count existing handles once; add / add_bulk both enforce
		// the per-user cap to keep an abuser from accumulating an
		// arbitrarily large watched list.
		existing, _ := s.store.ListUserBskyAccounts(u.ID)
		used := len(existing)

		switch body.Action {
		case "add":
			h := normalizeHandle(body.Handle)
			if h == "" {
				http.Error(w, "handle required", http.StatusBadRequest)
				return
			}
			if used >= userBskyAccountsCap {
				http.Error(w, fmt.Sprintf("watched-account cap reached (%d). remove one before adding another.", userBskyAccountsCap), http.StatusForbidden)
				return
			}
			if err := s.store.AddUserBskyAccount(u.ID, h); err != nil {
				http.Error(w, "add failed", http.StatusInternalServerError)
				return
			}
		case "remove":
			h := normalizeHandle(body.Handle)
			if h == "" {
				http.Error(w, "handle required", http.StatusBadRequest)
				return
			}
			if err := s.store.RemoveUserBskyAccount(u.ID, h); err != nil {
				http.Error(w, "remove failed", http.StatusInternalServerError)
				return
			}
		case "add_bulk":
			if len(body.Handles) > 1000 {
				http.Error(w, "too many handles", http.StatusBadRequest)
				return
			}
			cleaned := make([]string, 0, len(body.Handles))
			for _, raw := range body.Handles {
				if h := normalizeHandle(raw); h != "" {
					cleaned = append(cleaned, h)
				}
			}
			// Trim the bulk request to fit under the cap. We could 403,
			// but the friendlier UX is to accept up to the cap and tell
			// the caller how many we kept.
			if used+len(cleaned) > userBskyAccountsCap {
				room := userBskyAccountsCap - used
				if room < 0 {
					room = 0
				}
				if room == 0 {
					http.Error(w, fmt.Sprintf("watched-account cap reached (%d). remove some before adding more.", userBskyAccountsCap), http.StatusForbidden)
					return
				}
				cleaned = cleaned[:room]
			}
			if _, err := s.store.AddBulkUserBskyAccounts(u.ID, cleaned); err != nil {
				http.Error(w, "bulk add failed", http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "action must be add, remove, or add_bulk", http.StatusBadRequest)
			return
		}
		// Always return the fresh list so the client can update its view.
		handles, _ := s.store.ListUserBskyAccounts(u.ID)
		writeJSON(w, 200, map[string]any{"ok": true, "handles": handles})

	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// normalizeHandle strips a leading @ and surrounding whitespace. Bluesky
// handles are case-insensitive at the protocol level; lower-casing keeps
// the dedup join simple.
func normalizeHandle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	return strings.ToLower(s)
}

// --- Email digest preference (Pro) ---
//
//	GET  /api/me/digest        -> {"frequency", "last_sent_at"}
//	POST /api/me/digest {freq} -> {"ok":true, "frequency"}
//
// frequency ∈ {off, daily, weekly}. The worker (digestmail.Worker) ticks
// every 30min and uses ListEmailDigestDue to find subscribers due for
// a send.
func (s *Server) handleMeDigest(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, err := s.store.GetEmailDigestPref(u.ID)
		if err != nil {
			http.Error(w, "fetch failed", http.StatusInternalServerError)
			return
		}
		resp := map[string]any{"frequency": p.Frequency}
		if p.LastSentAt != nil {
			resp["last_sent_at"] = p.LastSentAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, 200, resp)

	case http.MethodPost:
		var body struct {
			Frequency string `json:"frequency"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		f := strings.ToLower(strings.TrimSpace(body.Frequency))
		switch f {
		case "off", "daily", "weekly":
		default:
			http.Error(w, "frequency must be off, daily, or weekly", http.StatusBadRequest)
			return
		}
		if err := s.store.PutEmailDigestPref(u.ID, f); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "frequency": f})

	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// --- AI personalization (Pro) ---
//
//	POST /api/me/personalize {profile, article_ids[]}
//	    -> {sorted_ids: [...]}  (Pro-gated, no caching, ~$0.008 per call)
//
// The frontend captures the user's profile separately (settings JSON);
// the endpoint takes profile + a batch of article ids, looks up each
// article's title + summary, builds the prompt, calls the AI, and
// returns the ids sorted by relevance. The frontend then re-orders the
// visible list.
func (s *Server) handleMePersonalize(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.enrich == nil || s.enrich.AI == nil {
		http.Error(w, "no AI provider configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Profile    string  `json:"profile"`
		ArticleIDs []int64 `json:"article_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	profile := strings.TrimSpace(body.Profile)
	if profile == "" {
		http.Error(w, "profile required", http.StatusBadRequest)
		return
	}
	if len(body.ArticleIDs) == 0 {
		writeJSON(w, 200, map[string]any{"sorted_ids": []int64{}})
		return
	}
	// Cap the batch so a runaway client can't blow LLM cost.
	if len(body.ArticleIDs) > 80 {
		body.ArticleIDs = body.ArticleIDs[:80]
	}

	// Pull title + summary for each id. One query, IN clause.
	placeholders := make([]string, len(body.ArticleIDs))
	args := make([]any, len(body.ArticleIDs))
	for i, id := range body.ArticleIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := s.store.DB().Query(
		"SELECT id, title, COALESCE(summary,'') FROM articles WHERE id IN ("+strings.Join(placeholders, ",")+")",
		args...,
	)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var items []ai.ClusterItem
	for rows.Next() {
		var it ai.ClusterItem
		if err := rows.Scan(&it.ID, &it.Title, &it.Summary); err != nil {
			http.Error(w, "scan error", http.StatusInternalServerError)
			return
		}
		items = append(items, it)
	}
	if len(items) == 0 {
		writeJSON(w, 200, map[string]any{"sorted_ids": []int64{}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	sorted, err := s.enrich.AI.RankForProfile(ctx, profile, items)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "provider": s.enrich.AI.Name()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"sorted_ids": sorted,
		"provider":   s.enrich.AI.Name(),
	})
}

// --- Per-user webhook alert rules (Pro) ---

// handleMeAlerts manages the calling user's webhook-alert rules. Pro-gated
// in hosted mode; in self-host the rules table is per-user but there's
// only one user (the operator) so it's open.
//
//	GET                                  -> {"rules":[...]}
//	POST {kind, pattern, channel, target} -> create, returns rule
//	POST {id, kind, pattern, channel, target, enabled} -> upsert (id present)
//	DELETE /api/me/alerts/<id>           -> remove
func (s *Server) handleMeAlerts(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	// Pro gate. Admins pass via IsPro() short-circuit.
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.ListAlertRules(u.ID)
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"rules": packAlertRules(rules)})

	case http.MethodPost:
		var body struct {
			ID            string `json:"id"`
			Kind          string `json:"kind"`
			Pattern       string `json:"pattern"`
			Channel       string `json:"channel"`
			ChannelTarget string `json:"channel_target"`
			Enabled       *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		body.Kind = strings.ToLower(strings.TrimSpace(body.Kind))
		body.Channel = strings.ToLower(strings.TrimSpace(body.Channel))
		body.ChannelTarget = strings.TrimSpace(body.ChannelTarget)
		if !validAlertKind(body.Kind) {
			http.Error(w, "kind must be kev, keyword, cve, or tag", http.StatusBadRequest)
			return
		}
		if !validAlertChannel(body.Channel) {
			http.Error(w, "channel must be slack, discord, or generic", http.StatusBadRequest)
			return
		}
		if body.Kind != "kev" && strings.TrimSpace(body.Pattern) == "" {
			http.Error(w, "pattern required for non-KEV rules", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(body.ChannelTarget, "https://") {
			http.Error(w, "channel_target must be an https URL", http.StatusBadRequest)
			return
		}
		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		rule := storage.AlertRule{
			ID:            body.ID,
			UserID:        u.ID,
			Kind:          body.Kind,
			Pattern:       strings.TrimSpace(body.Pattern),
			Channel:       body.Channel,
			ChannelTarget: body.ChannelTarget,
			Enabled:       enabled,
		}
		if rule.ID == "" {
			if err := s.store.CreateAlertRule(rule); err != nil {
				http.Error(w, "create failed", http.StatusInternalServerError)
				return
			}
		} else {
			if err := s.store.UpdateAlertRule(rule); err != nil {
				http.Error(w, "update failed", http.StatusInternalServerError)
				return
			}
		}
		rules, _ := s.store.ListAlertRules(u.ID)
		writeJSON(w, 200, map[string]any{"ok": true, "rules": packAlertRules(rules)})

	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/me/alerts/")
		if id == r.URL.Path || id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteAlertRule(u.ID, id); err != nil {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "GET, POST, or DELETE only", http.StatusMethodNotAllowed)
	}
}

func validAlertKind(k string) bool {
	switch k {
	case "kev", "keyword", "cve", "tag":
		return true
	}
	return false
}

func validAlertChannel(c string) bool {
	switch c {
	case "slack", "discord", "generic":
		return true
	}
	return false
}

type alertRuleJSON struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Pattern       string `json:"pattern"`
	Channel       string `json:"channel"`
	ChannelTarget string `json:"channel_target"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
	LastFiredAt   string `json:"last_fired_at,omitempty"`
}

func packAlertRules(rows []storage.AlertRule) []alertRuleJSON {
	out := make([]alertRuleJSON, 0, len(rows))
	for _, r := range rows {
		j := alertRuleJSON{
			ID:            r.ID,
			Kind:          r.Kind,
			Pattern:       r.Pattern,
			Channel:       r.Channel,
			ChannelTarget: r.ChannelTarget,
			Enabled:       r.Enabled,
			CreatedAt:     r.CreatedAt.UTC().Format(time.RFC3339),
		}
		if r.LastFiredAt != nil {
			j.LastFiredAt = r.LastFiredAt.UTC().Format(time.RFC3339)
		}
		out = append(out, j)
	}
	return out
}

// --- Saved searches / channels (Pro) ---
//
//	GET    /api/me/channels                  -> {"channels":[...]}
//	POST   /api/me/channels {"name","query"} -> {"ok":true, "channels":[...]}
//	DELETE /api/me/channels/<id>             -> 204
func (s *Server) handleMeChannels(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := s.store.ListSavedSearches(u.ID)
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"channels": packChannels(rows)})

	case http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Query string `json:"query"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(body.Name)
		query := strings.TrimSpace(body.Query)
		if name == "" || query == "" {
			http.Error(w, "name and query required", http.StatusBadRequest)
			return
		}
		if len(name) > 60 {
			name = name[:60]
		}
		if len(query) > 200 {
			query = query[:200]
		}
		if _, err := s.store.CreateSavedSearch(u.ID, name, query); err != nil {
			http.Error(w, "create failed", http.StatusInternalServerError)
			return
		}
		rows, _ := s.store.ListSavedSearches(u.ID)
		writeJSON(w, 200, map[string]any{"ok": true, "channels": packChannels(rows)})

	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/me/channels/")
		if id == r.URL.Path || id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteSavedSearch(u.ID, id); err != nil {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "GET, POST, or DELETE only", http.StatusMethodNotAllowed)
	}
}

func packChannels(rows []storage.SavedSearch) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"id":         r.ID,
			"name":       r.Name,
			"query":      r.Query,
			"created_at": r.CreatedAt.UTC().Format(time.RFC3339),
			"sort_order": r.SortOrder,
		})
	}
	return out
}

// --- Per-user REST API tokens (Pro) ---
//
//	GET    /api/me/tokens          -> {"tokens":[...]}
//	POST   /api/me/tokens {"name"} -> {"token":"...", "row":{...}}  (token shown once)
//	DELETE /api/me/tokens/<id>     -> 204
//
// The bearer-token middleware in auth/auth.go accepts these tokens via the
// Authorization: Bearer <token> header, returning the same User context
// the cookie path produces. Admin-only and billing endpoints stay
// cookie-only because they enforce IsAdmin / cookie-specific flows.
func (s *Server) handleMeTokens(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	// Token management is browser-only on purpose: a stolen bearer token
	// must not be able to mint additional tokens. Cookie presence is the
	// proxy for "this is the actual user at their browser." The auth
	// middleware sets the cookie HttpOnly so JS / API consumers can't
	// spoof it.
	if _, err := r.Cookie("omnom_session"); err != nil {
		http.Error(w, "token operations require a browser session", http.StatusForbidden)
		return
	}
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := s.store.ListAPITokens(u.ID)
		if err != nil {
			http.Error(w, "list failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"tokens": packTokenRows(rows)})

	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if len(name) > 80 {
			name = name[:80]
		}
		token, tokenHash, err := newAPIToken()
		if err != nil {
			http.Error(w, "token gen failed", http.StatusInternalServerError)
			return
		}
		prefix := token
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		if _, err := s.store.CreateAPIToken(u.ID, name, tokenHash, prefix); err != nil {
			http.Error(w, "create failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{
			"token":  token,
			"name":   name,
			"prefix": prefix,
		})

	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/me/tokens/")
		if id == r.URL.Path || id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := s.store.RevokeAPIToken(u.ID, id); err != nil {
			http.Error(w, "revoke failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "GET, POST, or DELETE only", http.StatusMethodNotAllowed)
	}
}

func packTokenRows(rows []storage.APITokenRow) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		row := map[string]any{
			"id":         r.ID,
			"name":       r.Name,
			"prefix":     r.Prefix,
			"created_at": r.CreatedAt.UTC().Format(time.RFC3339),
		}
		if r.LastUsedAt != nil {
			row["last_used_at"] = r.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out
}

// newAPIToken mints a 32-byte URL-safe-base64 token and its SHA-256 hash.
// Same shape the auth session helper uses; the bearer middleware decodes +
// hashes incoming Authorization: Bearer values the same way.
func newAPIToken() (token string, hash []byte, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", nil, err
	}
	token = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)
	sum := sha256.Sum256(buf)
	return token, sum[:], nil
}

// --- helpers ---

// decodeArticleID accepts either {"id": 123} JSON or ?id=123 query string
// so callers can pick the style that fits their existing code path.
func decodeArticleID(w http.ResponseWriter, r *http.Request) (int64, error) {
	if q := r.URL.Query().Get("id"); q != "" {
		id, err := strconv.ParseInt(q, 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "bad id", http.StatusBadRequest)
			return 0, err
		}
		return id, nil
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return 0, err
	}
	if body.ID <= 0 {
		http.Error(w, "id required", http.StatusBadRequest)
		return 0, &httpError{}
	}
	return body.ID, nil
}

func readBoundedJSON(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body := http.MaxBytesReader(w, r.Body, meMaxBody)
	defer body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return nil, err
	}
	return raw, nil
}

type httpError struct{}

func (httpError) Error() string { return "http error" }

// --- "What changed while you were gone" banner ---

// handleMeWhatsNew powers a dismissible banner on the /app reader. GET
// returns either {dismissed: true} (if the user dismissed it in the last
// 24h) or {summary, since, article_count, generated_at}. POST writes
// the current time as the new dismiss timestamp so the banner stays
// hidden for the next 24h. Pro-gated; uses the same AI key as the daily
// brief. Cache key includes the dismiss timestamp so dismissing
// implicitly invalidates the cached summary.
const whatsNewCacheTTL = 6 * time.Hour
const whatsNewMaxLookback = 14 * 24 * time.Hour
const whatsNewQuietWindow = 24 * time.Hour

func (s *Server) handleMeWhatsNew(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	if s.cfg.Hosted.Enabled && !u.IsPro() {
		http.Error(w, "pro subscription required", http.StatusPaymentRequired)
		return
	}
	if s.enrich == nil || s.enrich.AI == nil {
		writeJSON(w, 503, map[string]string{"error": "no AI provider configured"})
		return
	}

	switch r.Method {
	case http.MethodPost:
		now := time.Now()
		if err := s.store.PutWhatsNewDismiss(u.ID, now); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		// Invalidate any cached summaries for this user so the next GET
		// honours the fresh dismiss timestamp.
		s.whatsNewMu.Lock()
		for k := range s.whatsNewCache {
			if strings.HasPrefix(k, u.ID+"|") {
				delete(s.whatsNewCache, k)
			}
		}
		s.whatsNewMu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true, "dismissed_at": now.UTC().Format(time.RFC3339)})
		return

	case http.MethodGet:
		// fall through
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}

	dismiss, _ := s.store.GetWhatsNewDismiss(u.ID)
	now := time.Now()

	// ?force=1 lets the user manually re-open the brief from the command
	// palette even if they've dismissed it inside the quiet window. The
	// AI summary is identical; we just bypass the auto-hide gate.
	force := r.URL.Query().Get("force") == "1"

	// Inside the quiet window? Don't show a banner. The frontend treats
	// this response as "no banner, move on."
	if !force && !dismiss.IsZero() && now.Sub(dismiss) < whatsNewQuietWindow {
		writeJSON(w, 200, map[string]any{
			"dismissed":    true,
			"dismissed_at": dismiss.UTC().Format(time.RFC3339),
		})
		return
	}

	// Compute the lookback window. Floor at 14 days so a user away for
	// months doesn't trigger a comparably-large AI call.
	since := dismiss
	floor := now.Add(-whatsNewMaxLookback)
	if since.Before(floor) {
		since = floor
	}

	cacheKey := u.ID + "|" + since.UTC().Format(time.RFC3339)
	s.whatsNewMu.Lock()
	if entry, ok := s.whatsNewCache[cacheKey]; ok && time.Now().Before(entry.expiry) {
		payload := entry.payload
		s.whatsNewMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
		return
	}
	s.whatsNewMu.Unlock()

	articles, err := s.store.List(storage.ListFilter{
		Since:    since,
		MinScore: 15,
		Limit:    80,
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if len(articles) == 0 {
		writeJSON(w, 200, map[string]any{
			"empty": true,
			"since": since.UTC().Format(time.RFC3339),
		})
		return
	}

	// Build the slim AI input. Same shape the daily brief uses.
	aiArts := make([]ai.Article, 0, len(articles))
	for _, a := range articles {
		aiArts = append(aiArts, ai.Article{
			Title:   a.Title,
			Score:   a.Score,
			Tags:    a.Tags,
			Source:  a.Source,
			Summary: a.Summary,
		})
		if len(aiArts) >= ai.MaxArticles {
			break
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 95*time.Second)
	defer cancel()
	text, err := s.enrich.AI.Summarize(ctx, aiArts)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "provider": s.enrich.AI.Name()})
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"summary":       text,
		"since":         since.UTC().Format(time.RFC3339),
		"article_count": len(articles),
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"provider":      s.enrich.AI.Name(),
	})
	s.whatsNewMu.Lock()
	s.whatsNewCache[cacheKey] = &whatsNewEntry{
		payload: payload,
		expiry:  time.Now().Add(whatsNewCacheTTL),
	}
	s.whatsNewMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}
