package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	magicLinkTTL         = 15 * time.Minute
	magicLinkRateWindow  = 60 * time.Second // min interval between requests per email
	magicLinkIPWindow    = 60 * time.Second // window for per-IP cap
	magicLinkIPCap       = 5                // max distinct requests per IP per window (looser to allow NAT)
	magicLinkMaxEmailLen = 254              // RFC 5321
)

// handleMagicRequest accepts {email} and emails the user a sign-in link.
// Always returns 202 so callers can't enumerate which addresses have accounts.
func (h *Handler) handleMagicRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if h.cfg.ResendAPIKey == "" {
		http.Error(w, "magic-link login not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := normalizeEmail(body.Email)
	if !looksLikeEmail(email) {
		// Same status as the success case so probes can't tell valid from invalid.
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}

	// Rate-limit per email (1/min) and per IP fingerprint (5/min).
	// Silently drop both cases so probes can't distinguish.
	ipH := hashIP(remoteIP(r))
	if n, _ := h.store.RecentMagicLinksForEmail(email, magicLinkRateWindow); n > 0 {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	if n, _ := h.store.RecentMagicLinksForIP(ipH, magicLinkIPWindow); n >= magicLinkIPCap {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}

	// Generate token + hash.
	rawToken, tokenHash, err := newRandomToken()
	if err != nil {
		log.Printf("[auth] magic: token gen: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.store.CreateMagicLink(tokenHash, email, r.UserAgent(), magicLinkTTL, ipH); err != nil {
		log.Printf("[auth] magic: store link: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	link := h.magicVerifyURL() + "?t=" + rawToken
	subject := "Sign in to oM noM Security Feeds"
	textBody := "Click this link to sign in to oM noM Security Feeds:\n\n" + link +
		"\n\nThe link expires in 15 minutes. If you didn't request it, you can ignore this email."
	htmlBody := buildMagicHTML(link)

	em := newEmailClient(h.cfg.ResendAPIKey)
	if err := em.Send(email, subject, textBody, htmlBody); err != nil {
		// Log server-side but don't reveal to the client; the 202 we already
		// promised is the only reliable signal we give.
		log.Printf("[auth] magic: send to %s: %v", email, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// handleMagicVerify: GET renders an interstitial, POST consumes the token.
// Split because mail scanners GET every link and would burn one-shot tokens.
func (h *Handler) handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	if h.cfg.ResendAPIKey == "" {
		http.Error(w, "magic-link login not configured", http.StatusServiceUnavailable)
		return
	}

	var rawToken string
	switch r.Method {
	case http.MethodGet:
		rawToken = r.URL.Query().Get("t")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		rawToken = r.PostFormValue("t")
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}

	if rawToken == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(rawToken)
	if err != nil || len(raw) != 32 {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// GET phase: render the confirm page. Don't touch the token yet.
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(magicConfirmHTML(rawToken)))
		return
	}

	// POST phase: real click. Consume + sign in.
	sum := sha256.Sum256(raw)
	row, err := h.store.ConsumeMagicLink(sum[:])
	if err != nil {
		http.Error(w, "link is expired or already used", http.StatusUnauthorized)
		return
	}

	// Upsert user. id_provider="email", id_external=normalized email so
	// signing in twice with the same address always lands on the same row.
	userID, err := h.store.UpsertUser("email", row.Email, row.Email, "")
	if err != nil {
		log.Printf("[auth] magic: upsert user %s: %v", row.Email, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Issue session.
	sessToken, sessHash, err := newRandomToken()
	if err != nil {
		log.Printf("[auth] magic: session token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.store.CreateSession(userID, sessHash, r.UserAgent(), sessionTTL); err != nil {
		log.Printf("[auth] magic: create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, sessToken)
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

// magicConfirmHTML renders the interstitial that mail scanners hit on GET
// but a human completes with a click. Same dark theme as the rest of the
// app so the transition doesn't feel jarring.
func magicConfirmHTML(token string) string {
	// Token is already base64-no-pad random; safe in an HTML attribute.
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<meta name="referrer" content="no-referrer">
<title>Sign in - oM noM Security Feeds</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --bg: #0a0e14; --bg-card: #14191f; --border: #2a3340;
  --text: #e6ecf5; --text-dim: #b8c4d4; --text-bright: #ffffff;
  --accent: #00e5a0;
}
html, body {
  background: var(--bg); color: var(--text);
  font-family: 'Space Grotesk', system-ui, sans-serif;
  font-size: 15px; line-height: 1.55; min-height: 100vh;
}
.wrap {
  min-height: 100vh; display: flex; flex-direction: column;
  align-items: center; justify-content: center; padding: 32px 24px;
}
.card {
  width: 100%; max-width: 380px;
  background: var(--bg-card); border: 1px solid var(--border);
  border-top: 2px solid var(--accent); border-radius: 5px;
  padding: 30px 28px 26px;
}
.brand {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px; color: var(--text-bright); font-weight: 600;
  letter-spacing: 0.4px; margin-bottom: 14px;
}
.brand .worm { color: var(--accent); text-shadow: 0 0 8px rgba(0,229,160,0.4); }
h1 { font-size: 22px; font-weight: 600; color: var(--text-bright); margin-bottom: 8px; letter-spacing: -0.2px; }
.subhead { color: var(--text-dim); font-size: 13px; margin-bottom: 22px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center;
  gap: 10px; width: 100%; padding: 12px 16px; border-radius: 4px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600;
  letter-spacing: 0.3px; border: 1px solid var(--accent);
  cursor: pointer; transition: all 0.14s ease; text-decoration: none;
  background: rgba(0,229,160,0.10); color: var(--accent);
  text-shadow: 0 0 6px rgba(0,229,160,0.3);
}
.btn:hover { background: rgba(0,229,160,0.2); color: var(--text-bright); box-shadow: 0 0 14px rgba(0,229,160,0.25); }
.fineprint {
  margin-top: 18px; font-family: 'JetBrains Mono', monospace;
  font-size: 10px; color: var(--text-dim); text-align: center;
  letter-spacing: 0.4px; line-height: 1.6;
}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="worm">~~~_o)</span> oM noM Security Feeds</div>
    <h1>Finish signing in</h1>
    <p class="subhead">Click the button below to complete sign-in. The one-time link is consumed when you click; opening the email itself never consumes it.</p>
    <form method="POST" action="/auth/magic/verify">
      <input type="hidden" name="t" value="` + token + `">
      <button type="submit" class="btn">Sign me in &rarr;</button>
    </form>
    <p class="fineprint">If nothing happens after clicking, the link probably expired (15 minute window). Just request a new one.</p>
  </div>
</div>
</body>
</html>`
}

// magicVerifyURL builds the absolute URL the email link points to. It reuses
// the OAUTH_REDIRECT_URL's base since both handlers live under /auth/.
func (h *Handler) magicVerifyURL() string {
	base := strings.TrimSuffix(h.cfg.OAuthRedirectURL, "/auth/callback")
	return base + "/auth/magic/verify"
}

// normalizeEmail lowercases + trims so the same address always hashes to the
// same id_external regardless of how the user typed it.
func normalizeEmail(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) > magicLinkMaxEmailLen {
		return ""
	}
	return s
}

// looksLikeEmail is intentionally minimal: an @ between non-empty halves,
// no spaces, has a dot in the domain. Real validation happens when Resend
// either delivers or doesn't.
func looksLikeEmail(s string) bool {
	if s == "" {
		return false
	}
	i := strings.IndexByte(s, '@')
	if i <= 0 || i == len(s)-1 {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return strings.IndexByte(s[i+1:], '.') > 0
}

// newRandomToken returns a 32-byte URL-safe random token (base64 no-pad) plus
// its SHA-256 hash. Reusable for session cookies and magic-link tokens; the
// raw token never touches the DB.
func newRandomToken() (token string, hash []byte, err error) {
	token, hash, err = newSessionToken()
	return
}

// errMagicNotConfigured is returned when handleMagic* fires but no Resend
// API key is set. Kept as a sentinel for tests later.
var errMagicNotConfigured = errors.New("magic-link login not configured")

// buildMagicHTML wraps the sign-in link in a tiny HTML email body. No
// external CSS, no images, no tracking pixels.
func buildMagicHTML(link string) string {
	// Minimal, mobile-friendly, all-inline-styled. Plain text alternative
	// already covered by the textBody arg in Send().
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="margin:0;padding:24px;background:#0a0e14;color:#e6ecf5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:15px;line-height:1.6;">
<table cellpadding="0" cellspacing="0" border="0" style="max-width:520px;margin:0 auto;">
<tr><td style="padding:18px 0;font-family:'JetBrains Mono',monospace;color:#00e5a0;font-size:13px;letter-spacing:0.6px;">
  ~~~_o)  oM noM Security Feeds
</td></tr>
<tr><td style="padding:8px 0 18px;font-size:18px;font-weight:600;color:#ffffff;">
  Click to sign in
</td></tr>
<tr><td style="padding:0 0 22px;color:#b8c4d4;">
  Click the button below to finish signing in. The link is valid for 15 minutes and can only be used once.
</td></tr>
<tr><td style="padding:0 0 26px;">
  <a href="` + link + `" style="display:inline-block;padding:11px 22px;background:rgba(0,229,160,0.12);border:1px solid #00e5a0;border-radius:4px;color:#00e5a0;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;text-decoration:none;letter-spacing:0.3px;">Sign me in &rarr;</a>
</td></tr>
<tr><td style="padding:0 0 8px;color:#b8c4d4;font-size:13px;">
  Or paste this URL into your browser:
</td></tr>
<tr><td style="padding:0 0 28px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#56e2ff;word-break:break-all;">
  ` + link + `
</td></tr>
<tr><td style="padding:18px 0 0;border-top:1px solid #2a3340;color:#b8c4d4;font-size:12px;">
  Didn't request this? You can safely ignore the email; the link will expire on its own.
</td></tr>
</table>
</body></html>`
}
