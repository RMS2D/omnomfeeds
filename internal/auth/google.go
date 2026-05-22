package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Google OAuth 2.0 + PKCE flow. Trust is anchored at TLS (token comes
// directly from googleapis.com); JWKS verification is future hardening.

const (
	googleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	googleScope         = "openid email profile"

	oauthStateCookieName = "omnom_oauth_state"
	oauthStateTTL        = 10 * time.Minute
)

func (h *Handler) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	if h.cfg.GoogleClientID == "" {
		http.Error(w, "google oauth not configured", http.StatusServiceUnavailable)
		return
	}

	// Random state + PKCE verifier. Both 32 bytes URL-safe base64. The state
	// is the CSRF anchor; the verifier proves the callback is the same party
	// that initiated the redirect (defeats stolen-code replay).
	state, _, err := newRandomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier, _, err := newRandomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// PKCE S256: challenge = base64url(sha256(verifier_string))
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(challengeBytes[:])

	// Stash both in a short-lived cookie that only the callback path can read.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state + "." + verifier,
		Path:     "/auth/callback",
		MaxAge:   int(oauthStateTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	q := url.Values{}
	q.Set("client_id", h.cfg.GoogleClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", h.cfg.OAuthRedirectURL)
	q.Set("scope", googleScope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "online")
	q.Set("prompt", "select_account")

	http.Redirect(w, r, googleAuthEndpoint+"?"+q.Encode(), http.StatusSeeOther)
}

func (h *Handler) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if h.cfg.GoogleClientID == "" {
		http.Error(w, "google oauth not configured", http.StatusServiceUnavailable)
		return
	}

	// Pull the state cookie regardless of outcome so we don't leave it around.
	c, err := r.Cookie(oauthStateCookieName)
	clearOAuthStateCookie(w)
	if err != nil {
		http.Error(w, "missing oauth state", http.StatusBadRequest)
		return
	}

	dot := strings.IndexByte(c.Value, '.')
	if dot <= 0 || dot == len(c.Value)-1 {
		http.Error(w, "malformed oauth state", http.StatusBadRequest)
		return
	}
	expectedState := c.Value[:dot]
	verifier := c.Value[dot+1:]

	if g := r.URL.Query().Get("error"); g != "" {
		// Common values: access_denied (user clicked cancel), invalid_request.
		log.Printf("[auth] google: oauth error %q", g)
		http.Redirect(w, r, "/login.html?err=cancelled", http.StatusSeeOther)
		return
	}
	if got := r.URL.Query().Get("state"); got != expectedState {
		http.Error(w, "oauth state mismatch", http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing oauth code", http.StatusBadRequest)
		return
	}

	tokenResp, err := h.exchangeGoogleCode(r.Context(), code, verifier)
	if err != nil {
		log.Printf("[auth] google: token exchange: %v", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	if tokenResp.IDToken == "" {
		log.Printf("[auth] google: empty id_token in token response")
		http.Error(w, "no id token", http.StatusBadGateway)
		return
	}

	claims, err := parseGoogleIDToken(tokenResp.IDToken, h.cfg.GoogleClientID)
	if err != nil {
		log.Printf("[auth] google: parse id token: %v", err)
		http.Error(w, "id token invalid", http.StatusBadRequest)
		return
	}
	if claims.Sub == "" || claims.Email == "" {
		http.Error(w, "incomplete id token claims", http.StatusBadRequest)
		return
	}
	if !claims.EmailVerified {
		// Google flags unverified accounts (very rare for personal Gmail).
		// Refuse them so we don't end up with a verified-by-association user.
		http.Error(w, "google reports your email is not verified", http.StatusForbidden)
		return
	}

	userID, err := h.store.UpsertUser("google", claims.Sub, strings.ToLower(claims.Email), claims.Name)
	if err != nil {
		log.Printf("[auth] google: upsert user %s: %v", claims.Email, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessToken, sessHash, err := newRandomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.store.CreateSession(userID, sessHash, r.UserAgent(), sessionTTL); err != nil {
		log.Printf("[auth] google: create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, sessToken)
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

// --- helpers ---

type googleTokenResp struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (h *Handler) exchangeGoogleCode(ctx context.Context, code, verifier string) (*googleTokenResp, error) {
	form := url.Values{}
	form.Set("client_id", h.cfg.GoogleClientID)
	form.Set("client_secret", h.cfg.GoogleClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", h.cfg.OAuthRedirectURL)
	form.Set("code", code)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d :: %s", resp.StatusCode, string(b))
	}
	var tr googleTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

type googleIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Aud           string `json:"aud"`
	Iss           string `json:"iss"`
	Exp           int64  `json:"exp"`
}

// validGoogleIssuers are the two strings Google's identity service uses
// in the iss claim. Both are valid per OIDC discovery; accept either.
var validGoogleIssuers = map[string]bool{
	"accounts.google.com":         true,
	"https://accounts.google.com": true,
}

// parseGoogleIDToken decodes the JWT payload (sig trusted via TLS).
// Validates aud/iss/exp to block confused-deputy / replay attacks.
func parseGoogleIDToken(s, expectedAud string) (*googleIDClaims, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload b64: %w", err)
	}
	var c googleIDClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("payload json: %w", err)
	}
	if expectedAud == "" {
		return nil, errors.New("expected aud not configured")
	}
	if c.Aud != expectedAud {
		return nil, fmt.Errorf("id token aud %q does not match configured client", c.Aud)
	}
	if !validGoogleIssuers[c.Iss] {
		return nil, fmt.Errorf("id token iss %q is not Google", c.Iss)
	}
	if c.Exp <= 0 {
		return nil, errors.New("id token missing exp")
	}
	// 30s clock-skew tolerance is the conventional OIDC slack.
	if time.Now().Unix() > c.Exp+30 {
		return nil, errors.New("id token expired")
	}
	return &c, nil
}

func clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/auth/callback",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
