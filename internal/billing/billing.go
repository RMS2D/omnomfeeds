// Package billing wires the Stripe REST client into HTTP handlers and the
// users table. Hosted-mode only; self-host installs never construct a
// Handler.
package billing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/analytics"
	"github.com/RMS2D/omnomfeeds/internal/auth"
	"github.com/RMS2D/omnomfeeds/internal/config"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Handler bundles cfg + store + Stripe client. Built once at startup.
type Handler struct {
	cfg       config.HostedConfig
	store     *storage.Store
	client    *stripeClient
	analytics *analytics.Analytics // optional; nil-safe via Emit() guards
}

// SetAnalytics wires the analytics handle after construction so the
// constructor signature stays unchanged for self-host callers that never
// build one.
func (h *Handler) SetAnalytics(a *analytics.Analytics) {
	h.analytics = a
}

// NewHandler returns nil if the hosted Stripe creds aren't set so the server
// can simply skip mounting billing routes.
func NewHandler(cfg config.HostedConfig, store *storage.Store) (*Handler, error) {
	if !cfg.Enabled {
		return nil, errors.New("hosted mode not enabled")
	}
	if cfg.StripeSecretKey == "" || cfg.StripePriceID == "" {
		return nil, errors.New("STRIPE_SECRET_KEY or STRIPE_PRO_PRICE_ID not set")
	}
	return &Handler{
		cfg:    cfg,
		store:  store,
		client: newStripeClient(cfg.StripeSecretKey),
	}, nil
}

// Mount attaches the billing routes to a mux. The checkout + portal routes
// require an authenticated user (wrap with auth.RequireUser before calling).
// The webhook route is unauthenticated; its signature is the trust anchor.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.Handle("/api/billing/checkout", auth.RequireUser(http.HandlerFunc(h.handleCheckout)))
	mux.Handle("/api/billing/portal", auth.RequireUser(http.HandlerFunc(h.handlePortal)))
	mux.HandleFunc("/api/billing/webhook", h.handleWebhook)
}

// handleCheckout creates a Stripe Checkout Session and returns its URL.
// Frontend either redirects via window.location or opens in a new tab.
func (h *Handler) handleCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}

	row, err := h.store.GetUserByID(u.ID)
	if err != nil {
		log.Printf("[billing] checkout: get user %s: %v", u.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	base := siteBaseURL(h.cfg)
	in := checkoutInput{
		UserID:        u.ID,
		PriceID:       h.cfg.StripePriceID,
		CustomerID:    row.StripeCustomerID,
		CustomerEmail: u.Email,
		SuccessURL:    base + "/app?billing=ok",
		CancelURL:     base + "/app?billing=cancelled",
	}
	sess, err := h.client.createCheckout(r.Context(), in)
	if err != nil {
		log.Printf("[billing] checkout: stripe create: %v", err)
		http.Error(w, "checkout unavailable", http.StatusBadGateway)
		return
	}

	h.analytics.Emit(u.ID, analytics.SessionFromRequest(r), analytics.EvProCheckoutStart, sess.ID, nil, analytics.HashIPFromRequest(r), r.UserAgent())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": sess.URL, "id": sess.ID})
}

func (h *Handler) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	row, err := h.store.GetUserByID(u.ID)
	if err != nil || row.StripeCustomerID == "" {
		http.Error(w, "no stripe customer on file", http.StatusBadRequest)
		return
	}
	sess, err := h.client.createPortal(r.Context(), row.StripeCustomerID, siteBaseURL(h.cfg)+"/app")
	if err != nil {
		log.Printf("[billing] portal: stripe create: %v", err)
		http.Error(w, "portal unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": sess.URL})
}

// webhookEvent is the slim shape of a Stripe event envelope we care about.
// Each handled type has its own struct under "data.object".
type webhookEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

const webhookMaxBody = 1 << 20 // 1 MiB ceiling on inbound webhook payloads

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, webhookMaxBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if err := verifyWebhookSignature(h.cfg.StripeWebhookSecret, sig, body); err != nil {
		log.Printf("[billing] webhook: sig verify: %v", err)
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}
	var ev webhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := h.dispatchEvent(r, &ev); err != nil {
		log.Printf("[billing] webhook: %s: %v", ev.Type, err)
		// sql.ErrNoRows means unknown/deleted customer; ack 200 so Stripe
		// stops retrying. Everything else 500s for self-heal retries.
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("[billing] webhook: %s acknowledged with 200 - unknown customer, no retry useful", ev.Type)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "handler error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) dispatchEvent(r *http.Request, ev *webhookEvent) error {
	switch ev.Type {
	case "checkout.session.completed":
		return h.onCheckoutCompleted(r, ev.Data.Object)
	case "invoice.paid":
		return h.onInvoicePaid(r, ev.Data.Object)
	case "customer.subscription.deleted":
		return h.onSubscriptionDeleted(ev.Data.Object)
	case "customer.subscription.updated":
		return h.onSubscriptionUpdated(ev.Data.Object)
	default:
		// Unknown event types are not errors; Stripe sends a long tail.
		return nil
	}
}

// checkout.session.completed: link the Stripe customer + subscription to
// our user via client_reference_id, then extend pro_until from the sub's
// current period end.
type checkoutSessionEvent struct {
	ID                string `json:"id"`
	CustomerID        string `json:"customer"`
	SubscriptionID    string `json:"subscription"`
	ClientReferenceID string `json:"client_reference_id"`
	Mode              string `json:"mode"`
}

func (h *Handler) onCheckoutCompleted(r *http.Request, obj json.RawMessage) error {
	var s checkoutSessionEvent
	if err := json.Unmarshal(obj, &s); err != nil {
		return err
	}
	if s.Mode != "subscription" || s.ClientReferenceID == "" || s.CustomerID == "" {
		return nil
	}
	// Confirm the user row still exists before writing pro state; a deleted user
	// hitting a stale checkout link would otherwise silently no-op the UPDATE.
	if u, err := h.store.GetUserByID(s.ClientReferenceID); err != nil || u == nil {
		return fmt.Errorf("checkout.completed: unknown user %q", s.ClientReferenceID)
	}
	if err := h.store.SetStripeCustomer(s.ClientReferenceID, s.CustomerID, s.SubscriptionID); err != nil {
		return err
	}
	if s.SubscriptionID == "" {
		return nil
	}
	sub, err := h.client.getSubscription(r.Context(), s.SubscriptionID)
	if err != nil {
		return err
	}
	if sub.CurrentPeriodEnd == 0 {
		return nil
	}
	until := time.Unix(sub.CurrentPeriodEnd, 0).Add(48 * time.Hour) // small grace window
	if err := h.store.SetProUntil(s.ClientReferenceID, until); err != nil {
		return err
	}
	// Stripe webhook event - no end-user IP/UA to record.
	h.analytics.Emit(s.ClientReferenceID, "", analytics.EvProSubscribeSuccess, s.SubscriptionID, nil, nil, "")
	return nil
}

// invoice.paid: extend pro_until on every renewal. We look the user up by
// customer ID, then read current_period_end from the subscription.
type invoiceEvent struct {
	ID             string `json:"id"`
	CustomerID     string `json:"customer"`
	SubscriptionID string `json:"subscription"`
	Status         string `json:"status"`
}

func (h *Handler) onInvoicePaid(r *http.Request, obj json.RawMessage) error {
	var inv invoiceEvent
	if err := json.Unmarshal(obj, &inv); err != nil {
		return err
	}
	if inv.CustomerID == "" || inv.SubscriptionID == "" {
		return nil
	}
	user, err := h.store.GetUserByStripeCustomerID(inv.CustomerID)
	if err != nil {
		// Unknown customer; could be a race with checkout.session.completed.
		// Returning the error makes Stripe retry, which usually wins.
		return err
	}
	sub, err := h.client.getSubscription(r.Context(), inv.SubscriptionID)
	if err != nil {
		return err
	}
	if sub.CurrentPeriodEnd == 0 {
		return nil
	}
	until := time.Unix(sub.CurrentPeriodEnd, 0).Add(48 * time.Hour)
	if err := h.store.SetProUntil(user.ID, until); err != nil {
		return err
	}
	// Stripe webhook event - no end-user IP/UA to record.
	h.analytics.Emit(user.ID, "", analytics.EvProSubscribeRenew, inv.SubscriptionID, nil, nil, "")
	return nil
}

// customer.subscription.deleted: revoke Pro immediately at period end.
// Stripe sends this when the subscription fully ends (after grace + dunning),
// so we clear the entitlement.
type subscriptionEvent struct {
	ID                string `json:"id"`
	CustomerID        string `json:"customer"`
	Status            string `json:"status"`
	CurrentPeriodEnd  int64  `json:"current_period_end"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
}

func (h *Handler) onSubscriptionDeleted(obj json.RawMessage) error {
	var s subscriptionEvent
	if err := json.Unmarshal(obj, &s); err != nil {
		return err
	}
	if s.CustomerID == "" {
		return nil
	}
	user, err := h.store.GetUserByStripeCustomerID(s.CustomerID)
	if err != nil {
		return err
	}
	return h.store.ClearProAccess(user.ID)
}

// customer.subscription.updated: status changes (e.g. past_due, unpaid).
// We re-read the sub and rebuild pro_until from current_period_end so the
// entitlement stays in sync.
func (h *Handler) onSubscriptionUpdated(obj json.RawMessage) error {
	var s subscriptionEvent
	if err := json.Unmarshal(obj, &s); err != nil {
		return err
	}
	if s.CustomerID == "" {
		return nil
	}
	user, err := h.store.GetUserByStripeCustomerID(s.CustomerID)
	if err != nil {
		return err
	}
	if s.Status == "canceled" || s.Status == "incomplete_expired" {
		return h.store.ClearProAccess(user.ID)
	}
	if s.CurrentPeriodEnd == 0 {
		return nil
	}
	until := time.Unix(s.CurrentPeriodEnd, 0).Add(48 * time.Hour)
	return h.store.SetProUntil(user.ID, until)
}

// siteBaseURL strips /auth/callback off OAUTH_REDIRECT_URL so we don't need
// a separate SITE_URL env var. Works for both omnomfeeds.com and any other
// host running the hosted build.
func siteBaseURL(cfg config.HostedConfig) string {
	base := strings.TrimSuffix(cfg.OAuthRedirectURL, "/auth/callback")
	if base == "" {
		return "https://omnomfeeds.com"
	}
	// Ensure URL parses; fall back to the literal env value if it doesn't.
	if _, err := url.Parse(base); err != nil {
		return "https://omnomfeeds.com"
	}
	return base
}
