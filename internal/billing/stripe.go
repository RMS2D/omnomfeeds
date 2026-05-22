// Package billing wraps the Stripe REST surface we need for the hosted-mode
// Pro tier. We don't import the official SDK; everything is plain net/http,
// for the same reasons the auth package skips x/oauth2: fewer transitive deps,
// smaller binary, and the API surface we touch is tiny.
//
//	POST /v1/checkout/sessions    -> kicks off a hosted checkout
//	POST /v1/billing_portal/sessions -> returns a portal URL for self-service
//	GET  /v1/subscriptions/<id>   -> read subscription state on resync
//
// Webhook signature verification is also in this file; it has no API call,
// just HMAC-SHA256 of the timestamped raw body against the endpoint secret.
package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const stripeBase = "https://api.stripe.com"

// stripeClient is the minimal REST surface; secret key in Authorization.
type stripeClient struct {
	secret string
	http   *http.Client
}

func newStripeClient(secret string) *stripeClient {
	return &stripeClient{
		secret: secret,
		http:   &http.Client{Timeout: 20 * time.Second},
	}
}

// post sends form-encoded params and decodes a JSON object into dst. Stripe's
// REST API takes application/x-www-form-urlencoded for writes.
func (c *stripeClient) post(ctx context.Context, path string, form url.Values, dst any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", stripeBase+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Stripe-Version", "2024-06-20")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stripe %s: %d :: %s", path, resp.StatusCode, string(body))
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(body, dst)
}

func (c *stripeClient) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", stripeBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Stripe-Version", "2024-06-20")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stripe %s: %d :: %s", path, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dst)
}

// --- Checkout ---

type checkoutSessionResp struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	CustomerID string `json:"customer"`
}

// createCheckout starts a Stripe-hosted Checkout for a single subscription
// price. clientReferenceID carries our internal user ID so the webhook can
// match the resulting subscription back to the row.
func (c *stripeClient) createCheckout(ctx context.Context, in checkoutInput) (*checkoutSessionResp, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", in.PriceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", in.SuccessURL)
	form.Set("cancel_url", in.CancelURL)
	form.Set("client_reference_id", in.UserID)
	form.Set("allow_promotion_codes", "true")
	form.Set("billing_address_collection", "auto")
	form.Set("subscription_data[metadata][user_id]", in.UserID)

	if in.CustomerID != "" {
		form.Set("customer", in.CustomerID)
	} else if in.CustomerEmail != "" {
		// Stripe auto-creates the Customer in subscription mode; pre-fill
		// email. customer_creation is payment-mode only.
		form.Set("customer_email", in.CustomerEmail)
	}

	var out checkoutSessionResp
	if err := c.post(ctx, "/v1/checkout/sessions", form, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type checkoutInput struct {
	UserID        string
	CustomerID    string
	CustomerEmail string
	PriceID       string
	SuccessURL    string
	CancelURL     string
}

// --- Customer portal ---

type portalSessionResp struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func (c *stripeClient) createPortal(ctx context.Context, customerID, returnURL string) (*portalSessionResp, error) {
	form := url.Values{}
	form.Set("customer", customerID)
	form.Set("return_url", returnURL)
	var out portalSessionResp
	if err := c.post(ctx, "/v1/billing_portal/sessions", form, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Subscription read ---

type subscriptionResp struct {
	ID                string `json:"id"`
	Status            string `json:"status"` // active | past_due | canceled | trialing | unpaid | incomplete | incomplete_expired
	CurrentPeriodEnd  int64  `json:"current_period_end"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
	CustomerID        string `json:"customer"`
}

func (c *stripeClient) getSubscription(ctx context.Context, id string) (*subscriptionResp, error) {
	var out subscriptionResp
	if err := c.get(ctx, "/v1/subscriptions/"+url.PathEscape(id), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Webhook signature verification ---
//
// Stripe-Signature header: "t=<unix_ts>,v1=<hex_hmac>,v1=<hex_hmac>,..."
// We HMAC-SHA256 the secret over "<ts>.<raw_body>" and compare to any v1.
// Reject if ts is more than tolerance seconds away from wall clock (replay
// guard).

const webhookTolerance = 5 * time.Minute

func verifyWebhookSignature(secret, sigHeader string, payload []byte) error {
	if secret == "" {
		return errors.New("webhook secret not configured")
	}
	var ts int64
	var v1s []string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			n, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return errors.New("bad timestamp in stripe-signature")
			}
			ts = n
		case "v1":
			v1s = append(v1s, kv[1])
		}
	}
	if ts == 0 || len(v1s) == 0 {
		return errors.New("stripe-signature missing fields")
	}
	if diff := time.Now().Unix() - ts; diff > int64(webhookTolerance.Seconds()) || diff < -int64(webhookTolerance.Seconds()) {
		return errors.New("stripe-signature timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, got := range v1s {
		if hmac.Equal([]byte(expected), []byte(got)) {
			return nil
		}
	}
	return errors.New("stripe-signature mismatch")
}
