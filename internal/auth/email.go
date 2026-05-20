package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const resendAPI = "https://api.resend.com/emails"

// emailClient is a minimal Resend wrapper. We only need send-one-email, no
// templates, no attachments. Resend reuses the user's API key for all sends;
// the From address must be on a verified domain in the Resend dashboard.
type emailClient struct {
	apiKey string
	from   string
	client *http.Client
}

func newEmailClient(apiKey string) *emailClient {
	return &emailClient{
		apiKey: apiKey,
		from:   "oM noM Security Feeds <noreply@omnomfeeds.com>",
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

type resendReq struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
}

func (e *emailClient) Send(to, subject, text, html string) error {
	body, _ := json.Marshal(resendReq{
		From:    e.from,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
		Text:    text,
	})
	req, err := http.NewRequest("POST", resendAPI, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("resend: status %d :: %s", resp.StatusCode, string(b))
	}
	return nil
}
