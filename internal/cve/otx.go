// otx.go - AlienVault OTX overlay for CVE deep-dives.
//
// Adds one signal to the CVE modal: how many OTX threat-intel pulses
// reference this CVE, plus how many of those landed in the last 7 days.
// Higher pulse count = more analysts have written threat reports tagged
// to this CVE, a useful "is this hot in the community" proxy.
//
// Free public endpoint, no API key required. Cached locally for 6 hours
// so we don't hammer their service.

package cve

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const otxBase = "https://otx.alienvault.com/api/v1/indicators/cve"
const otxCacheTTL = 6 * time.Hour

// OTXData is what we surface to the frontend per CVE.
type OTXData struct {
	CVE         string `json:"cve"`
	PulseCount  int    `json:"pulse_count"`
	RecentCount int    `json:"recent_pulse_count"` // pulses created in last 7d
	Cached      bool   `json:"cached"`
}

type OTXClient struct {
	db     *sql.DB
	client *http.Client
}

func NewOTXClient(db *sql.DB) *OTXClient {
	return &OTXClient{
		db:     db,
		client: &http.Client{Timeout: 25 * time.Second},
	}
}

func (o *OTXClient) EnsureTable() error {
	_, err := o.db.Exec(`
		CREATE TABLE IF NOT EXISTS cve_otx (
			cve_id        TEXT PRIMARY KEY,
			pulse_count   INTEGER,
			recent_count  INTEGER,
			fetched_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			error         TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_cve_otx_fetched ON cve_otx(fetched_at);
	`)
	return err
}

// Get: OTX pulse data, 6h disk cache. 200/404 cached, 5xx/timeout retried.
// HTTP timeout is generous because OTX runs 4-5s from some datacenters.
func (o *OTXClient) Get(ctx context.Context, cveID string) (*OTXData, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}
	if d := o.readCache(cveID); d != nil {
		return d, nil
	}
	d, err := o.fetch(ctx, cveID)
	if err != nil {
		// Transient failures don't poison the cache - retry next time.
		return nil, err
	}
	o.writeCache(d)
	return d, nil
}

func (o *OTXClient) readCache(cveID string) *OTXData {
	row := o.db.QueryRow(`
		SELECT cve_id, pulse_count, recent_count, fetched_at, error
		FROM cve_otx WHERE cve_id = ?
	`, cveID)
	var (
		id              string
		pulseCount      sql.NullInt64
		recentCount     sql.NullInt64
		fetchedAt       time.Time
		errMsg          sql.NullString
	)
	if err := row.Scan(&id, &pulseCount, &recentCount, &fetchedAt, &errMsg); err != nil {
		return nil
	}
	if time.Since(fetchedAt) > otxCacheTTL {
		return nil
	}
	// Old rows wrote an error sentinel with pulse_count=0 on transient
	// failures. We no longer write those; treat any error row as a miss
	// so the next Get triggers a fresh fetch.
	if errMsg.String != "" {
		return nil
	}
	return &OTXData{
		CVE:         id,
		PulseCount:  int(pulseCount.Int64),
		RecentCount: int(recentCount.Int64),
		Cached:      true,
	}
}

func (o *OTXClient) writeCache(d *OTXData) error {
	_, err := o.db.Exec(`
		INSERT OR REPLACE INTO cve_otx (cve_id, pulse_count, recent_count, fetched_at, error)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP, NULL)
	`, d.CVE, d.PulseCount, d.RecentCount)
	return err
}

// otxResponse matches the slice of the OTX general indicator response we
// actually use. Their full payload has many more fields; we ignore them.
type otxResponse struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Created string `json:"created"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

func (o *OTXClient) fetch(ctx context.Context, cveID string) (*OTXData, error) {
	url := fmt.Sprintf("%s/%s/general", otxBase, cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1 (+https://omnomfeeds.com)")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		// CVE not in OTX index - normal, not an error worth retrying.
		return &OTXData{CVE: cveID, PulseCount: 0, RecentCount: 0}, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("otx status %d :: %s", resp.StatusCode, string(body))
	}
	var parsed otxResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	recent := 0
	for _, p := range parsed.PulseInfo.Pulses {
		t, err := time.Parse(time.RFC3339Nano, p.Created)
		if err != nil {
			// OTX sometimes returns timestamps without nanoseconds.
			t, err = time.Parse(time.RFC3339, p.Created)
			if err != nil {
				continue
			}
		}
		if t.After(cutoff) {
			recent++
		}
	}
	return &OTXData{
		CVE:         cveID,
		PulseCount:  parsed.PulseInfo.Count,
		RecentCount: recent,
	}, nil
}
