// Package cve holds NVD and EPSS enrichment for CVE chips. Both maintain
// SQLite caches alongside the article DB so repeat lookups are free and offline.
package cve

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ErrNotFound is returned by NVDClient.Get when the upstream NVD API
// reports no record for the requested CVE (either HTTP 404 or 200 with
// an empty vulnerabilities array). Callers use errors.Is to map this to
// a 404 response instead of a generic 502 — important because hitting
// /api/cve/<random-id> is a common HN poke and a 502 makes the backend
// look like it's crashing when it's just "CVE doesn't exist."
var ErrNotFound = errors.New("cve not found")

// CVEDetail is the per-CVE payload secfeed returns to the frontend.
// EPSS fields are populated in the server handler via the EPSS join.
type CVEDetail struct {
	ID             string  `json:"id"`
	Description    string  `json:"description,omitempty"`
	CVSSv3Score    float64 `json:"cvss_v3_score,omitempty"`
	CVSSv3Severity string  `json:"cvss_v3_severity,omitempty"`
	CVSSv3Vector   string  `json:"cvss_v3_vector,omitempty"`
	CWE            string  `json:"cwe,omitempty"`
	Published      string  `json:"published,omitempty"`
	LastModified   string  `json:"last_modified,omitempty"`
	EPSSScore      float64 `json:"epss_score,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	Cached         bool    `json:"cached"`
}

// NVDClient looks up CVE detail through cache → NVD REST API.
//
// Rate-limited per NVD's documented bands: 5 req/30s without an apiKey, 50/30s
// with one. We translate that into a fixed-interval ticker (6s / 600ms).
type NVDClient struct {
	apiKey  string
	db      *sql.DB
	client  *http.Client
	rateLim *time.Ticker
	mu      sync.Mutex
}

func NewNVDClient(db *sql.DB, apiKey string) *NVDClient {
	interval := 6 * time.Second
	if apiKey != "" {
		interval = 600 * time.Millisecond
	}
	return &NVDClient{
		apiKey:  apiKey,
		db:      db,
		client:  &http.Client{Timeout: 30 * time.Second},
		rateLim: time.NewTicker(interval),
	}
}

func (n *NVDClient) EnsureTable() error {
	_, err := n.db.Exec(`
		CREATE TABLE IF NOT EXISTS cve_details (
			cve_id TEXT PRIMARY KEY,
			description TEXT,
			cvss_v3_score REAL,
			cvss_v3_severity TEXT,
			cvss_v3_vector TEXT,
			cwe TEXT,
			published TEXT,
			last_modified TEXT,
			fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			error TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_cve_fetched ON cve_details(fetched_at);
	`)
	return err
}

// Get returns the cached CVE detail, fetching from NVD on miss.
func (n *NVDClient) Get(ctx context.Context, cveID string) (*CVEDetail, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}
	if d := n.readCache(cveID); d != nil {
		d.Cached = true
		return d, nil
	}
	// Wait for the rate-limit window before hitting NVD.
	n.mu.Lock()
	<-n.rateLim.C
	n.mu.Unlock()
	d, err := n.fetchFromNVD(ctx, cveID)
	if err != nil {
		n.writeError(cveID, err.Error())
		return nil, err
	}
	n.writeCache(d)
	return d, nil
}

func (n *NVDClient) readCache(cveID string) *CVEDetail {
	row := n.db.QueryRow(`
		SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v3_vector, cwe, published, last_modified, error
		FROM cve_details WHERE cve_id = ?
	`, cveID)
	var d CVEDetail
	var desc, sev, vec, cwe, pub, mod, errMsg sql.NullString
	var score sql.NullFloat64
	if err := row.Scan(&d.ID, &desc, &score, &sev, &vec, &cwe, &pub, &mod, &errMsg); err != nil {
		return nil
	}
	// If the cached row is an error sentinel (no detail captured), treat as miss
	// so a retry can happen. We avoid infinite retries by writing errors with a
	// recent fetched_at; readError below could be used to short-circuit.
	if errMsg.String != "" && !desc.Valid && !score.Valid {
		return nil
	}
	d.Description = desc.String
	d.CVSSv3Score = score.Float64
	d.CVSSv3Severity = sev.String
	d.CVSSv3Vector = vec.String
	d.CWE = cwe.String
	d.Published = pub.String
	d.LastModified = mod.String
	return &d
}

func (n *NVDClient) writeCache(d *CVEDetail) error {
	_, err := n.db.Exec(`
		INSERT OR REPLACE INTO cve_details
			(cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v3_vector, cwe, published, last_modified, fetched_at, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL)
	`, d.ID, d.Description, d.CVSSv3Score, d.CVSSv3Severity, d.CVSSv3Vector, d.CWE, d.Published, d.LastModified)
	return err
}

func (n *NVDClient) writeError(cveID, errMsg string) {
	n.db.Exec(`
		INSERT OR REPLACE INTO cve_details (cve_id, error, fetched_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`, cveID, errMsg)
}

func (n *NVDClient) fetchFromNVD(ctx context.Context, cveID string) (*CVEDetail, error) {
	url := fmt.Sprintf("%s?cveId=%s", nvdAPIBase, cveID)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "oM-noM-Feeds/0.1")
	if n.apiKey != "" {
		req.Header.Set("apiKey", n.apiKey)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Metrics struct {
					CVSSv31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSv30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, ErrNotFound
	}
	cve := doc.Vulnerabilities[0].CVE
	d := &CVEDetail{
		ID:           cve.ID,
		Published:    cve.Published,
		LastModified: cve.LastModified,
	}
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			v := desc.Value
			if len(v) > 600 {
				v = v[:600] + "..."
			}
			d.Description = v
			break
		}
	}
	for _, w := range cve.Weaknesses {
		for _, desc := range w.Description {
			if desc.Lang == "en" && strings.HasPrefix(desc.Value, "CWE-") {
				d.CWE = desc.Value
				break
			}
		}
		if d.CWE != "" {
			break
		}
	}
	if len(cve.Metrics.CVSSv31) > 0 {
		m := cve.Metrics.CVSSv31[0].CVSSData
		d.CVSSv3Score = m.BaseScore
		d.CVSSv3Severity = m.BaseSeverity
		d.CVSSv3Vector = m.VectorString
	} else if len(cve.Metrics.CVSSv30) > 0 {
		m := cve.Metrics.CVSSv30[0].CVSSData
		d.CVSSv3Score = m.BaseScore
		d.CVSSv3Severity = m.BaseSeverity
		d.CVSSv3Vector = m.VectorString
	}
	return d, nil
}
