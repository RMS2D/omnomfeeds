// Package mitre loads the MITRE ATT&CK Enterprise corpus and exposes a
// technique lookup keyed by T-code. Bundle is fetched from the public mitre/cti
// repo on first run, cached to disk for 30 days, and re-read on every startup
// (no network call on warm-cache boots).
package mitre

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	enterpriseAttackURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	cacheTTL            = 30 * 24 * time.Hour
)

// TacticOrder is the kill-chain sequence used by the ATT&CK matrix.
// Left-to-right is the order shown on the live dashboard.
var TacticOrder = []string{
	"reconnaissance",
	"resource-development",
	"initial-access",
	"execution",
	"persistence",
	"privilege-escalation",
	"defense-evasion",
	"credential-access",
	"discovery",
	"lateral-movement",
	"collection",
	"command-and-control",
	"exfiltration",
	"impact",
}

// tacticAlias normalises MITRE's older / parallel phase names onto the
// canonical 14 tactics. Their published bundle still uses "stealth" instead
// of "defense-evasion" and "defense-impairment" for the disable-defenses
// subset; both fold into defense-evasion for dashboard placement.
var tacticAlias = map[string]string{
	"stealth":            "defense-evasion",
	"defense-impairment": "defense-evasion",
}

// NormalizeTactic returns the canonical tactic name for any phase string
// MITRE has used. Empty input returns empty.
func NormalizeTactic(t string) string {
	if a, ok := tacticAlias[t]; ok {
		return a
	}
	return t
}

// TacticDisplay maps the kill-chain phase name to a human-readable label.
var TacticDisplay = map[string]string{
	"reconnaissance":       "Reconnaissance",
	"resource-development": "Resource Development",
	"initial-access":       "Initial Access",
	"execution":            "Execution",
	"persistence":          "Persistence",
	"privilege-escalation": "Privilege Escalation",
	"defense-evasion":      "Defense Evasion",
	"credential-access":    "Credential Access",
	"discovery":            "Discovery",
	"lateral-movement":     "Lateral Movement",
	"collection":           "Collection",
	"command-and-control":  "Command and Control",
	"exfiltration":         "Exfiltration",
	"impact":               "Impact",
}

// Technique is the trimmed ATT&CK record we keep cached.
type Technique struct {
	ID          string   `json:"id"` // T1190 or T1190.001
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tactics     []string `json:"tactics"` // kill_chain phase names
	URL         string   `json:"url"`
	IsSubTech   bool     `json:"is_subtechnique"`
}

// Map is the lookup secfeed serves to the frontend.
type Map map[string]*Technique

// CompactNames returns just the {id: name} map for compact transmission to JS.
func (m Map) CompactNames() map[string]string {
	out := make(map[string]string, len(m))
	for id, t := range m {
		out[id] = t.Name
	}
	return out
}

// Loader handles cache + fetch.
type Loader struct {
	cachePath string
}

func New(cacheDir string) *Loader {
	return &Loader{cachePath: filepath.Join(cacheDir, "mitre-attack.json")}
}

// Load returns the ATT&CK Enterprise technique map. Uses local cache when fresh;
// otherwise downloads + parses + writes cache. Returns nil if both paths fail.
func (l *Loader) Load() Map {
	if data, ok := l.loadCacheIfFresh(); ok {
		return data
	}
	log.Printf("[MITRE] fetching ATT&CK Enterprise from %s", enterpriseAttackURL)
	data, err := l.fetchAndParse()
	if err != nil {
		log.Printf("[MITRE] fetch error: %v (falling back to stale cache if present)", err)
		return l.readCache()
	}
	if err := l.writeCache(data); err != nil {
		log.Printf("[MITRE] cache write error: %v", err)
	}
	log.Printf("[MITRE] loaded %d techniques", len(data))
	return data
}

func (l *Loader) loadCacheIfFresh() (Map, bool) {
	info, err := os.Stat(l.cachePath)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, false
	}
	return l.readCache(), true
}

func (l *Loader) readCache() Map {
	data, err := os.ReadFile(l.cachePath)
	if err != nil {
		return nil
	}
	var m Map
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

func (l *Loader) writeCache(m Map) error {
	if err := os.MkdirAll(filepath.Dir(l.cachePath), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(l.cachePath, data, 0o600)
}

func (l *Loader) fetchAndParse() (Map, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	req, _ := http.NewRequest("GET", enterpriseAttackURL, nil)
	req.Header.Set("User-Agent", "secfeed/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 80*1024*1024)) // safety cap
	if err != nil {
		return nil, err
	}
	var bundle struct {
		Objects []struct {
			Type         string `json:"type"`
			Name         string `json:"name"`
			Description  string `json:"description"`
			ExternalRefs []struct {
				SourceName string `json:"source_name"`
				ExternalID string `json:"external_id"`
				URL        string `json:"url"`
			} `json:"external_references"`
			KillChainPhases []struct {
				KillChainName string `json:"kill_chain_name"`
				PhaseName     string `json:"phase_name"`
			} `json:"kill_chain_phases"`
			XMitreIsSubtechnique bool `json:"x_mitre_is_subtechnique"`
			Revoked              bool `json:"revoked"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, err
	}
	m := make(Map)
	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" || obj.Revoked {
			continue
		}
		var techID, url string
		for _, ref := range obj.ExternalRefs {
			if ref.SourceName == "mitre-attack" {
				techID = ref.ExternalID
				url = ref.URL
				break
			}
		}
		if techID == "" {
			continue
		}
		tactics := make([]string, 0, len(obj.KillChainPhases))
		for _, p := range obj.KillChainPhases {
			if p.KillChainName == "mitre-attack" {
				tactics = append(tactics, p.PhaseName)
			}
		}
		desc := obj.Description
		if len(desc) > 600 {
			desc = desc[:600] + "..."
		}
		m[techID] = &Technique{
			ID:          techID,
			Name:        obj.Name,
			Description: desc,
			Tactics:     tactics,
			URL:         url,
			IsSubTech:   obj.XMitreIsSubtechnique,
		}
	}
	return m, nil
}
