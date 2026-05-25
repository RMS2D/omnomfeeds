package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// publicRSS: /feed.xml. RSS 2.0 + atom:link self-discovery, links point at
// the original source (publisher gets the click). 10min in-mem cache.

type rssItem struct {
	XMLName     xml.Name `xml:"item"`
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`
	GUID        rssGUID  `xml:"guid"`
	PubDate     string   `xml:"pubDate"`
	Description string   `xml:"description"`
	Source      rssSrc   `xml:"source"`
	Categories  []string `xml:"category"`
}

type rssGUID struct {
	XMLName     xml.Name `xml:"guid"`
	Value       string   `xml:",chardata"`
	IsPermaLink string   `xml:"isPermaLink,attr"`
}

type rssSrc struct {
	XMLName xml.Name `xml:"source"`
	Value   string   `xml:",chardata"`
	URL     string   `xml:"url,attr,omitempty"`
}

type rssAtomLink struct {
	XMLName xml.Name `xml:"atom:link"`
	Href    string   `xml:"href,attr"`
	Rel     string   `xml:"rel,attr"`
	Type    string   `xml:"type,attr"`
}

type rssChannel struct {
	XMLName       xml.Name    `xml:"channel"`
	Title         string      `xml:"title"`
	Link          string      `xml:"link"`
	Description   string      `xml:"description"`
	Language      string      `xml:"language"`
	LastBuildDate string      `xml:"lastBuildDate"`
	Generator     string      `xml:"generator"`
	TTL           int         `xml:"ttl"`
	AtomLink      rssAtomLink `xml:"atom:link"`
	Items         []rssItem   `xml:"item"`
}

type rssRoot struct {
	XMLName   xml.Name   `xml:"rss"`
	Version   string     `xml:"version,attr"`
	XMLNSAtom string     `xml:"xmlns:atom,attr"`
	Channel   rssChannel `xml:"channel"`
}

type rssCache struct {
	mu   sync.Mutex
	body []byte
	at   time.Time
}

var feedCache = &rssCache{}

// handlePublicRSS serves /feed.xml. Public, no auth. RSS 2.0 of the
// top-scoring 50 articles in the last 7 days. 10-minute server cache.
func (s *Server) handlePublicRSS(w http.ResponseWriter, r *http.Request) {
	feedCache.mu.Lock()
	if feedCache.body != nil && time.Since(feedCache.at) < 10*time.Minute {
		body := feedCache.body
		feedCache.mu.Unlock()
		w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Write(body)
		return
	}
	feedCache.mu.Unlock()

	body, err := s.buildPublicRSS(r)
	if err != nil {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}

	feedCache.mu.Lock()
	feedCache.body = body
	feedCache.at = time.Now()
	feedCache.mu.Unlock()

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Write(body)
}

func (s *Server) buildPublicRSS(r *http.Request) ([]byte, error) {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = "omnomfeeds.com"
	}
	siteURL := scheme + "://" + host
	feedURL := siteURL + "/feed.xml"

	rows, err := s.store.DB().Query(`
		SELECT id, title, url, source, COALESCE(summary, ''), score,
		       COALESCE(published_at, fetched_at), COALESCE(tags, '[]')
		FROM articles
		WHERE duplicate_of IS NULL
		  AND score >= 60
		  AND published_at >= datetime('now','-7 days')
		ORDER BY published_at DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]rssItem, 0, 50)
	for rows.Next() {
		var id int64
		var title, url, source, summary, tagsRaw string
		var score int
		var pubStr string
		if err := rows.Scan(&id, &title, &url, &source, &summary, &score, &pubStr, &tagsRaw); err != nil {
			continue
		}
		pub := parseDBTimestamp(pubStr)
		var tags []string
		_ = json.Unmarshal([]byte(tagsRaw), &tags)

		// Description: short summary + enrichment hints. Plain-text only
		// (no HTML); some readers strip HTML aggressively and the inline
		// chips don't render. We surface KEV / score / source as text.
		var enrich []string
		if score > 0 {
			enrich = append(enrich, fmt.Sprintf("score %d", score))
		}
		var kev, cves []string
		for _, t := range tags {
			switch {
			case strings.HasPrefix(t, "kev:"):
				kev = append(kev, strings.TrimPrefix(t, "kev:"))
			case strings.HasPrefix(t, "CVE-"):
				cves = append(cves, t)
			}
		}
		if len(kev) > 0 {
			enrich = append(enrich, "KEV: "+strings.Join(kev, ", "))
		} else if len(cves) > 0 {
			limit := len(cves)
			if limit > 4 {
				limit = 4
			}
			enrich = append(enrich, "CVEs: "+strings.Join(cves[:limit], ", "))
		}
		summaryShort := summary
		if len(summaryShort) > 400 {
			summaryShort = summaryShort[:400] + "..."
		}
		desc := summaryShort
		if len(enrich) > 0 {
			desc = strings.TrimSpace(desc) + " [" + strings.Join(enrich, " · ") + "]"
		}

		// Category list: include human-friendly tags (not the heavy
		// MITRE T-codes since most readers will dump them as flat text).
		var cats []string
		for _, t := range tags {
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "T") && len(t) > 1 && t[1] >= '0' && t[1] <= '9' {
				continue
			}
			cats = append(cats, t)
		}

		items = append(items, rssItem{
			Title:       title,
			Link:        url,
			GUID:        rssGUID{Value: url, IsPermaLink: "true"},
			PubDate:     pub.Format(time.RFC1123Z),
			Description: desc,
			Source:      rssSrc{Value: source},
			Categories:  cats,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	doc := rssRoot{
		Version:   "2.0",
		XMLNSAtom: "http://www.w3.org/2005/Atom",
		Channel: rssChannel{
			Title:         "oM noM Security Feeds - High signal",
			Link:          siteURL,
			Description:   "Top-scoring security stories from oM noM. CVE / KEV / EPSS / actor context inline. Auto-curated from 80+ source feeds.",
			Language:      "en",
			LastBuildDate: time.Now().UTC().Format(time.RFC1123Z),
			Generator:     "omnomfeeds " + serverVersion,
			TTL:           10,
			AtomLink: rssAtomLink{
				Href: feedURL,
				Rel:  "self",
				Type: "application/rss+xml",
			},
			Items: items,
		},
	}

	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// parseDBTimestamp normalises the Go time.String() format that SQLite
// stores (including the trailing " m=+..." monotonic suffix) so item
// pubDates are accurate even when the DB row's text representation is
// the ugly Go default.
func parseDBTimestamp(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	if i := strings.Index(s, " m=+"); i > 0 {
		s = s[:i]
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
