package dedup

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	trackingParams = map[string]bool{
		"utm_source": true, "utm_medium": true, "utm_campaign": true,
		"utm_term": true, "utm_content": true, "utm_id": true,
		"fbclid": true, "gclid": true, "ref": true, "source": true,
		"mc_cid": true, "mc_eid": true, "_ga": true, "hsCtaTracking": true,
		"mkt_tok": true, "trk": true, "trkCampaign": true,
	}
	nonAlpha   = regexp.MustCompile(`[^a-z0-9\s]`)
	multiSpace = regexp.MustCompile(`\s+`)
)

func NormalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	u.Host = strings.TrimPrefix(u.Host, "www.")
	u.Fragment = ""
	u.Scheme = "https"

	q := u.Query()
	for param := range trackingParams {
		q.Del(param)
	}
	u.RawQuery = q.Encode()

	result := u.String()
	result = strings.TrimRight(result, "/")
	if u.RawQuery == "" {
		result = strings.TrimSuffix(result, "?")
	}
	return result
}

func NormalizeTitle(title string) string {
	t := strings.ToLower(title)
	t = nonAlpha.ReplaceAllString(t, " ")
	t = multiSpace.ReplaceAllString(t, " ")
	return strings.TrimSpace(t)
}

func TitleWords(title string) map[string]bool {
	words := make(map[string]bool)
	for _, w := range strings.Fields(NormalizeTitle(title)) {
		if len(w) < 3 || isStopWord(w) {
			continue
		}
		words[w] = true
	}
	return words
}

func TitleSimilarity(a, b string) float64 {
	wa := TitleWords(a)
	wb := TitleWords(b)
	if len(wa) == 0 || len(wb) == 0 {
		return 0
	}

	intersection := 0
	for w := range wa {
		if wb[w] {
			intersection++
		}
	}

	union := len(wa) + len(wb) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func IsDuplicate(titleA, urlA, titleB, urlB string) bool {
	if NormalizeURL(urlA) == NormalizeURL(urlB) {
		return true
	}
	sim := TitleSimilarity(titleA, titleB)
	return sim >= 0.55
}

func isStopWord(w string) bool {
	stops := map[string]bool{
		"the": true, "and": true, "for": true, "are": true,
		"but": true, "not": true, "you": true, "all": true,
		"can": true, "has": true, "was": true, "one": true,
		"our": true, "out": true, "its": true, "this": true,
		"that": true, "with": true, "have": true, "from": true,
		"been": true, "will": true, "they": true, "into": true,
		"than": true, "also": true, "what": true, "when": true,
		"who": true, "how": true, "new": true, "about": true,
		"which": true, "their": true, "there": true, "would": true,
		"could": true, "being": true, "after": true, "more": true,
	}
	return stops[w]
}
