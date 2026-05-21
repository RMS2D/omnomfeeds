// Package patchtuesday auto-generates AI summaries of vendor patch-day
// releases (Microsoft / Adobe Patch Tuesday, Oracle CPU). The worker
// ticks hourly; on each tick it asks "is today a patch day for any
// vendor I know about?" and, if so, whether a brief has already been
// generated for that vendor+date. If not, it pulls the last 24h of
// vendor-tagged articles and asks the AI to summarise.
//
// Threshold-triggered vendors (Apple, Linux distros, browser stable
// channels) are stubbed for v1 - the worker recognises their names in
// the config table but the threshold detector is "coming soon".
package patchtuesday

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// Vendor is a single tracked patch-day source.
type Vendor struct {
	Name     string   // human-readable (Microsoft, Adobe, Oracle, ...)
	Slug     string   // lowercase id used in DB rows + frontend toggles
	Keywords []string // title/summary/tag substrings that pick out their articles
	DueToday func(t time.Time) bool
}

// Calendar-pinned vendors. Threshold-triggered vendors (Apple security
// updates, Linux distro waves, browser stable channels) live in the
// frontend toggle UI for v2; this list is what the worker actually fires
// against.
var Vendors = []Vendor{
	{
		Name: "Microsoft", Slug: "microsoft",
		Keywords: []string{"microsoft", "windows", "edge", "azure", "exchange", "outlook", "office", "sharepoint", "msrc", "patch tuesday", "defender", "intune"},
		DueToday: isSecondTuesday,
	},
	{
		Name: "Adobe", Slug: "adobe",
		Keywords: []string{"adobe", "acrobat", "photoshop", "illustrator", "indesign", "premiere", "magento", "coldfusion", "after effects"},
		DueToday: isSecondTuesday,
	},
	{
		Name: "Oracle", Slug: "oracle",
		Keywords: []string{"oracle", "weblogic", "mysql", "solaris", "java se", "openjdk", "peoplesoft", "primavera", "fusion middleware", "oracle cpu"},
		DueToday: isOracleCPUDay,
	},
}

// isSecondTuesday reports whether t falls on the 2nd Tuesday of its
// month (Microsoft + Adobe Patch Tuesday).
func isSecondTuesday(t time.Time) bool {
	if t.Weekday() != time.Tuesday {
		return false
	}
	d := t.Day()
	return d >= 8 && d <= 14
}

// isOracleCPUDay reports whether t is the 3rd Tuesday of January, April,
// July, or October (Oracle's Critical Patch Update schedule).
func isOracleCPUDay(t time.Time) bool {
	if t.Weekday() != time.Tuesday {
		return false
	}
	m := t.Month()
	if m != time.January && m != time.April && m != time.July && m != time.October {
		return false
	}
	d := t.Day()
	return d >= 15 && d <= 21
}

// Worker is the periodic patch-brief generator. Holds refs to the
// dependencies it needs and a mutex over its tick clock so external
// callers can poke it for status without racing the loop.
type Worker struct {
	store    *storage.Store
	ai       ai.Summarizer
	interval time.Duration

	mu       sync.Mutex
	lastTick time.Time
}

// New returns a worker with a 1-hour tick. The hour cadence is fine -
// we only generate once per vendor per day; an hour of latency between
// "patch day starts" and "brief lands in /api/briefs/patch" is fine for
// a side-project SaaS.
func New(store *storage.Store, summarizer ai.Summarizer) *Worker {
	return &Worker{
		store:    store,
		ai:       summarizer,
		interval: 1 * time.Hour,
	}
}

// Run blocks until ctx is cancelled, calling tick once at startup then
// once per interval. Launch as `go w.Run(ctx)` from main.
func (w *Worker) Run(ctx context.Context) {
	// Fire once immediately so a fresh deploy on patch day doesn't have
	// to wait an hour for the first generation.
	w.tick(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	w.mu.Lock()
	w.lastTick = time.Now()
	w.mu.Unlock()

	if w.ai == nil {
		return
	}

	// Use UTC consistently so "today" doesn't shift around timezones.
	now := time.Now().UTC()
	today := now.Format("2006-01-02")

	for _, v := range Vendors {
		if !v.DueToday(now) {
			continue
		}
		existing, _ := w.store.GetPatchBrief(v.Slug, today)
		if existing != nil {
			continue
		}
		// Window: 24h ending at the current tick, so a Tuesday morning
		// tick picks up Tuesday's drop AND any late Monday-evening
		// posts that referenced the upcoming release.
		windowEnd := now
		windowStart := now.Add(-24 * time.Hour)
		articles, err := w.store.VendorArticles(windowStart, windowEnd, v.Keywords, 80)
		if err != nil {
			log.Printf("[patchtuesday] %s: vendor article query: %v", v.Slug, err)
			continue
		}
		if len(articles) == 0 {
			log.Printf("[patchtuesday] %s: 0 articles in window, skipping brief", v.Slug)
			continue
		}

		aiArts := make([]ai.Article, 0, len(articles))
		for _, a := range articles {
			aiArts = append(aiArts, ai.Article{
				Title: a.Title, Score: a.Score, Tags: a.Tags,
				Source: a.Source, Summary: a.Summary,
			})
			if len(aiArts) >= ai.MaxArticles {
				break
			}
		}

		cctx, cancel := context.WithTimeout(ctx, 95*time.Second)
		text, err := w.ai.Summarize(cctx, aiArts)
		cancel()
		if err != nil {
			log.Printf("[patchtuesday] %s: summarise: %v", v.Slug, err)
			continue
		}

		if err := w.store.PutPatchBrief(storage.PatchBrief{
			Vendor:       v.Slug,
			BriefDate:    today,
			BriefText:    text,
			ArticleCount: len(articles),
			WindowStart:  windowStart,
			WindowEnd:    windowEnd,
		}); err != nil {
			log.Printf("[patchtuesday] %s: persist: %v", v.Slug, err)
			continue
		}
		log.Printf("[patchtuesday] %s brief generated for %s (%d articles)", v.Slug, today, len(articles))
	}
}
