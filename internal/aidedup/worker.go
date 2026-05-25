// Package aidedup runs the LLM-assisted semantic-deduplication pass. The
// sibling internal/dedup package handles URL/title-canonical dedup at
// ingest; THIS worker is the second stage that groups articles describing
// the same incident across different sources.
//
// One batch per cycle, max ~50 articles per batch, score >= 10 to skip
// junk. Cost per cycle is well under a cent; the operator pays once
// every ~30 minutes regardless of how many users read the feed.
package aidedup

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

type Worker struct {
	store    *storage.Store
	ai       ai.Summarizer
	interval time.Duration
	window   time.Duration
	batch    int
	minScore int

	mu      sync.Mutex
	lastRun time.Time
}

func New(store *storage.Store, summarizer ai.Summarizer) *Worker {
	return &Worker{
		store:    store,
		ai:       summarizer,
		interval: 30 * time.Minute,
		window:   2 * time.Hour, // look back N hours for the dedup pass
		batch:    50,
		minScore: 10,
	}
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	// One immediate tick on boot so a fresh deploy gets dedup'd within
	// minutes, not "wait 30 minutes."
	w.tick(ctx)
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
	w.lastRun = time.Now()
	w.mu.Unlock()

	since := time.Now().Add(-w.window)
	articles, err := w.store.ArticlesForDedup(since, w.minScore, w.batch)
	if err != nil {
		log.Printf("[dedup] list articles: %v", err)
		return
	}
	if len(articles) < 4 {
		// Not worth a LLM call - dedup is irrelevant on tiny batches.
		return
	}

	items := make([]ai.ClusterItem, 0, len(articles))
	for _, a := range articles {
		items = append(items, ai.ClusterItem{
			ID:      int64(a.ID),
			Title:   a.Title,
			Summary: a.Summary,
		})
	}

	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	groups, err := w.ai.ClusterArticles(cctx, items)
	if err != nil {
		log.Printf("[dedup] cluster failed: %v", err)
		return
	}

	marked := 0
	for _, g := range groups {
		// Skip a group if the primary isn't one of the candidates we
		// sent (LLM hallucination guard).
		if !inItems(items, g.Primary) {
			continue
		}
		for _, d := range g.Dupes {
			if d == g.Primary || !inItems(items, d) {
				continue
			}
			if err := w.store.MarkDuplicate(d, g.Primary); err != nil {
				log.Printf("[dedup] mark %d -> %d: %v", d, g.Primary, err)
				continue
			}
			marked++
		}
	}
	if marked > 0 {
		log.Printf("[dedup] clustered %d article(s) across %d group(s) from a batch of %d",
			marked, len(groups), len(items))
	}
}

func inItems(items []ai.ClusterItem, id int64) bool {
	for _, it := range items {
		if it.ID == id {
			return true
		}
	}
	return false
}
