// Package aitriage runs as a goroutine, scanning the article corpus for
// items that don't yet have a cached "what? so what?" one-liner and
// generating one for each. Triage lines power the inline blurb shown
// next to article titles for Pro users in the /app reader.
//
// Bounded cost: only articles published in the last 72h with score >= 30
// are eligible per pass. Each call is ~80 output tokens × Haiku 4.5 =
// ~$0.0005 per article. At ~30-50 eligible articles per cycle = a few
// pennies per hour, capped by article volume not user count.
package aitriage

import (
	"context"
	"encoding/json"
	"errors"
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

	mu       sync.Mutex
	lastTick time.Time
}

// New returns a worker that ticks every 5 minutes. Cheap interval -
// most articles arrive in bursts on poll boundaries, and we want triage
// lines to show up in the reader UI within a minute or two of an
// article landing.
func New(store *storage.Store, summarizer ai.Summarizer) *Worker {
	return &Worker{
		store:    store,
		ai:       summarizer,
		interval: 5 * time.Minute,
	}
}

func (w *Worker) Run(ctx context.Context) {
	// Fire once at startup so the first batch lands without waiting a
	// full interval.
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

	// Pull candidates: high-score articles from the last 72h with no
	// cached triage yet. Cap at 25 per cycle so a backlog doesn't blow
	// the budget on one tick.
	rows, err := w.store.DB().Query(`
		SELECT a.id, a.title, a.source, a.summary, a.score, a.tags
		  FROM articles a
		  LEFT JOIN article_ai_triage t ON t.article_id = a.id
		 WHERE a.duplicate_of IS NULL
		   AND a.score >= 30
		   AND a.published_at >= datetime('now', '-72 hours')
		   AND t.article_id IS NULL
		 ORDER BY a.score DESC, a.published_at DESC
		 LIMIT 25
	`)
	if err != nil {
		log.Printf("[aitriage] candidate query: %v", err)
		return
	}

	type pending struct {
		id      int64
		article ai.Article
	}
	var batch []pending
	for rows.Next() {
		var id int64
		var title, source, summary, tagsJSON string
		var score int
		if err := rows.Scan(&id, &title, &source, &summary, &score, &tagsJSON); err != nil {
			continue
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		batch = append(batch, pending{
			id: id,
			article: ai.Article{
				Title: title, Source: source, Summary: summary,
				Score: score, Tags: tags,
			},
		})
	}
	rows.Close()
	if len(batch) == 0 {
		return
	}

	generated := 0
	for _, p := range batch {
		select {
		case <-ctx.Done():
			return
		default:
		}
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		line, err := w.ai.TriageArticle(cctx, p.article)
		cancel()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Printf("[aitriage] article %d: %v", p.id, err)
			}
			continue
		}
		if err := w.store.PutArticleTriage(p.id, line, w.ai.Name()); err != nil {
			log.Printf("[aitriage] cache write %d: %v", p.id, err)
			continue
		}
		generated++
		// Small jitter between calls so we don't burst the upstream API.
		time.Sleep(80 * time.Millisecond)
	}
	if generated > 0 {
		log.Printf("[aitriage] generated %d new triage line(s)", generated)
	}
}
