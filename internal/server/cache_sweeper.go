package server

import (
	"context"
	"log"
	"time"
)

// startCacheSweeper launches a goroutine that periodically removes
// expired entries from the in-memory caches added this week. Without
// this they grow forever - TTL is checked on read but expired entries
// are never deleted.
//
// Also enforces a hard cap on cvePageCache (the only cache keyed on
// user-controllable input). An attacker hitting /cve/CVE-9999-NNNNNN
// with sequential suffixes could otherwise grow the cache to NVD's full
// ~240k CVE space.
//
// Called once from main.go after server.New() and runs for the process
// lifetime; exits on ctx.Done() so SIGINT shutdown is clean.
func (s *Server) StartCacheSweeper(ctx context.Context) {
	go func() {
		// Sweep at half the shortest TTL so most expired entries are
		// gone within 2.5 minutes of their natural expiry.
		t := time.NewTicker(2*time.Minute + 30*time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepCaches()
				s.sweepWhatsNew()
			}
		}
	}()
}

// cvePageHardCap is the most entries we'll keep in cvePageCache. Each
// entry is a rendered HTML body (5-15 KB), so 2000 entries is roughly
// 10-30 MB. Past the cap we drop every expired entry first, then any
// remaining oldest-expiry entries until under the cap.
const cvePageHardCap = 2000

// hottestCVEHardCap and preKEVHardCap are small because both are keyed
// on a small set of (hours, limit) permutations; they should never grow
// past a few dozen entries naturally.
const hottestCVEHardCap = 64
const preKEVHardCap = 64

// sweepCaches walks every package-level cache map, removes expired
// entries, and enforces hard size caps. Each cache has its own mutex
// so the sweep doesn't block more than briefly.
func sweepCaches() {
	now := time.Now()

	// cvePageCache: TTL sweep + hard cap.
	cvePageMu.Lock()
	for k, e := range cvePageCache {
		if now.After(e.expiry) {
			delete(cvePageCache, k)
		}
	}
	if len(cvePageCache) > cvePageHardCap {
		// Build a slice of (key, expiry) so we can drop the entries
		// closest to expiry first. Simple O(n log n) sort; n is at
		// most a few thousand on the sweep that triggers this.
		evictOldest(cvePageCache, len(cvePageCache)-cvePageHardCap)
	}
	cvePageMu.Unlock()

	// hottestCVECache: TTL sweep + cap. Keyed on (hours|limit) which is
	// bounded by the frontend's allowed inputs, so cap is small.
	hottestCVEMu.Lock()
	for k, e := range hottestCVECache {
		if now.After(e.expiry) {
			delete(hottestCVECache, k)
		}
	}
	if len(hottestCVECache) > hottestCVEHardCap {
		evictOldestHottest(len(hottestCVECache) - hottestCVEHardCap)
	}
	hottestCVEMu.Unlock()

	// preKEVCache: same shape as hottestCVECache.
	preKEVCacheMu.Lock()
	for k, e := range preKEVCache {
		if now.After(e.expiry) {
			delete(preKEVCache, k)
		}
	}
	if len(preKEVCache) > preKEVHardCap {
		evictOldestPreKEV(len(preKEVCache) - preKEVHardCap)
	}
	preKEVCacheMu.Unlock()

	// Tail caches that hold one entry, but sweep them too for hygiene.
	statsCache.mu.Lock()
	if statsCache.data != nil && now.After(statsCache.at.Add(5*time.Minute)) {
		statsCache.data = nil
	}
	statsCache.mu.Unlock()

	feedCache.mu.Lock()
	if feedCache.body != nil && now.After(feedCache.at.Add(10*time.Minute)) {
		feedCache.body = nil
	}
	feedCache.mu.Unlock()

	sitemapCVECache.mu.Lock()
	if sitemapCVECache.body != nil && now.After(sitemapCVECache.expiry) {
		sitemapCVECache.body = nil
	}
	sitemapCVECache.mu.Unlock()
}

// sweepWhatsNew clears expired per-user "while you were gone" cache
// entries. This is a Server-method because whatsNewCache lives on the
// Server struct (rather than package-level like the others).
func (s *Server) sweepWhatsNew() {
	now := time.Now()
	s.whatsNewMu.Lock()
	for k, e := range s.whatsNewCache {
		if e == nil || now.After(e.expiry) {
			delete(s.whatsNewCache, k)
		}
	}
	s.whatsNewMu.Unlock()
}

// evictOldest removes the n entries with the smallest expiry (closest
// to "already expired") from the cvePageCache. Caller holds the lock.
// Cheap because the cache is at most cvePageHardCap+1 = 2001 entries at
// the moment of call.
func evictOldest(m map[string]cvePageCacheEntry, n int) {
	if n <= 0 {
		return
	}
	type kv struct {
		k      string
		expiry time.Time
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k: k, expiry: v.expiry})
	}
	// Selection-sort the n oldest. Faster than full sort because n is
	// usually small relative to len(all).
	for i := 0; i < n && i < len(all); i++ {
		minIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j].expiry.Before(all[minIdx].expiry) {
				minIdx = j
			}
		}
		all[i], all[minIdx] = all[minIdx], all[i]
		delete(m, all[i].k)
	}
	log.Printf("[cache-sweep] cvePageCache: evicted %d oldest entries (was at cap)", n)
}

// evictOldestHottest is the same as evictOldest but typed for the
// hottestCVECache value shape. Go generics would consolidate these but
// the duplication is tiny and explicit types are clearer at this scale.
func evictOldestHottest(n int) {
	if n <= 0 {
		return
	}
	type kv struct {
		k      string
		expiry time.Time
	}
	all := make([]kv, 0, len(hottestCVECache))
	for k, v := range hottestCVECache {
		all = append(all, kv{k: k, expiry: v.expiry})
	}
	for i := 0; i < n && i < len(all); i++ {
		minIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j].expiry.Before(all[minIdx].expiry) {
				minIdx = j
			}
		}
		all[i], all[minIdx] = all[minIdx], all[i]
		delete(hottestCVECache, all[i].k)
	}
}

func evictOldestPreKEV(n int) {
	if n <= 0 {
		return
	}
	type kv struct {
		k      string
		expiry time.Time
	}
	all := make([]kv, 0, len(preKEVCache))
	for k, v := range preKEVCache {
		all = append(all, kv{k: k, expiry: v.expiry})
	}
	for i := 0; i < n && i < len(all); i++ {
		minIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j].expiry.Before(all[minIdx].expiry) {
				minIdx = j
			}
		}
		all[i], all[minIdx] = all[minIdx], all[i]
		delete(preKEVCache, all[i].k)
	}
}
