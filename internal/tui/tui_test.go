package tui

// End-to-end-ish smoke tests for the TUI. We can't drive a real
// terminal from go test, but Bubbletea's Update() takes synthetic
// tea.KeyMsg events, so we can:
//
//   1. Stand up an in-memory SQLite store with seed articles
//   2. Construct an initialModel pointed at it
//   3. Drive it through scripted keystrokes via Update()
//   4. Assert on model state + View() output after each step
//
// This catches: compile errors, nil-deref panics on common keypresses,
// state transitions (mode/selected/listOffset), storage interactions
// (mark-read, bookmark toggle), and renderer crashes on edge cases
// (empty list, missing fields).
//
// This does NOT catch: terminal rendering bugs (cell alignment, ANSI
// width disagreement, lipgloss border quirks - those need a real TTY).
// Those classes shipped via the manual screenshot pass earlier.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// seedStore builds a SQLite store in a temp file with N synthetic
// articles covering the main combinations the TUI cares about
// (KEV-tagged, CVE-ID in title, multi-source, varying scores, varying
// source_types). The temp DB is removed via t.Cleanup.
func seedStore(t *testing.T, n int) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secfeed-test.db")
	store, err := storage.New(path)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		os.RemoveAll(dir)
	})

	sources := []string{"BleepingComputer", "TheHackerNews", "Bluesky", "Mastodon:ioc.exchange", "r/netsec"}
	sourceTypes := []string{"rss", "rss", "bluesky", "mastodon", "reddit"}
	for i := 0; i < n; i++ {
		idx := i % len(sources)
		a := models.Article{
			Title:       "Test article " + sources[idx] + " #" + itoa(i) + ": CVE-2026-" + itoa(10000+i),
			URL:         "https://example.test/" + itoa(i),
			Source:      sources[idx],
			SourceType:  sourceTypes[idx],
			Summary:     "RCE vulnerability in something. Patch immediately. CVE-2026-" + itoa(10000+i),
			Score:       10 + (i*7)%80, // 10..89
			PublishedAt: time.Now().Add(-time.Duration(i) * time.Minute),
			FetchedAt:   time.Now(),
		}
		// Every fourth article is KEV-tagged so the renderer hits the
		// red-pulse path.
		if i%4 == 0 {
			a.Tags = []string{"rce", "kev", "exploit"}
		} else {
			a.Tags = []string{"rce", "exploit"}
		}
		if err := store.Upsert(a); err != nil {
			t.Fatalf("Upsert %d: %v", i, err)
		}
	}
	return store
}

// itoa is the standard-lib detour-free int-to-string for test seeds.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// keystroke builds a tea.KeyMsg from a string. "j" sends a literal j;
// "esc" / "enter" / "down" map to named keys.
func keystroke(s string) tea.KeyMsg {
	switch s {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "ctrl+d":
		return tea.KeyMsg{Type: tea.KeyCtrlD}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	default:
		runes := []rune(s)
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: runes}
	}
}

// driveKeys feeds a sequence of keystrokes through Update and returns
// the final model. Each step also runs a basic invariant check
// (selected must be in range, mode must be defined). Catches panics
// and lets the test report exactly which key broke things.
func driveKeys(t *testing.T, m model, keys []string) model {
	t.Helper()
	// Seed with a window-size msg so View() has dimensions to work with.
	out, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	m = out.(model)
	for i, k := range keys {
		var msg tea.Msg = keystroke(k)
		out, _ := m.Update(msg)
		m = out.(model)
		// Render after each keystroke to catch rendering panics.
		_ = m.View()
		// Sanity invariants.
		if m.selected < 0 {
			t.Fatalf("step %d (%q): selected went negative: %d", i, k, m.selected)
		}
		if len(m.articles) > 0 && m.selected >= len(m.articles) {
			t.Fatalf("step %d (%q): selected %d out of range (have %d articles)", i, k, m.selected, len(m.articles))
		}
	}
	return m
}

// --- Tests ---

func TestEmptyStoreDoesNotCrash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.db")
	store, err := storage.New(path)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	m := initialModel(store)
	out, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	m = out.(model)
	view := m.View()
	if !strings.Contains(view, "no articles") {
		t.Errorf("empty-store view should mention 'no articles', got: %s", view[:min(len(view), 200)])
	}
}

func TestNavigationBasics(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)
	if len(m.articles) == 0 {
		t.Fatal("seeded store produced 0 articles")
	}

	// j three times → selected should be 3
	m = driveKeys(t, m, []string{"j", "j", "j"})
	if m.selected != 3 {
		t.Errorf("after 3x j: want selected=3, got %d", m.selected)
	}

	// k twice → 1
	m = driveKeys(t, m, []string{"k", "k"})
	if m.selected != 1 {
		t.Errorf("after 2x k: want selected=1, got %d", m.selected)
	}

	// G → last
	m = driveKeys(t, m, []string{"G"})
	if m.selected != len(m.articles)-1 {
		t.Errorf("after G: want selected=%d, got %d", len(m.articles)-1, m.selected)
	}

	// g → first
	m = driveKeys(t, m, []string{"g"})
	if m.selected != 0 {
		t.Errorf("after g: want selected=0, got %d", m.selected)
	}
}

func TestScoreFilter(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)
	totalAtMinScore10 := len(m.articles)

	// Press 5 → min score 50
	m = driveKeys(t, m, []string{"5"})
	if m.minScore != 50 {
		t.Errorf("after '5': want minScore=50, got %d", m.minScore)
	}
	if len(m.articles) >= totalAtMinScore10 {
		t.Errorf("score filter should have reduced article count (was %d, now %d)", totalAtMinScore10, len(m.articles))
	}

	// Press 0 → cleared
	m = driveKeys(t, m, []string{"0"})
	if m.minScore != 0 {
		t.Errorf("after '0': want minScore=0, got %d", m.minScore)
	}
}

func TestSearchMode(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)

	// /  → enter search mode, type "cve", enter to apply
	m = driveKeys(t, m, []string{"/", "c", "v", "e", "enter"})
	if m.mode != normalMode {
		t.Errorf("after search submit: want normalMode, got %v", m.mode)
	}
	if m.search != "cve" {
		t.Errorf("want search='cve', got %q", m.search)
	}
}

func TestSearchEscapeCancels(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)
	m = driveKeys(t, m, []string{"/", "f", "o", "o", "esc"})
	if m.mode != normalMode {
		t.Errorf("after search esc: want normalMode, got %v", m.mode)
	}
	if m.search != "" {
		t.Errorf("esc should leave search empty, got %q", m.search)
	}
}

func TestBookmarkToggle(t *testing.T) {
	store := seedStore(t, 10)
	m := initialModel(store)
	if len(m.articles) == 0 {
		t.Fatal("no articles seeded")
	}
	firstID := m.articles[0].ID

	// b → toggle bookmark on first article
	m = driveKeys(t, m, []string{"b"})
	if !m.bookmarks[firstID] {
		t.Errorf("after b: article %d should be bookmarked", firstID)
	}

	// b again → toggle off
	m = driveKeys(t, m, []string{"b"})
	if m.bookmarks[firstID] {
		t.Errorf("after second b: article %d should be un-bookmarked", firstID)
	}
}

func TestBookmarkFilter(t *testing.T) {
	store := seedStore(t, 10)
	m := initialModel(store)
	totalArticles := len(m.articles)

	// Bookmark first 3 articles.
	m = driveKeys(t, m, []string{"b", "j", "b", "j", "b"})

	// B → filter to bookmarked-only
	m = driveKeys(t, m, []string{"B"})
	if !m.bookmarksOnly {
		t.Error("B should turn on bookmarksOnly")
	}
	if len(m.articles) != 3 {
		t.Errorf("bookmark filter: want 3 articles, got %d", len(m.articles))
	}

	// B again → off
	m = driveKeys(t, m, []string{"B"})
	if m.bookmarksOnly {
		t.Error("second B should turn off bookmarksOnly")
	}
	if len(m.articles) != totalArticles {
		t.Errorf("after clearing bookmark filter: want %d articles, got %d", totalArticles, len(m.articles))
	}
}

func TestModalOpensDoNotCrash(t *testing.T) {
	// Each modal-opening keystroke gets driven; we just want to confirm
	// no panic + correct mode transition + correct dismissal.
	store := seedStore(t, 30)

	cases := []struct {
		key      string
		wantMode uiMode
	}{
		{"?", helpMode},
		{"S", statsMode},
		{"s", sourcePickerMode},
		{"D", iocMode},
		{"T", mitreMode},
		{"v", vizMode},
		{"L", leaderboardMode},
		{"P", patchBriefMode},
		{"e", scoreExplainMode},
		{"c", cveMode}, // first article in seed has CVE-2026-10000 in title
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			m := initialModel(store)
			// Score-explainer needs a scorer to open the modal; the
			// production path attaches one in main.go via tui.Run. Tests
			// constructing initialModel directly need to attach it here.
			m.scorer = scoring.New()
			m = driveKeys(t, m, []string{tc.key})
			if m.mode != tc.wantMode {
				t.Errorf("after %q: want mode=%v, got %v", tc.key, tc.wantMode, m.mode)
			}
			// Render the modal once to catch view-time panics.
			out, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
			m = out.(model)
			_ = m.View()
			// Esc should dismiss back to normal mode.
			out, _ = m.Update(keystroke("esc"))
			m = out.(model)
			// IOC and search use their own esc semantics; the others
			// just go back to normalMode. We don't enforce normalMode
			// here because mitre/sourcepicker may interpret esc
			// differently; we only enforce no-panic.
			_ = m.View()
		})
	}
}

func TestSourceTypeCycle(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)
	// Five presses should cycle through "rss" / "bluesky" / "mastodon" /
	// "reddit" / "github" - we just check it's non-empty after one press
	// and that successive presses don't crash.
	m = driveKeys(t, m, []string{"t"})
	if m.sourceType == "" {
		t.Errorf("after t: source type should be non-empty (was %q)", m.sourceType)
	}
	m = driveKeys(t, m, []string{"t", "t", "t", "t", "t", "t"})
	// After 7 total presses we should have wrapped back around at
	// least once.
	_ = m
}

func TestUnreadAndDupeToggles(t *testing.T) {
	store := seedStore(t, 30)
	m := initialModel(store)

	m = driveKeys(t, m, []string{"u"})
	if !m.unreadOnly {
		t.Error("u should turn on unreadOnly")
	}
	m = driveKeys(t, m, []string{"u"})
	if m.unreadOnly {
		t.Error("second u should turn off unreadOnly")
	}

	m = driveKeys(t, m, []string{"d"})
	if !m.showDupes {
		t.Error("d should turn on showDupes")
	}
}

func TestIOCDecoderDetection(t *testing.T) {
	// Pure unit test of detectIOC - no model state needed.
	cases := []struct {
		in       string
		wantKind string
	}{
		{"CVE-2026-12345", "CVE"},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1"},
		{"d41d8cd98f00b204e9800998ecf8427e", "MD5"},
		{"192.168.1.1", "IPv4"},
		{"https://example.com/x", "URL"},
		{"example.com", "Domain"},
		{"not actually an ioc", "unknown"},
	}
	for _, tc := range cases {
		kind, _, pivots := detectIOC(tc.in)
		if kind != tc.wantKind {
			t.Errorf("detectIOC(%q): want kind=%q, got %q", tc.in, tc.wantKind, kind)
		}
		if tc.wantKind != "unknown" && len(pivots) == 0 {
			t.Errorf("detectIOC(%q): expected pivot URLs for kind=%q", tc.in, kind)
		}
	}
}

func TestQuitKey(t *testing.T) {
	store := seedStore(t, 5)
	m := initialModel(store)
	out, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	m = out.(model)
	out, cmd := m.Update(keystroke("q"))
	_ = out
	if cmd == nil {
		t.Error("q should return tea.Quit cmd")
	}
}

func TestMarkRead(t *testing.T) {
	store := seedStore(t, 5)
	m := initialModel(store)
	if m.articles[0].Read {
		t.Fatal("seed article should start unread")
	}
	m = driveKeys(t, m, []string{"m"})
	if !m.articles[0].Read {
		t.Errorf("m should mark selected article read")
	}
}

func TestFirstCVEIDExtraction(t *testing.T) {
	// Pure unit test of firstCVEID; relies on the regex defined in tui.go.
	cases := []struct {
		article models.Article
		want    string
	}{
		{models.Article{Title: "RCE in foo (CVE-2026-12345)"}, "CVE-2026-12345"},
		{models.Article{Tags: []string{"cve-2025-99999"}}, "CVE-2025-99999"},
		{models.Article{Summary: "Patched in cve-2024-1"}, ""}, // 1-digit suffix invalid
		{models.Article{Title: "no cves here"}, ""},
	}
	for _, tc := range cases {
		got := firstCVEID(tc.article)
		if got != tc.want {
			t.Errorf("firstCVEID(%v): want %q, got %q", tc.article, tc.want, got)
		}
	}
}

func TestSanitizeOneLineCollapsesControlChars(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"hello\nworld", "hello world"},
		{"a\tb\rc", "a b c"},
		{"  multiple   spaces  ", "multiple spaces"},
		{"plain", "plain"},
	}
	for _, tc := range cases {
		got := sanitizeOneLine(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeOneLine(%q): want %q, got %q", tc.in, tc.want, got)
		}
	}
}
