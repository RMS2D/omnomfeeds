// Package tui is the Bubbletea terminal reader. Reads the same SQLite
// the HTTP daemon writes to; WAL handles concurrent access.
package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/RMS2D/omnomfeeds/internal/ai"
	"github.com/RMS2D/omnomfeeds/internal/cve"
	"github.com/RMS2D/omnomfeeds/internal/models"
	"github.com/RMS2D/omnomfeeds/internal/scoring"
	"github.com/RMS2D/omnomfeeds/internal/storage"
)

// openInBrowser opens url in the OS default browser. Errors swallowed
// so a failed shell-out doesn't drop the user out of the TUI.
func openInBrowser(url string) error {
	if url == "" {
		return nil
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Empty string before url is the window title for `start`.
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// Run is the TUI entry point. nvd/epss/summarizer/scorer are optional.
func Run(store *storage.Store, nvd *cve.NVDClient, epss *cve.EPSSClient, summarizer ai.Summarizer, scorer *scoring.Scorer) error {
	// runewidth auto-detect via LANG is unreliable on Windows. Force narrow.
	runewidth.DefaultCondition.EastAsianWidth = false

	m := initialModel(store)
	m.nvd = nvd
	m.epss = epss
	m.ai = summarizer
	m.scorer = scorer
	// Mouse cell-motion was causing artifacts on some Windows terminals -
	// the alt-screen mode is enough for the launch-scope TUI.
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type uiMode int

const (
	normalMode uiMode = iota
	searchMode
	helpMode
	cveMode
	statsMode
	sourcePickerMode
	iocMode
	mitreMode
	vizMode
	aiBriefMode
	leaderboardMode
	patchBriefMode
	scoreExplainMode
)

// 4-7 digit suffix per NVD spec. Years 1990+ to skip false positives.
var cveIDRegex = regexp.MustCompile(`(?i)CVE-(?:19|20)\d{2}-\d{4,7}`)

type model struct {
	store    *storage.Store
	nvd      *cve.NVDClient
	epss     *cve.EPSSClient
	ai       ai.Summarizer
	scorer   *scoring.Scorer
	articles []models.Article
	selected int

	width  int
	height int

	listOffset int
	loadErr    error

	minScore   int
	sourceType string
	unreadOnly bool
	showDupes  bool
	search     string

	mode        uiMode
	searchInput string

	cveID        string
	cveConsensus []storage.CVEConsensusRow
	cveTimeline  []storage.CVETimelineEvent
	cveArticles  []models.Article
	cveDetail    *cve.CVEDetail
	cveEPSS      *cve.EPSSScore
	cveLoading   bool
	cveLoadErr   string

	stats *models.Stats

	sourceList   []string
	sourceCursor int
	sourceOffset int

	iocInput  string
	iocKind   string
	iocValue  string
	iocPivots []iocPivot

	mitreEntries []mitreEntry
	mitreCursor  int
	mitreOffset  int

	vizEntries []vizEntry

	bookmarks         map[int64]bool
	bookmarksOnly     bool
	bookmarksLoadedAt time.Time

	aiBriefBody    string
	aiBriefLoading bool
	aiBriefErr     string
	aiBriefLabel   string
	aiBriefWindow  time.Duration

	trendingCVEs     []storage.CVEActivity
	preKEVCandidates []preKEVRow

	patchBriefs []storage.PatchBrief

	scoreExplain *scoreExplainResult

	flash string
}

var sourceTypeCycle = []string{"", "rss", "bluesky", "mastodon", "reddit", "github", "ioc_feed"}

type iocPivot struct {
	label string
	url   string
}

type mitreEntry struct {
	techID string
	count  int
}

type vizEntry struct {
	source string
	count  int
}

type preKEVRow struct {
	cveID   string
	sources int
}

type scoreExplainResult struct {
	article models.Article
	matches []scoreExplainCategory
	total   int
}

type scoreExplainCategory struct {
	name   string
	weight int
	hits   []string
}

func initialModel(store *storage.Store) model {
	m := model{store: store, minScore: 10, bookmarks: map[int64]bool{}}
	m.reloadBookmarks()
	m.reloadArticles()
	return m
}

func (m *model) reloadBookmarks() {
	if m.store == nil {
		return
	}
	bs, err := m.store.BookmarkIDs()
	if err != nil || bs == nil {
		m.bookmarks = map[int64]bool{}
		return
	}
	m.bookmarks = bs
	m.bookmarksLoadedAt = time.Now()
}

func (m *model) reloadArticles() {
	// Bookmark-only uses its own query; doesn't compose with the other filters.
	if m.bookmarksOnly {
		rows, err := m.store.BookmarkedArticles(500)
		if err != nil {
			m.loadErr = err
			return
		}
		m.articles = rows
		m.loadErr = nil
		if m.selected >= len(m.articles) {
			m.selected = max(0, len(m.articles)-1)
		}
		if m.selected < 0 {
			m.selected = 0
		}
		if m.listOffset > m.selected {
			m.listOffset = m.selected
		}
		return
	}

	rows, err := m.store.List(storage.ListFilter{
		MinScore:   m.minScore,
		SourceType: m.sourceType,
		Unread:     m.unreadOnly,
		ShowDupes:  m.showDupes,
		Search:     m.search,
		Limit:      500,
	})
	if err != nil {
		m.loadErr = err
		return
	}
	m.articles = rows
	m.loadErr = nil
	if m.selected >= len(m.articles) {
		m.selected = max(0, len(m.articles)-1)
	}
	if m.selected < 0 {
		m.selected = 0
	}
	if m.listOffset > m.selected {
		m.listOffset = m.selected
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case cveLoadedMsg:
		// Discard stale results if the user moved on.
		if msg.cveID != m.cveID {
			return m, nil
		}
		m.cveLoading = false
		if msg.err != nil {
			m.cveLoadErr = msg.err.Error()
		} else {
			m.cveDetail = msg.detail
		}
		return m, nil

	case aiBriefLoadedMsg:
		m.aiBriefLoading = false
		if msg.err != nil {
			m.aiBriefErr = msg.err.Error()
		} else {
			m.aiBriefBody = msg.body
		}
		return m, nil

	case tea.KeyMsg:
		// Modal dispatch first; modal handlers capture all keys.
		switch m.mode {
		case searchMode:
			return m.updateSearch(msg)
		case helpMode:
			return m.updateHelp(msg)
		case cveMode:
			return m.updateCVE(msg)
		case statsMode:
			return m.updateStats(msg)
		case sourcePickerMode:
			return m.updateSourcePicker(msg)
		case iocMode:
			return m.updateIOC(msg)
		case mitreMode:
			return m.updateMITRE(msg)
		case vizMode:
			return m.updateViz(msg)
		case aiBriefMode:
			return m.updateAIBrief(msg)
		case leaderboardMode:
			return m.updateLeaderboards(msg)
		case patchBriefMode:
			return m.updatePatchBrief(msg)
		case scoreExplainMode:
			return m.updateScoreExplain(msg)
		}
		return m.updateNormal(msg)
	}
	return m, nil
}

func (m model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.flash = ""

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "j", "down":
		m.moveSelection(1)
	case "k", "up":
		m.moveSelection(-1)
	case "g", "home":
		m.selected = 0
		m.listOffset = 0
	case "G", "end":
		m.selected = max(0, len(m.articles)-1)
		m.ensureSelectedVisible()
	case "ctrl+d":
		m.moveSelection(m.visibleRows() / 2)
	case "ctrl+u":
		m.moveSelection(-m.visibleRows() / 2)

	case "o", "enter":
		return m, m.openSelected()
	case "m":
		m.markSelectedRead()
	case "M":
		if err := m.store.MarkAllRead(); err != nil {
			m.flash = "mark-all-read failed: " + err.Error()
		} else {
			m.flash = "all visible marked read"
			m.reloadArticles()
		}
	case "b":
		m.toggleSelectedBookmark()
	case "B":
		m.bookmarksOnly = !m.bookmarksOnly
		m.selected = 0
		m.listOffset = 0
		m.reloadArticles()
		if m.bookmarksOnly {
			m.flash = "showing bookmarked only"
		} else {
			m.flash = "showing all"
		}

	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		m.minScore = int(msg.String()[0]-'0') * 10
		m.reloadArticles()
		m.flash = fmt.Sprintf("min score: %d", m.minScore)
	case "0":
		m.minScore = 0
		m.reloadArticles()
		m.flash = "score filter cleared"
	case "t":
		m.sourceType = nextSourceType(m.sourceType)
		m.reloadArticles()
		label := m.sourceType
		if label == "" {
			label = "all"
		}
		m.flash = "source-type: " + label
	case "u":
		m.unreadOnly = !m.unreadOnly
		m.reloadArticles()
		if m.unreadOnly {
			m.flash = "showing unread only"
		} else {
			m.flash = "showing all"
		}
	case "d":
		m.showDupes = !m.showDupes
		m.reloadArticles()
		if m.showDupes {
			m.flash = "duplicates shown"
		} else {
			m.flash = "duplicates hidden"
		}

	case "/":
		m.mode = searchMode
		m.searchInput = m.search

	case "?":
		m.mode = helpMode

	case "c":
		cmd := m.openCVEPopover()
		if cmd != nil {
			return m, cmd
		}

	case "S":
		m.openStats()
	case "s":
		m.openSourcePicker()
	case "D":
		m.openIOCDecoder()
	case "T":
		m.openMITRE()
	case "v":
		m.openViz()
	case "I":
		cmd := m.openAIBrief(24 * time.Hour)
		if cmd != nil {
			return m, cmd
		}
	case "W":
		// W = same as I but scoped to last 4h.
		cmd := m.openAIBriefWithLabel(4*time.Hour, "WHILE YOU WERE GONE :: last 4h")
		if cmd != nil {
			return m, cmd
		}
	case "L":
		m.openLeaderboards()
	case "P":
		m.openPatchBrief()
	case "e":
		m.openScoreExplain()
	case "E":
		if path, err := m.exportATTACKLayer(); err != nil {
			m.flash = "ATT&CK export failed: " + err.Error()
		} else {
			m.flash = "ATT&CK layer saved → " + path
		}

	case "r":
		m.reloadArticles()
		m.flash = "reloaded"
	}
	return m, nil
}

func (m model) updateStats(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.stats = nil
	return m, nil
}

func (m model) updateViz(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.vizEntries = nil
	return m, nil
}

func (m model) updateSourcePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = normalMode
		m.sourceList = nil
	case "j", "down":
		if m.sourceCursor < len(m.sourceList)-1 {
			m.sourceCursor++
		}
	case "k", "up":
		if m.sourceCursor > 0 {
			m.sourceCursor--
		}
	case "g", "home":
		m.sourceCursor = 0
		m.sourceOffset = 0
	case "G", "end":
		m.sourceCursor = max(0, len(m.sourceList)-1)
	case "enter", " ":
		if m.sourceCursor >= 0 && m.sourceCursor < len(m.sourceList) {
			m.search = ""
			m.sourceType = ""
			m.reloadArticlesWithSource(m.sourceList[m.sourceCursor])
			m.flash = "source: " + m.sourceList[m.sourceCursor]
		}
		m.mode = normalMode
		m.sourceList = nil
	case "0":
		m.reloadArticlesWithSource("")
		m.flash = "source filter cleared"
		m.mode = normalMode
		m.sourceList = nil
	}
	return m, nil
}

func (m model) updateMITRE(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.mode = normalMode
		m.mitreEntries = nil
	case "j", "down":
		if m.mitreCursor < len(m.mitreEntries)-1 {
			m.mitreCursor++
		}
	case "k", "up":
		if m.mitreCursor > 0 {
			m.mitreCursor--
		}
	case "g":
		m.mitreCursor = 0
	case "G":
		m.mitreCursor = max(0, len(m.mitreEntries)-1)
	case "enter", " ":
		if m.mitreCursor >= 0 && m.mitreCursor < len(m.mitreEntries) {
			m.search = m.mitreEntries[m.mitreCursor].techID
			m.reloadArticles()
			m.flash = "filtered to " + m.mitreEntries[m.mitreCursor].techID
		}
		m.mode = normalMode
		m.mitreEntries = nil
	}
	return m, nil
}

func (m model) updateIOC(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = normalMode
		m.iocInput, m.iocKind, m.iocValue = "", "", ""
		m.iocPivots = nil
	case "enter":
		m.iocKind, m.iocValue, m.iocPivots = detectIOC(m.iocInput)
	case "backspace", "ctrl+h":
		if n := len(m.iocInput); n > 0 {
			runes := []rune(m.iocInput)
			m.iocInput = string(runes[:len(runes)-1])
		}
	case "ctrl+u":
		m.iocInput = ""
		m.iocKind, m.iocValue, m.iocPivots = "", "", nil
	default:
		if len(msg.Runes) > 0 {
			m.iocInput += string(msg.Runes)
			m.iocKind, m.iocValue, m.iocPivots = detectIOC(m.iocInput)
		}
	}
	return m, nil
}

func (m *model) reloadArticlesWithSource(src string) {
	rows, err := m.store.List(storage.ListFilter{
		MinScore:   m.minScore,
		SourceType: m.sourceType,
		Source:     src,
		Unread:     m.unreadOnly,
		ShowDupes:  m.showDupes,
		Search:     m.search,
		Limit:      500,
	})
	if err != nil {
		m.loadErr = err
		return
	}
	m.articles = rows
	m.loadErr = nil
	m.selected = 0
	m.listOffset = 0
}

func (m *model) openStats() {
	s, err := m.store.Stats()
	if err != nil {
		m.flash = "stats query failed: " + err.Error()
		return
	}
	m.stats = &s
	m.mode = statsMode
}

func (m *model) openSourcePicker() {
	srcs, err := m.store.Sources()
	if err != nil {
		m.flash = "source query failed: " + err.Error()
		return
	}
	m.sourceList = srcs
	m.sourceCursor = 0
	m.sourceOffset = 0
	m.mode = sourcePickerMode
}

func (m *model) openIOCDecoder() {
	m.iocInput = ""
	m.iocKind, m.iocValue, m.iocPivots = "", "", nil
	m.mode = iocMode
}

func (m *model) openMITRE() {
	freq, err := m.store.TTPFrequency(30)
	if err != nil {
		m.flash = "MITRE query failed: " + err.Error()
		return
	}
	var entries []mitreEntry
	for tid, n := range freq {
		entries = append(entries, mitreEntry{techID: tid, count: n})
	}
	// Sort by count desc, ties broken by ID asc.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].techID < entries[j].techID
	})
	m.mitreEntries = entries
	m.mitreCursor = 0
	m.mitreOffset = 0
	m.mode = mitreMode
}

func (m *model) openAIBrief(window time.Duration) tea.Cmd {
	return m.openAIBriefWithLabel(window, "")
}

func (m *model) openAIBriefWithLabel(window time.Duration, label string) tea.Cmd {
	m.aiBriefBody = ""
	m.aiBriefErr = ""
	m.aiBriefLoading = false
	m.aiBriefLabel = label
	m.aiBriefWindow = window
	m.mode = aiBriefMode
	if m.ai == nil {
		return nil
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	since := time.Now().Add(-window)
	rows, err := m.store.List(storage.ListFilter{
		MinScore: 30,
		Since:    since,
		Limit:    25,
	})
	if err != nil {
		m.aiBriefErr = "couldn't pull digest input: " + err.Error()
		return nil
	}
	if len(rows) == 0 {
		m.aiBriefErr = fmt.Sprintf("no articles in the last %s above score 30 - nothing to brief on", humanizeDuration(window))
		return nil
	}
	m.aiBriefLoading = true
	return fetchAIBrief(m.ai, rows)
}

func humanizeDuration(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

type aiBriefLoadedMsg struct {
	body string
	err  error
}

func fetchAIBrief(client ai.Summarizer, rows []models.Article) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		items := make([]ai.Article, 0, len(rows))
		for _, a := range rows {
			items = append(items, ai.Article{
				Title:   a.Title,
				Source:  a.Source,
				Summary: a.Summary,
				Score:   a.Score,
				Tags:    a.Tags,
			})
		}
		body, err := client.Summarize(ctx, items)
		return aiBriefLoadedMsg{body: body, err: err}
	}
}

func (m model) updateAIBrief(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.aiBriefBody = ""
	m.aiBriefErr = ""
	m.aiBriefLoading = false
	return m, nil
}

func (m *model) openViz() {
	s, err := m.store.Stats()
	if err != nil {
		m.flash = "viz query failed: " + err.Error()
		return
	}
	var entries []vizEntry
	for src, n := range s.SourceBreakdown {
		entries = append(entries, vizEntry{source: src, count: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].source < entries[j].source
	})
	m.vizEntries = entries
	m.mode = vizMode
}

var (
	iocCVERegex  = regexp.MustCompile(`(?i)^CVE-(?:19|20)\d{2}-\d{4,7}$`)
	iocSHA256Reg = regexp.MustCompile(`(?i)^[0-9a-f]{64}$`)
	iocSHA1Reg   = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)
	iocMD5Reg    = regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)
	iocIPv4Regex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	iocURLRegex  = regexp.MustCompile(`^https?://[^\s]+$`)
	iocDomainReg = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$`)
)

func detectIOC(raw string) (kind, value string, pivots []iocPivot) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", nil
	}
	low := strings.ToLower(s)
	upper := strings.ToUpper(s)

	switch {
	case iocCVERegex.MatchString(s):
		return "CVE", upper, []iocPivot{
			{"NVD", "https://nvd.nist.gov/vuln/detail/" + upper},
			{"CVE.org", "https://www.cve.org/CVERecord?id=" + upper},
			{"Exploit-DB", "https://www.exploit-db.com/search?cve=" + upper},
			{"GitHub PoC", "https://github.com/search?q=" + upper + "&type=code"},
		}
	case iocSHA256Reg.MatchString(s):
		return "SHA-256", low, []iocPivot{
			{"VirusTotal", "https://www.virustotal.com/gui/file/" + low},
			{"MalwareBazaar", "https://bazaar.abuse.ch/sample/" + low + "/"},
			{"HybridAnalysis", "https://hybrid-analysis.com/search?query=" + low},
			{"Triage", "https://tria.ge/s?q=" + low},
		}
	case iocSHA1Reg.MatchString(s):
		return "SHA-1", low, []iocPivot{
			{"VirusTotal", "https://www.virustotal.com/gui/file/" + low},
			{"HybridAnalysis", "https://hybrid-analysis.com/search?query=" + low},
		}
	case iocMD5Reg.MatchString(s):
		return "MD5", low, []iocPivot{
			{"VirusTotal", "https://www.virustotal.com/gui/file/" + low},
		}
	case iocIPv4Regex.MatchString(s):
		return "IPv4", s, []iocPivot{
			{"AbuseIPDB", "https://www.abuseipdb.com/check/" + s},
			{"GreyNoise", "https://viz.greynoise.io/ip/" + s},
			{"Shodan", "https://www.shodan.io/host/" + s},
			{"VirusTotal", "https://www.virustotal.com/gui/ip-address/" + s},
		}
	case iocURLRegex.MatchString(s):
		return "URL", s, []iocPivot{
			{"urlscan", "https://urlscan.io/search/#" + s},
			{"VirusTotal", "https://www.virustotal.com/gui/url/"},
		}
	case iocDomainReg.MatchString(low):
		return "Domain", low, []iocPivot{
			{"VirusTotal", "https://www.virustotal.com/gui/domain/" + low},
			{"urlscan", "https://urlscan.io/search/#" + low},
			{"crt.sh", "https://crt.sh/?q=" + low},
			{"whois", "https://www.whois.com/whois/" + low},
		}
	}
	return "unknown", s, nil
}

func (m model) updateCVE(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.cveID = ""
	m.cveConsensus = nil
	m.cveTimeline = nil
	m.cveArticles = nil
	return m, nil
}

// openCVEPopover: loads local data synchronously, kicks off async NVD fetch.
func (m *model) openCVEPopover() tea.Cmd {
	if m.selected < 0 || m.selected >= len(m.articles) {
		return nil
	}
	a := m.articles[m.selected]
	cveID := firstCVEID(a)
	if cveID == "" {
		m.flash = "no CVE-ID found in selected article"
		return nil
	}
	m.cveID = cveID
	m.cveDetail = nil
	m.cveEPSS = nil
	m.cveLoadErr = ""

	if rows, err := m.store.CVEConsensus(cveID, 30); err == nil {
		m.cveConsensus = rows
	}
	if events, err := m.store.CVETimeline(cveID); err == nil {
		m.cveTimeline = events
	}
	if articles, err := m.store.ArticlesForCVE(cveID, 20); err == nil {
		m.cveArticles = articles
	}
	if m.epss != nil {
		m.cveEPSS = m.epss.Get(cveID)
	}

	m.mode = cveMode

	if m.nvd == nil {
		return nil
	}
	m.cveLoading = true
	return fetchCVEDetail(m.nvd, cveID)
}

type cveLoadedMsg struct {
	cveID  string
	detail *cve.CVEDetail
	err    error
}

func fetchCVEDetail(client *cve.NVDClient, cveID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		d, err := client.Get(ctx, cveID)
		return cveLoadedMsg{cveID: cveID, detail: d, err: err}
	}
}

// firstCVEID scans tags, then title, then summary.
func firstCVEID(a models.Article) string {
	for _, t := range a.Tags {
		if m := cveIDRegex.FindString(strings.ToUpper(t)); m != "" {
			return strings.ToUpper(m)
		}
	}
	if m := cveIDRegex.FindString(strings.ToUpper(a.Title)); m != "" {
		return strings.ToUpper(m)
	}
	if m := cveIDRegex.FindString(strings.ToUpper(a.Summary)); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

func (m model) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.search = strings.TrimSpace(m.searchInput)
		m.mode = normalMode
		m.reloadArticles()
		if m.search == "" {
			m.flash = "search cleared"
		} else {
			m.flash = "search: " + m.search
		}
	case "esc":
		m.mode = normalMode
		m.searchInput = ""
	case "backspace", "ctrl+h":
		if n := len(m.searchInput); n > 0 {
			runes := []rune(m.searchInput)
			m.searchInput = string(runes[:len(runes)-1])
		}
	case "ctrl+u":
		m.searchInput = ""
	default:
		if len(msg.Runes) > 0 {
			m.searchInput += string(msg.Runes)
		}
	}
	return m, nil
}

func (m model) updateHelp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	return m, nil
}

func (m *model) toggleSelectedBookmark() {
	if m.selected < 0 || m.selected >= len(m.articles) {
		return
	}
	a := m.articles[m.selected]
	now, err := m.store.ToggleBookmark(a.ID)
	if err != nil {
		m.flash = "bookmark toggle failed: " + err.Error()
		return
	}
	if m.bookmarks == nil {
		m.bookmarks = map[int64]bool{}
	}
	if now {
		m.bookmarks[a.ID] = true
		m.flash = "★ bookmarked"
	} else {
		delete(m.bookmarks, a.ID)
		m.flash = "★ removed"
	}
}

func (m *model) markSelectedRead() {
	if m.selected < 0 || m.selected >= len(m.articles) {
		return
	}
	a := &m.articles[m.selected]
	if a.Read {
		m.flash = "already read"
		return
	}
	if err := m.store.MarkRead(a.ID); err != nil {
		m.flash = "mark-read failed: " + err.Error()
		return
	}
	a.Read = true
	m.flash = "marked read"
}

// openSelected marks read synchronously, opens URL via shell cmd in background.
func (m *model) openSelected() tea.Cmd {
	if m.selected < 0 || m.selected >= len(m.articles) {
		return nil
	}
	a := &m.articles[m.selected]
	url := a.URL
	if !a.Read {
		if err := m.store.MarkRead(a.ID); err == nil {
			a.Read = true
		}
	}
	m.flash = "opening: " + truncateForFlash(url)
	return func() tea.Msg {
		_ = openInBrowser(url)
		return nil
	}
}

func nextSourceType(current string) string {
	for i, v := range sourceTypeCycle {
		if v == current {
			return sourceTypeCycle[(i+1)%len(sourceTypeCycle)]
		}
	}
	return ""
}

// truncateForFlash shortens long URLs for the status bar flash.
func truncateForFlash(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		// First-frame race: WindowSizeMsg hasn't landed yet. Render a
		// terse placeholder rather than a 0x0 panic surface.
		return "loading..."
	}
	if m.loadErr != nil {
		return errorStyle.Render(fmt.Sprintf("storage error: %v\n\npress q to quit", m.loadErr))
	}

	if m.mode == helpMode {
		return m.renderHelp()
	}
	if m.mode == cveMode {
		return m.renderCVEPopover()
	}
	if m.mode == statsMode {
		return m.renderStatsModal()
	}
	if m.mode == sourcePickerMode {
		return m.renderSourcePickerModal()
	}
	if m.mode == iocMode {
		return m.renderIOCModal()
	}
	if m.mode == mitreMode {
		return m.renderMITREModal()
	}
	if m.mode == vizMode {
		return m.renderVizModal()
	}
	if m.mode == aiBriefMode {
		return m.renderAIBriefModal()
	}
	if m.mode == leaderboardMode {
		return m.renderLeaderboardModal()
	}
	if m.mode == patchBriefMode {
		return m.renderPatchBriefModal()
	}
	if m.mode == scoreExplainMode {
		return m.renderScoreExplainModal()
	}

	if len(m.articles) == 0 {
		body := dimStyle.Render("no articles match the current filters - try `0` to reset or `r` to refresh")
		header := m.renderHeader()
		status := m.renderStatus()
		return lipgloss.JoinVertical(lipgloss.Left, header, body, status)
	}

	listW, previewW := m.paneWidths()
	bottomReserved := 2
	if m.mode == searchMode {
		bottomReserved = 3
	}
	bodyH := m.height - bottomReserved

	header := m.renderHeader()

	// paneFrame eats 2 rows + 4 cells of width. Pass exact inner dims to avoid overflow.
	innerListW := listW - 4
	innerPreviewW := previewW - 4
	innerH := bodyH - 2
	listContent := m.renderList(innerListW, innerH)
	previewContent := m.renderPreview(innerPreviewW, innerH)
	listPane := paneFrame("●●●  FEED", listContent, listW, bodyH, paneTitleStyle)
	previewPane := paneFrame("READER", previewContent, previewW, bodyH, paneTitleAltStyle)
	body := lipgloss.JoinHorizontal(lipgloss.Top, listPane, previewPane)

	bottom := m.renderStatus()
	if m.mode == searchMode {
		bottom = m.renderSearchBar() + "\n" + bottom
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, body, bottom)
}

func (m model) renderHelp() string {
	titleText := lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(":: TUI keybinds ::")
	dismiss := dimStyle.Render("any key dismisses")
	innerW := 60
	pad := innerW - lipgloss.Width(titleText) - lipgloss.Width(dismiss)
	if pad < 1 {
		pad = 1
	}
	header := titleText + strings.Repeat(" ", pad) + dismiss

	lines := []string{
		header,
		"",
		modalSectionStyle.Render("Navigation"),
		"  j / k             next / prev item",
		"  g / G             top / bottom",
		"  ctrl-d / ctrl-u   half-page down / up",
		"",
		modalSectionStyle.Render("Reading"),
		"  o / Enter         open in browser (marks read)",
		"  m                 mark selected read",
		"  M                 mark all visible read",
		"  b                 toggle bookmark (★) on selected",
		"  B                 filter to bookmarked only / clear",
		"",
		modalSectionStyle.Render("Filters"),
		"  1..9              minimum score (10..90)",
		"  0                 clear score filter",
		"  /                 search title + summary",
		"  t                 cycle source-type filter",
		"  u                 toggle unread-only",
		"  d                 toggle show-duplicates",
		"",
		modalSectionStyle.Render("Tools"),
		"  c                 CVE deep-dive (CVSS / EPSS / KEV / consensus / timeline)",
		"  D                 IOC decoder (paste hash / CVE / IP / URL / domain)",
		"  T                 MITRE ATT&CK coverage",
		"  S                 Feast Stats (sources + tags)",
		"  v                 Feeding Tubes (source distribution chart)",
		"  s                 source picker (selectable list)",
		"  I                 intel brief :: last 24h (BYOK Anthropic/OpenAI)",
		"  W                 while you were gone :: last 4h",
		"  L                 leaderboards :: /trending + /pre-kev",
		"  P                 Patch Tuesday brief reader",
		"  e                 score explainer (which keywords fired?)",
		"  E                 export MITRE ATT&CK Navigator layer JSON",
		"  r                 force refresh",
		"  ?                 this overlay",
		"  q / ctrl-c        quit",
	}

	modal := modalStyle.Width(innerW + 6).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		modal,
		lipgloss.WithWhitespaceBackground(lipgloss.Color("#050709")),
	)
}

func accentText(s string) string {
	return lipgloss.NewStyle().Foreground(accent).Bold(true).Render(s)
}

// paneFrame wraps content in a titled box. Content lines must be padded to width-4 cells.
func paneFrame(title, content string, width, height int, titleStyle lipgloss.Style) string {
	if width < 8 || height < 3 {
		return content
	}
	titleLabel := titleStyle.Render(" " + title + " ")
	titleLabelW := lipgloss.Width(titleLabel)
	headerFill := width - 3 - titleLabelW - 1 - 1
	if headerFill < 1 {
		headerFill = 1
	}
	bracketL := paneBorderStyle.Render("┌─[")
	bracketR := paneBorderStyle.Render("]")
	rule := paneBorderStyle.Render(strings.Repeat("─", headerFill))
	corner := paneBorderStyle.Render("┐")
	top := bracketL + titleLabel + bracketR + rule + corner

	bottom := paneBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")

	// Don't truncate over-wide lines: ANSI strip breaks styling. Pad short ones only.
	bar := paneBorderStyle.Render("│")
	innerW := width - 4
	var bodyLines []string
	for _, line := range strings.Split(content, "\n") {
		visW := lipgloss.Width(line)
		if visW < innerW {
			line = line + strings.Repeat(" ", innerW-visW)
		}
		bodyLines = append(bodyLines, bar+" "+line+" "+bar)
	}
	for len(bodyLines) < height-2 {
		bodyLines = append(bodyLines, bar+strings.Repeat(" ", width-2)+bar)
	}
	if len(bodyLines) > height-2 {
		bodyLines = bodyLines[:height-2]
	}

	return strings.Join(append(append([]string{top}, bodyLines...), bottom), "\n")
}

func (m model) renderCVEPopover() string {
	modalW := m.width * 80 / 100
	if modalW > 110 {
		modalW = 110
	}
	if modalW < 60 {
		modalW = 60
	}
	innerW := modalW - 6

	kev := false
	var sourceArticle models.Article
	if m.selected >= 0 && m.selected < len(m.articles) {
		sourceArticle = m.articles[m.selected]
		for _, t := range sourceArticle.Tags {
			low := strings.ToLower(t)
			if low == "kev" || strings.HasPrefix(low, "kev:") {
				kev = true
				break
			}
		}
	}

	titleText := lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(":: " + m.cveID + " ::")
	dismiss := dimStyle.Render("any key dismisses")
	pad := innerW - lipgloss.Width(titleText) - lipgloss.Width(dismiss)
	if pad < 1 {
		pad = 1
	}
	header := titleText + strings.Repeat(" ", pad) + dismiss

	var kevBanner string
	if kev {
		banner := kevPulseBannerStyle.Render(runewidth.FillRight("  ●  ACTIVELY EXPLOITED  -  IN CISA KEV CATALOG  ", innerW))
		kevBanner = banner
	}

	var chipsLine string
	if len(sourceArticle.Tags) > 0 {
		var chips []string
		for _, t := range sourceArticle.Tags {
			low := strings.ToLower(t)
			if strings.Contains(low, "cve-") || strings.HasPrefix(low, "cve:") {
				continue
			}
			chips = append(chips, tagChip(low).Render(" "+low+" "))
		}
		if len(chips) > 0 {
			chipsLine = lipgloss.JoinHorizontal(lipgloss.Top, chips...)
		}
	}

	var body []string
	body = append(body, header)
	if kevBanner != "" {
		body = append(body, "")
		body = append(body, kevBanner)
	}
	if chipsLine != "" {
		body = append(body, "")
		body = append(body, chipsLine)
	}

	body = append(body, "")
	body = append(body, modalSectionStyle.Render("::  NVD + EPSS  ::"))
	switch {
	case m.cveLoading && m.cveDetail == nil:
		body = append(body, dimStyle.Render("   fetching NVD detail..."))
	case m.cveLoadErr != "":
		body = append(body, lipgloss.NewStyle().Foreground(accentRed).Render("   [!] NVD lookup failed: "+m.cveLoadErr))
	case m.cveDetail != nil:
		d := m.cveDetail
		var cvssLine string
		if d.CVSSv3Score > 0 {
			sevColor := accent
			switch strings.ToUpper(d.CVSSv3Severity) {
			case "CRITICAL":
				sevColor = accentRed
			case "HIGH":
				sevColor = accentRed
			case "MEDIUM":
				sevColor = accentAmber
			case "LOW":
				sevColor = accent
			}
			sevStyle := lipgloss.NewStyle().Foreground(sevColor).Bold(true)
			cvssLine = "  " + dimStyle.Render("CVSSv3 ") + sevStyle.Render(fmt.Sprintf("%.1f", d.CVSSv3Score)) +
				"  " + sevStyle.Render(strings.ToUpper(d.CVSSv3Severity))
			if d.CVSSv3Vector != "" {
				cvssLine += "  " + dimStyle.Render(d.CVSSv3Vector)
			}
		} else {
			cvssLine = "  " + dimStyle.Render("CVSSv3 unavailable")
		}
		body = append(body, cvssLine)
		if m.cveEPSS != nil {
			epssLine := "  " + dimStyle.Render("EPSS   ") +
				lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(fmt.Sprintf("%.1f%% pctile", m.cveEPSS.Percentile*100)) +
				"  " + dimStyle.Render(fmt.Sprintf("score %.4f", m.cveEPSS.Score))
			body = append(body, epssLine)
		}
		if d.CWE != "" {
			body = append(body, "  "+dimStyle.Render("CWE    ")+titleStyle.Render(d.CWE))
		}
		if d.Published != "" {
			body = append(body, "  "+dimStyle.Render("dates  ")+dimStyle.Render(d.Published+" → "+d.LastModified))
		}
		if d.Description != "" {
			body = append(body, "")
			desc := wordWrap(sanitizeOneLine(d.Description), innerW-2)
			for _, line := range strings.Split(desc, "\n") {
				body = append(body, "  "+line)
			}
		}
	case m.nvd == nil:
		body = append(body, dimStyle.Render("   (no NVD client wired - run with full daemon to enable)"))
	}

	body = append(body, "")
	body = append(body, modalSectionStyle.Render("::  Source consensus (last 30 days)  ::"))
	if len(m.cveConsensus) == 0 {
		body = append(body, dimStyle.Render("   (no other sources have mentioned this CVE recently)"))
	} else {
		for i, c := range m.cveConsensus {
			if i >= 10 {
				body = append(body, dimStyle.Render(fmt.Sprintf("   ... and %d more", len(m.cveConsensus)-10)))
				break
			}
			count := lipgloss.NewStyle().Foreground(accentAmber).Render(fmt.Sprintf("×%-3d", c.Count))
			seen := dimStyle.Render(humanizeAge(c.LastSeen))
			src := titleStyle.Render(runewidth.Truncate(c.Source, innerW-25, "…"))
			body = append(body, "  "+count+" "+src+"  "+seen)
		}
	}

	// Timeline: collapse to one event per Kind.
	if len(m.cveTimeline) > 0 {
		body = append(body, "")
		body = append(body, modalSectionStyle.Render("::  Timeline  ::"))
		shown := map[string]bool{}
		for _, e := range m.cveTimeline {
			if shown[e.Kind] {
				continue
			}
			shown[e.Kind] = true
			label := lipgloss.NewStyle().Foreground(accentAmber).Bold(true).Render(fmt.Sprintf("%-13s", e.Kind))
			when := dimStyle.Render(e.At.Format("2006-01-02"))
			titleTrim := runewidth.Truncate(sanitizeOneLine(e.Title), innerW-30, "…")
			body = append(body, "  "+when+"  "+label+" "+titleStyle.Render(titleTrim))
		}
	}

	if len(m.cveArticles) > 0 {
		body = append(body, "")
		body = append(body, modalSectionStyle.Render(fmt.Sprintf("::  Articles in corpus (%d)  ::", len(m.cveArticles))))
		for i, a := range m.cveArticles {
			if i >= 10 {
				body = append(body, dimStyle.Render(fmt.Sprintf("   ... and %d more", len(m.cveArticles)-10)))
				break
			}
			when := dimStyle.Render(runewidth.FillRight(humanizeAge(a.PublishedAt), 8))
			src := dimStyle.Render(runewidth.FillRight("["+runewidth.Truncate(a.Source, 18, "…")+"]", 22))
			titleTrim := runewidth.Truncate(sanitizeOneLine(a.Title), innerW-35, "…")
			body = append(body, "  "+when+" "+src+" "+titleStyle.Render(titleTrim))
		}
	}

	maxBodyLines := m.height*80/100 - 4
	if len(body) > maxBodyLines {
		body = body[:maxBodyLines-1]
		body = append(body, dimStyle.Render("   ... (more not shown - terminal too short)"))
	}

	frame := modalStyle
	if kev {
		frame = modalKEVStyle
	}
	modal := frame.Width(modalW).Render(strings.Join(body, "\n"))

	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		modal,
		lipgloss.WithWhitespaceBackground(lipgloss.Color("#050709")),
	)
}

func (m model) renderSearchBar() string {
	prompt := accentText("/")
	caret := "_"
	bar := " " + prompt + " " + m.searchInput + caret
	bar = runewidth.FillRight(bar, m.width)
	return lipgloss.NewStyle().Background(lipgloss.Color("#14191f")).Render(bar)
}

func (m *model) moveSelection(delta int) {
	if len(m.articles) == 0 {
		return
	}
	m.selected += delta
	if m.selected < 0 {
		m.selected = 0
	}
	if m.selected >= len(m.articles) {
		m.selected = len(m.articles) - 1
	}
	m.ensureSelectedVisible()
}

func (m *model) ensureSelectedVisible() {
	rows := m.visibleRows()
	if m.selected < m.listOffset {
		m.listOffset = m.selected
	}
	if m.selected >= m.listOffset+rows {
		m.listOffset = m.selected - rows + 1
	}
	if m.listOffset < 0 {
		m.listOffset = 0
	}
}

func (m model) visibleRows() int {
	// header + status + pane top + pane bottom (+ search bar)
	reserved := 4
	if m.mode == searchMode {
		reserved = 5
	}
	r := m.height - reserved
	if r < 1 {
		r = 1
	}
	return r
}

func (m model) paneWidths() (listW, previewW int) {
	// 60/40 split, with 2-char buffer for a vertical separator + breathing room.
	listW = (m.width * 60) / 100
	previewW = m.width - listW - 1
	return
}

func (m model) renderHeader() string {
	worm := lipgloss.NewStyle().Foreground(accent).Render("●●●")
	title := headerBrandStyle.Render(" om nom nom")
	tagline := dimStyle.Render(" :: security feeds ")
	count := dimStyle.Render(fmt.Sprintf(" %d articles ", len(m.articles)))

	left := " " + worm + " " + title + tagline
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(count)
	if pad < 0 {
		pad = 0
	}
	return headerBarStyle.Render(left + strings.Repeat(" ", pad) + count)
}

func (m model) renderStatus() string {
	// Left side: active filter chips. Empty when nothing is filtered
	// so the casual reader sees a clean status bar.
	var filters []string
	if m.minScore > 0 {
		filters = append(filters, fmt.Sprintf("score≥%d", m.minScore))
	}
	if m.sourceType != "" {
		filters = append(filters, "type:"+m.sourceType)
	}
	if m.unreadOnly {
		filters = append(filters, "unread")
	}
	if m.showDupes {
		filters = append(filters, "dupes")
	}
	if m.search != "" {
		filters = append(filters, "search:"+truncateForFlash(m.search))
	}
	left := ""
	if len(filters) > 0 {
		left = dimStyle.Render(" filters: ") + accentText(strings.Join(filters, " · "))
	}

	mid := ""
	if m.flash != "" {
		mid = "  " + lipgloss.NewStyle().Foreground(accentCyan).Render(m.flash)
	}

	right := dimStyle.Render(" j/k nav   o open   /search   ? help   q quit ")

	used := lipgloss.Width(left) + lipgloss.Width(mid) + lipgloss.Width(right)
	pad := m.width - used
	if pad < 0 {
		pad = 0
	}
	return statusBarStyle.Render(left + mid + strings.Repeat(" ", pad) + right)
}

func (m model) renderList(width, height int) string {
	rows := m.visibleRows()
	end := m.listOffset + rows
	if end > len(m.articles) {
		end = len(m.articles)
	}

	var lines []string
	for i := m.listOffset; i < end; i++ {
		a := m.articles[i]
		lines = append(lines, m.renderListRow(a, width, i == m.selected))
	}

	// Pad to fill height so the preview pane has a stable left edge.
	for len(lines) < rows {
		lines = append(lines, strings.Repeat(" ", width))
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderListRow: bar(2) score(5) bm(1) title(W) source(14) age(7) + 5 gaps.
func (m model) renderListRow(a models.Article, width int, selected bool) string {
	const (
		barW    = 2
		scoreW  = 5
		bmW     = 1
		sourceW = 14
		ageW    = 7
		gaps    = 5
	)
	titleW := width - barW - scoreW - bmW - sourceW - ageW - gaps
	if titleW < 8 {
		titleW = 8
	}

	var bar string
	if selected {
		bar = selectedBarStyle.Render("  ")
	} else {
		bar = "  "
	}

	score := scoreStyle(a.Score, hasKEV(a)).Render(fmt.Sprintf(" %3d ", a.Score))

	bmGlyph := " "
	if m.bookmarks[a.ID] {
		bmGlyph = lipgloss.NewStyle().Foreground(accentAmber).Bold(true).Render("★")
	}

	// Strip control chars first; Bluesky / Mastodon titles often have embedded \n.
	cleanTitle := sanitizeOneLine(a.Title)
	titleText := runewidth.FillRight(runewidth.Truncate(cleanTitle, titleW, "…"), titleW)
	var title string
	switch {
	case selected:
		title = selectedTitleStyle.Render(titleText)
	case a.Read:
		title = readTitleStyle.Render(titleText)
	default:
		title = titleStyle.Render(titleText)
	}

	sourceText := runewidth.FillRight(runewidth.Truncate(sanitizeOneLine(a.Source), sourceW, "…"), sourceW)
	source := dimStyle.Render(sourceText)
	ageText := runewidth.FillRight(runewidth.Truncate(humanizeAge(a.PublishedAt), ageW, ""), ageW)
	age := dimStyle.Render(ageText)

	row := bar + " " + score + " " + bmGlyph + " " + title + " " + source + " " + age

	if selected {
		return selectedRowStyle.Render(row)
	}
	return row
}

func (m model) renderPreview(width, height int) string {
	if m.selected < 0 || m.selected >= len(m.articles) {
		return strings.Repeat("\n", height)
	}
	a := m.articles[m.selected]

	cleanTitle := sanitizeOneLine(a.Title)
	titleBlock := previewHeroTitleStyle.Width(width).Render(wordWrap(cleanTitle, width-2))

	var kevBanner string
	if hasKEV(a) {
		kevBanner = kevPulseBannerStyle.Render(runewidth.FillRight("  ●  ACTIVELY EXPLOITED  ", width))
	}

	scoreChip := scoreStyle(a.Score, hasKEV(a)).Render(fmt.Sprintf(" score %d ", a.Score))
	metaLine := srcIcon(a.SourceType) + " " +
		previewMetaStyle.Render(a.Source) + "  " +
		previewMetaStyle.Render("·  "+humanizeAge(a.PublishedAt)+"  ·  ") +
		scoreChip

	var tagsLine string
	if len(a.Tags) > 0 {
		var chips []string
		for _, t := range a.Tags {
			chips = append(chips, tagChip(t).Render(" "+t+" "))
		}
		tagsLine = lipgloss.JoinHorizontal(lipgloss.Top, chips...)
	}

	// Triage line is populated by the daemon's worker when a Claude/OpenAI key is set.
	var triageLine string
	if strings.TrimSpace(a.Triage) != "" {
		label := lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render("◆ triage: ")
		triageLine = label + lipgloss.NewStyle().Foreground(textBright).Render(sanitizeOneLine(a.Triage))
		triageLine = wordWrap(triageLine, width)
	}

	summary := strings.TrimSpace(a.Summary)
	if summary == "" {
		summary = dimStyle.Render("(no summary)")
	}
	summary = wordWrap(summary, width)

	urlLabel := previewMetaStyle.Render("url:")
	urlLine := urlLabel + " " + dimStyle.Render(truncateForFlash(a.URL))

	parts := []string{titleBlock}
	if kevBanner != "" {
		parts = append(parts, kevBanner)
	}
	parts = append(parts, "", metaLine)
	if tagsLine != "" {
		parts = append(parts, "", tagsLine)
	}
	if triageLine != "" {
		parts = append(parts, "", triageLine)
	}
	parts = append(parts, "", summary, "", urlLine)

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func hasKEV(a models.Article) bool {
	for _, t := range a.Tags {
		if strings.HasPrefix(t, "kev") || t == "kev" {
			return true
		}
	}
	return false
}

func humanizeAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("Jan 2")
	}
}

// sanitizeOneLine collapses control chars to spaces.
// Bluesky/Mastodon titles often carry embedded \n which breaks column alignment.
func sanitizeOneLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	for strings.Contains(out, "  ") {
		out = strings.ReplaceAll(out, "  ", " ")
	}
	return strings.TrimSpace(out)
}

// wordWrap breaks on word boundaries; lipgloss.Width hard-clips, which mangles URLs.
func wordWrap(s string, width int) string {
	if width <= 0 {
		return s
	}
	var out strings.Builder
	for _, paragraph := range strings.Split(s, "\n") {
		words := strings.Fields(paragraph)
		var line strings.Builder
		for _, w := range words {
			if line.Len() == 0 {
				line.WriteString(w)
				continue
			}
			if line.Len()+1+len(w) > width {
				out.WriteString(line.String())
				out.WriteByte('\n')
				line.Reset()
				line.WriteString(w)
				continue
			}
			line.WriteByte(' ')
			line.WriteString(w)
		}
		if line.Len() > 0 {
			out.WriteString(line.String())
		}
		out.WriteByte('\n')
	}
	return strings.TrimRight(out.String(), "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (m model) renderStatsModal() string {
	if m.stats == nil {
		return m.renderModal("FEAST STATS", []string{dimStyle.Render("(no stats available)")}, false)
	}
	s := m.stats

	kevCount := 0
	for _, a := range m.articles {
		if hasKEV(a) {
			kevCount++
		}
	}

	heroLine := dimStyle.Render("  total chewed     ") + statHeroNumber(s.TotalArticles, accent) + "  " +
		dimStyle.Render("  still waiting    ") + statHeroNumber(s.UnreadCount, accentCyan) + "  " +
		dimStyle.Render("  kev-listed       ") + statHeroNumber(kevCount, accentRed)

	lines := []string{heroLine, ""}

	lines = append(lines, modalSectionStyle.Render("::  Top feeding tubes  ::"))
	sources := topKMap(s.SourceBreakdown, 10)
	maxSrcCount := 0
	for _, p := range sources {
		if p.v > maxSrcCount {
			maxSrcCount = p.v
		}
	}
	for _, p := range sources {
		bar := renderHBar(p.v, maxSrcCount, 30, accent)
		lines = append(lines, fmt.Sprintf("  %s %s %s",
			runewidth.FillRight(p.k, 24),
			bar,
			lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("%d", p.v))))
	}
	lines = append(lines, "")

	lines = append(lines, modalSectionStyle.Render("::  Most-chewed tags  ::"))
	tags := topKMap(s.TopTags, 12)
	maxTagCount := 0
	for _, p := range tags {
		if p.v > maxTagCount {
			maxTagCount = p.v
		}
	}
	for _, p := range tags {
		bar := renderHBar(p.v, maxTagCount, 30, accentCyan)
		lines = append(lines, fmt.Sprintf("  %s %s %s",
			runewidth.FillRight(p.k, 24),
			bar,
			lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("%d", p.v))))
	}

	return m.renderModal("FEAST STATS", lines, false)
}

func (m model) renderSourcePickerModal() string {
	var lines []string
	lines = append(lines, dimStyle.Render(fmt.Sprintf("  %d sources :: j/k nav, Enter selects, 0 clears, q cancels", len(m.sourceList))))
	lines = append(lines, "")

	visibleRows := m.height * 60 / 100
	if visibleRows < 8 {
		visibleRows = 8
	}
	if m.sourceCursor < m.sourceOffset {
		m.sourceOffset = m.sourceCursor
	}
	if m.sourceCursor >= m.sourceOffset+visibleRows {
		m.sourceOffset = m.sourceCursor - visibleRows + 1
	}

	end := m.sourceOffset + visibleRows
	if end > len(m.sourceList) {
		end = len(m.sourceList)
	}
	for i := m.sourceOffset; i < end; i++ {
		src := m.sourceList[i]
		if i == m.sourceCursor {
			lines = append(lines, selectedRowStyle.Render(" "+selectedBarStyle.Render(" ")+" "+selectedTitleStyle.Render(src)))
		} else {
			lines = append(lines, "   "+src)
		}
	}
	return m.renderModal("SOURCE PICKER", lines, false)
}

// renderIOCModal renders the IOC decoder: input bar at top, detected
// type + pivot URLs below.
func (m model) renderIOCModal() string {
	var lines []string
	prompt := accentText("> ")
	caret := "_"
	input := prompt + m.iocInput + caret
	lines = append(lines, input)
	lines = append(lines, dimStyle.Render("  paste a hash / CVE / IP / URL / domain - detect happens as you type"))
	lines = append(lines, "")

	if m.iocKind == "" {
		lines = append(lines, dimStyle.Render("  (waiting for input...)"))
	} else if m.iocKind == "unknown" {
		lines = append(lines, lipgloss.NewStyle().Foreground(accentRed).Render("  [!] couldn't classify input"))
	} else {
		lines = append(lines, dimStyle.Render("  detected: ")+lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(m.iocKind))
		lines = append(lines, dimStyle.Render("  value:    ")+titleStyle.Render(m.iocValue))
		lines = append(lines, "")
		lines = append(lines, modalSectionStyle.Render("::  Pivot links  ::"))
		for _, p := range m.iocPivots {
			label := lipgloss.NewStyle().Foreground(accent).Bold(true).Render(p.label)
			lines = append(lines, "  "+runewidth.FillRight(label, 24)+dimStyle.Render(p.url))
		}
	}
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("  ENTER re-detect   ctrl-u clear   ESC dismiss"))
	return m.renderModal("IOC TASTE TEST", lines, false)
}

func (m model) renderMITREModal() string {
	var lines []string
	lines = append(lines, dimStyle.Render(fmt.Sprintf("  %d techniques across the last 30 days :: j/k nav, Enter filters feed, q dismisses", len(m.mitreEntries))))
	lines = append(lines, "")

	if len(m.mitreEntries) == 0 {
		lines = append(lines, dimStyle.Render("  no MITRE techniques tagged in the last 30 days"))
		return m.renderModal("MITRE ATT&CK COVERAGE", lines, false)
	}

	maxCount := m.mitreEntries[0].count
	visibleRows := m.height*60/100 - 4
	if visibleRows < 8 {
		visibleRows = 8
	}
	if m.mitreCursor < m.mitreOffset {
		m.mitreOffset = m.mitreCursor
	}
	if m.mitreCursor >= m.mitreOffset+visibleRows {
		m.mitreOffset = m.mitreCursor - visibleRows + 1
	}
	end := m.mitreOffset + visibleRows
	if end > len(m.mitreEntries) {
		end = len(m.mitreEntries)
	}
	for i := m.mitreOffset; i < end; i++ {
		e := m.mitreEntries[i]
		bar := renderHBar(e.count, maxCount, 24, accentAmber)
		row := fmt.Sprintf("  %s %s %s",
			lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(runewidth.FillRight(e.techID, 10)),
			bar,
			lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("%d", e.count)))
		if i == m.mitreCursor {
			lines = append(lines, selectedRowStyle.Render(row))
		} else {
			lines = append(lines, row)
		}
	}
	return m.renderModal("MITRE ATT&CK COVERAGE", lines, false)
}

func (m model) renderVizModal() string {
	var lines []string
	lines = append(lines, dimStyle.Render(fmt.Sprintf("  %d sources :: distribution across the current corpus", len(m.vizEntries))))
	lines = append(lines, "")

	if len(m.vizEntries) == 0 {
		lines = append(lines, dimStyle.Render("  no sources to chart"))
		return m.renderModal("FEEDING TUBES // FLOW", lines, false)
	}
	maxCount := m.vizEntries[0].count
	for i, e := range m.vizEntries {
		if i >= 25 {
			lines = append(lines, dimStyle.Render(fmt.Sprintf("  ... and %d more", len(m.vizEntries)-25)))
			break
		}
		bar := renderHBar(e.count, maxCount, 36, accent)
		lines = append(lines, fmt.Sprintf("  %s %s %s",
			runewidth.FillRight(runewidth.Truncate(e.source, 28, "…"), 28),
			bar,
			lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("%d", e.count))))
	}
	return m.renderModal("FEEDING TUBES // FLOW", lines, false)
}

func (m model) renderModal(title string, lines []string, kev bool) string {
	modalW := m.width * 80 / 100
	if modalW > 120 {
		modalW = 120
	}
	if modalW < 60 {
		modalW = 60
	}
	innerW := modalW - 6

	titleText := lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(":: " + title + " ::")
	dismiss := dimStyle.Render("q / esc dismisses")
	pad := innerW - lipgloss.Width(titleText) - lipgloss.Width(dismiss)
	if pad < 1 {
		pad = 1
	}
	header := titleText + strings.Repeat(" ", pad) + dismiss
	full := append([]string{header, ""}, lines...)

	frame := modalStyle
	if kev {
		frame = modalKEVStyle
	}
	modal := frame.Width(modalW).Render(strings.Join(full, "\n"))

	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		modal,
		lipgloss.WithWhitespaceBackground(lipgloss.Color("#050709")),
	)
}

func statHeroNumber(n int, c lipgloss.TerminalColor) string {
	return lipgloss.NewStyle().Foreground(c).Bold(true).Render(fmt.Sprintf("%-6d", n))
}

// renderHBar draws a bar from value/max width cells; empty space filled with dim dots.
func renderHBar(value, max, width int, c lipgloss.TerminalColor) string {
	if max <= 0 {
		return strings.Repeat(" ", width)
	}
	filled := (value * width) / max
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled)
	empty := strings.Repeat("·", width-filled)
	return lipgloss.NewStyle().Foreground(c).Render(bar) + dimStyle.Render(empty)
}

func (m model) renderAIBriefModal() string {
	title := m.aiBriefLabel
	if title == "" {
		title = "WORM'S DIGEST :: last 24h"
	}
	var lines []string
	if m.ai == nil {
		lines = []string{
			lipgloss.NewStyle().Foreground(accentAmber).Bold(true).Render("  [BYOK required]"),
			"",
			"  No summarizer configured. Set one of these env vars and restart:",
			"",
			"    " + accentText("ANTHROPIC_API_KEY") + dimStyle.Render(" - Claude Haiku (recommended)"),
			"    " + accentText("OPENAI_API_KEY") + dimStyle.Render("    - gpt-4o-mini"),
			"",
			dimStyle.Render("  Both providers cost ~$0.001-0.005 per brief call. We don't bill you;"),
			dimStyle.Render("  the API costs are yours, paid direct to the provider."),
		}
		return m.renderModal(title, lines, false)
	}
	if m.aiBriefErr != "" {
		lines = []string{
			lipgloss.NewStyle().Foreground(accentRed).Bold(true).Render("  [error]"),
			"",
			"  " + m.aiBriefErr,
		}
		return m.renderModal(title, lines, false)
	}
	if m.aiBriefLoading {
		provider := dimStyle.Render(m.ai.Name())
		lines = []string{
			lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render("  synthesising intel brief..."),
			"",
			dimStyle.Render("  provider: ") + provider,
			"",
			dimStyle.Render("  Pulling the top-scoring articles from the last 24h, summarising into"),
			dimStyle.Render("  KEV / RCE / supply-chain / threat-actor sections. Takes 10-30s."),
		}
		return m.renderModal(title, lines, false)
	}
	// Render the LLM body. Word-wrap to the modal inner width.
	modalW := m.width * 80 / 100
	if modalW > 120 {
		modalW = 120
	}
	innerW := modalW - 6
	body := sanitizeOneLine(m.aiBriefBody)
	// Preserve double-newlines (section breaks); sanitizeOneLine collapses
	// them to spaces, so go back to the raw body for the section split.
	for _, paragraph := range strings.Split(m.aiBriefBody, "\n\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" {
			lines = append(lines, "")
			continue
		}
		wrapped := wordWrap(strings.ReplaceAll(paragraph, "\n", " "), innerW-2)
		for _, l := range strings.Split(wrapped, "\n") {
			lines = append(lines, "  "+l)
		}
		lines = append(lines, "")
	}
	_ = body // sanitizeOneLine reserved for future use
	lines = append(lines, dimStyle.Render("  generated by "+m.ai.Name()))
	return m.renderModal("WORM'S DIGEST :: last 24h", lines, false)
}

func (m *model) openLeaderboards() {
	if rows, err := m.store.HottestCVEs(168, 20); err == nil {
		m.trendingCVEs = rows
	}
	if cands, err := m.store.PreKEVCandidates(168, 3); err == nil {
		var rows []preKEVRow
		for id, n := range cands {
			rows = append(rows, preKEVRow{cveID: id, sources: n})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].sources != rows[j].sources {
				return rows[i].sources > rows[j].sources
			}
			return rows[i].cveID < rows[j].cveID
		})
		if len(rows) > 20 {
			rows = rows[:20]
		}
		m.preKEVCandidates = rows
	}
	m.mode = leaderboardMode
}

// updateLeaderboards dismisses on any key.
func (m model) updateLeaderboards(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.trendingCVEs = nil
	m.preKEVCandidates = nil
	return m, nil
}

func (m model) renderLeaderboardModal() string {
	var lines []string
	lines = append(lines, modalSectionStyle.Render("::  TRENDING CVEs (last 7d, by mention count)  ::"))
	if len(m.trendingCVEs) == 0 {
		lines = append(lines, dimStyle.Render("   (no trending CVEs)"))
	} else {
		max := m.trendingCVEs[0].Mentions
		for i, c := range m.trendingCVEs {
			if i >= 15 {
				lines = append(lines, dimStyle.Render(fmt.Sprintf("   ... and %d more", len(m.trendingCVEs)-15)))
				break
			}
			bar := renderHBar(c.Mentions, max, 18, accent)
			kevTag := ""
			if c.KEV {
				kevTag = " " + lipgloss.NewStyle().Background(accentRed).Foreground(textBright).Bold(true).Render(" KEV ")
			}
			lines = append(lines, fmt.Sprintf("  %s  %s  %s%s",
				runewidth.FillRight(lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(c.CVE), 16),
				bar,
				lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("×%d", c.Mentions)),
				kevTag))
		}
	}
	lines = append(lines, "")
	lines = append(lines, modalSectionStyle.Render("::  PRE-KEV (heating up, not yet in CISA KEV)  ::"))
	if len(m.preKEVCandidates) == 0 {
		lines = append(lines, dimStyle.Render("   (no pre-KEV candidates - either every hot CVE is already in KEV, or no chatter)"))
	} else {
		maxSrc := m.preKEVCandidates[0].sources
		for i, p := range m.preKEVCandidates {
			if i >= 15 {
				lines = append(lines, dimStyle.Render(fmt.Sprintf("   ... and %d more", len(m.preKEVCandidates)-15)))
				break
			}
			bar := renderHBar(p.sources, maxSrc, 18, accentAmber)
			lines = append(lines, fmt.Sprintf("  %s  %s  %s",
				runewidth.FillRight(lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render(p.cveID), 16),
				bar,
				lipgloss.NewStyle().Foreground(textBright).Bold(true).Render(fmt.Sprintf("%d sources", p.sources))))
		}
	}
	return m.renderModal("LEADERBOARDS // /trending + /pre-kev", lines, false)
}

func (m *model) openPatchBrief() {
	briefs, err := m.store.RecentPatchBriefs(90)
	if err != nil {
		m.flash = "patch brief query failed: " + err.Error()
		return
	}
	m.patchBriefs = briefs
	m.mode = patchBriefMode
}

func (m model) updatePatchBrief(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.patchBriefs = nil
	return m, nil
}

func (m model) renderPatchBriefModal() string {
	var lines []string
	if len(m.patchBriefs) == 0 {
		lines = append(lines, dimStyle.Render("  No Patch Tuesday briefs generated yet."))
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("  Briefs auto-generate on the 2nd Tuesday of each month if"))
		lines = append(lines, dimStyle.Render("  ANTHROPIC_API_KEY or OPENAI_API_KEY is set. Configure"))
		lines = append(lines, dimStyle.Render("  vendor list in the config panel."))
		return m.renderModal("PATCH TUESDAY", lines, false)
	}
	b := m.patchBriefs[0]
	lines = append(lines, lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render("  "+b.Vendor+" - "+b.BriefDate))
	lines = append(lines, dimStyle.Render(fmt.Sprintf("  window: %s → %s   articles: %d   generated: %s",
		b.WindowStart.Format("2006-01-02"), b.WindowEnd.Format("2006-01-02"),
		b.ArticleCount, b.GeneratedAt.Format("2006-01-02 15:04"))))
	lines = append(lines, "")
	for _, para := range strings.Split(b.BriefText, "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			lines = append(lines, "")
			continue
		}
		wrapped := wordWrap(strings.ReplaceAll(para, "\n", " "), 100)
		for _, l := range strings.Split(wrapped, "\n") {
			lines = append(lines, "  "+l)
		}
		lines = append(lines, "")
	}
	if len(m.patchBriefs) > 1 {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  + %d older briefs in the corpus (v0.2 will add a picker)", len(m.patchBriefs)-1)))
	}
	return m.renderModal("PATCH TUESDAY", lines, false)
}

func (m *model) openScoreExplain() {
	if m.scorer == nil {
		m.flash = "no scorer wired"
		return
	}
	if m.selected < 0 || m.selected >= len(m.articles) {
		return
	}
	a := m.articles[m.selected]
	text := strings.ToLower(a.Title + " " + a.Summary)
	cats := m.scorer.Categories()
	result := &scoreExplainResult{article: a}
	for _, c := range cats {
		var hits []string
		for _, kw := range c.Keywords {
			if strings.Contains(text, strings.ToLower(kw)) {
				hits = append(hits, kw)
			}
		}
		if len(hits) > 0 {
			result.matches = append(result.matches, scoreExplainCategory{
				name:   c.Name,
				weight: c.Weight,
				hits:   hits,
			})
			result.total += c.Weight
		}
	}
	m.scoreExplain = result
	m.mode = scoreExplainMode
}

func (m model) updateScoreExplain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = normalMode
	m.scoreExplain = nil
	return m, nil
}

func (m model) renderScoreExplainModal() string {
	var lines []string
	if m.scoreExplain == nil {
		lines = []string{dimStyle.Render("  (no score data)")}
		return m.renderModal("SCORE EXPLAINER", lines, false)
	}
	r := m.scoreExplain
	lines = append(lines, lipgloss.NewStyle().Foreground(accentCyan).Bold(true).Render("  "+sanitizeOneLine(r.article.Title)))
	lines = append(lines, "")
	scoreChip := scoreStyle(r.article.Score, hasKEV(r.article)).Render(fmt.Sprintf(" %d ", r.article.Score))
	lines = append(lines, "  "+dimStyle.Render("article score: ")+scoreChip+"  "+
		dimStyle.Render(fmt.Sprintf("(sum of category weights = %d, then capped at 100)", r.total)))
	lines = append(lines, "")
	if len(r.matches) == 0 {
		lines = append(lines, dimStyle.Render("  No scoring categories matched. This article is in the corpus probably"))
		lines = append(lines, dimStyle.Render("  because of source type or upstream score; review with the source curator."))
		return m.renderModal("SCORE EXPLAINER", lines, false)
	}
	lines = append(lines, modalSectionStyle.Render("::  Categories that fired  ::"))
	for _, c := range r.matches {
		weight := lipgloss.NewStyle().Foreground(accentAmber).Bold(true).Render(fmt.Sprintf("+%d", c.weight))
		name := titleStyle.Render(c.name)
		lines = append(lines, "  "+weight+"  "+name)
		// Hits, joined as a comma-separated list, wrapped if long.
		hitsLine := dimStyle.Render("        hits: ") + strings.Join(c.hits, dimStyle.Render(", "))
		lines = append(lines, hitsLine)
	}
	return m.renderModal("SCORE EXPLAINER", lines, false)
}

// exportATTACKLayer writes a Navigator v4.5 layer JSON to ~/secfeed-attack-<YYYYMMDD>.json.
func (m *model) exportATTACKLayer() (string, error) {
	freq, err := m.store.TTPFrequency(30)
	if err != nil {
		return "", err
	}
	if len(freq) == 0 {
		return "", fmt.Errorf("no MITRE technique mentions in last 30 days")
	}

	maxCount := 0
	for _, n := range freq {
		if n > maxCount {
			maxCount = n
		}
	}
	if maxCount == 0 {
		maxCount = 1
	}

	type navTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Comment     string `json:"comment,omitempty"`
		Enabled     bool   `json:"enabled"`
	}
	type navGradient struct {
		Colors   []string `json:"colors"`
		MinValue int      `json:"minValue"`
		MaxValue int      `json:"maxValue"`
	}
	type navLayer struct {
		Name                          string         `json:"name"`
		Description                   string         `json:"description"`
		Versions                      map[string]any `json:"versions"`
		Domain                        string         `json:"domain"`
		Techniques                    []navTechnique `json:"techniques"`
		Gradient                      navGradient    `json:"gradient"`
		ShowTacticRowBackground       bool           `json:"showTacticRowBackground"`
		TacticRowBackground           string         `json:"tacticRowBackground"`
		SelectTechniquesAcrossTactics bool           `json:"selectTechniquesAcrossTactics"`
		HideDisabled                  bool           `json:"hideDisabled"`
	}

	techniques := make([]navTechnique, 0, len(freq))
	for tid, count := range freq {
		techniques = append(techniques, navTechnique{
			TechniqueID: tid,
			Score:       count,
			Comment:     fmt.Sprintf("%d mention(s) across articles", count),
			Enabled:     true,
		})
	}
	sort.Slice(techniques, func(i, j int) bool {
		if techniques[i].Score != techniques[j].Score {
			return techniques[i].Score > techniques[j].Score
		}
		return techniques[i].TechniqueID < techniques[j].TechniqueID
	})

	layer := navLayer{
		Name:        "oM noM - last 30 days (TUI export)",
		Description: "TTP frequency across the local corpus, exported from secfeed tui",
		Versions: map[string]any{
			"attack":    "14",
			"navigator": "4.9.4",
			"layer":     "4.5",
		},
		Domain:                        "enterprise-attack",
		Techniques:                    techniques,
		Gradient:                      navGradient{Colors: []string{"#0a0e14", "#00e5a0", "#ffb547", "#ff4d6a"}, MinValue: 1, MaxValue: maxCount},
		ShowTacticRowBackground:       false,
		TacticRowBackground:           "#dddddd",
		SelectTechniquesAcrossTactics: true,
		HideDisabled:                  false,
	}

	body, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return "", err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	path := filepath.Join(home, fmt.Sprintf("secfeed-attack-%s.json", time.Now().Format("20060102")))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// topKMap returns the K largest entries from a string→int map, sorted
// by value desc, ties broken by key asc.
type kv struct {
	k string
	v int
}

func topKMap(m map[string]int, k int) []kv {
	var all []kv
	for kk, vv := range m {
		all = append(all, kv{k: kk, v: vv})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > k {
		all = all[:k]
	}
	return all
}
