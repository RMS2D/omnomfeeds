package tui

import "github.com/charmbracelet/lipgloss"

// Worm theme - colour values mirror the web reader's CSS custom properties:
//   --bg          #0a0e14
//   --bg-card     #14191f
//   --border      #2a3340
//   --text        #e6ecf5
//   --text-dim    #b8c4d4
//   --accent      #00e5a0   (mint green - the worm)
//   --accent-cyan #56e2ff
//   --accent-amber #ffb547
//   --accent-red  #ff5470   (kev pulse)
//
// lipgloss truecolor strings ("#xxxxxx") downgrade gracefully on 256-color
// and 16-color terminals via termenv, so we don't need to maintain palette
// fallbacks ourselves.
var (
	accent      = lipgloss.Color("#00e5a0")
	accentCyan  = lipgloss.Color("#56e2ff")
	accentAmber = lipgloss.Color("#ffb547")
	accentRed   = lipgloss.Color("#ff5470")
	textBright  = lipgloss.Color("#ffffff")
	textDim     = lipgloss.Color("#b8c4d4")
	border      = lipgloss.Color("#2a3340")
	borderBright = lipgloss.Color("#3f4d62")
)

// ----- Surface styles -------------------------------------------------
//
// Heavy worm/cyberpunk theme: dark base (#0a0e14), mint-green accent
// (#00e5a0), cyan section headers (#56e2ff), amber pulse (#ffb547),
// blood-red for KEV (#ff5470). Panels are box-drawn with title labels
// in the top border so the whole thing reads as a real multi-panel TUI
// rather than free-floating columns of text.

var (
	// Brand label on the header strip. Mint-green, bold.
	headerBrandStyle = lipgloss.NewStyle().
				Foreground(accent).
				Bold(true)
	// Header strip background. Tinted so the bar reads as its own
	// UI element rather than the same plane as the body.
	headerBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0e1218")).
			Foreground(textBright)

	// Article-row text styles.
	titleStyle         = lipgloss.NewStyle().Foreground(textBright).Bold(true)
	readTitleStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6a7686"))
	selectedTitleStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)
	dimStyle           = lipgloss.NewStyle().Foreground(textDim)
	errorStyle         = lipgloss.NewStyle().Foreground(accentRed).Bold(true).Padding(1, 2)

	// Row container. Selected rows: clearly-different background +
	// a 2-cell solid-green bar at the leftmost columns.
	rowStyle         = lipgloss.NewStyle()
	selectedRowStyle = lipgloss.NewStyle().Background(lipgloss.Color("#1a2530"))
	selectedBarStyle = lipgloss.NewStyle().Background(accent)

	// Pane chrome. Each pane gets a box-drawn border with a title
	// label embedded in the top edge - the lazygit / gh-dash pattern.
	paneBorderStyle = lipgloss.NewStyle().Foreground(border)
	paneTitleStyle  = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)
	paneTitleAltStyle = lipgloss.NewStyle().
				Foreground(accentCyan).
				Bold(true)

	// Preview pane content styles.
	previewHeroTitleStyle = lipgloss.NewStyle().
				Foreground(textBright).
				Bold(true).
				Background(lipgloss.Color("#14191f")).
				Padding(0, 1)
	previewMetaStyle = lipgloss.NewStyle().
				Foreground(textDim)
	previewTitleStyle = lipgloss.NewStyle().
				Foreground(textBright).
				Bold(true).
				MarginBottom(1)

	// previewPaneStyle is the old left-bordered container - still
	// used as a fallback path while the new pane-frame helper rolls
	// out. v0.2 will retire this.
	previewPaneStyle = lipgloss.NewStyle().
				Padding(1, 2).
				BorderStyle(lipgloss.NormalBorder()).
				BorderLeft(true).
				BorderForeground(border)

	// Status bar at the bottom of the screen.
	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0e1218"))

	// Modal box - rounded border, accent colour, dark interior.
	// KEV variant swaps the border colour to red.
	modalStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Padding(1, 2).
			Background(lipgloss.Color("#0a0e14"))

	modalKEVStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(accentRed).
			Padding(1, 2).
			Background(lipgloss.Color("#0a0e14"))

	// Modal backdrop: full-screen dark fill rendered behind the modal
	// so the underlying view is hidden and the modal really pops.
	modalBackdropStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#050709"))

	// Section header inside a modal - flat cyan tracking matching
	// the web reader's "::  SECTION  ::" convention.
	modalSectionStyle = lipgloss.NewStyle().
				Foreground(accentCyan).
				Bold(true)

	// KEV pulse banner that runs across the top of a CVE popover
	// when the source article is CISA KEV-listed. Red on red.
	kevPulseBannerStyle = lipgloss.NewStyle().
				Background(accentRed).
				Foreground(textBright).
				Bold(true).
				Padding(0, 1)

	// Source-type accent colours. Each source_type maps to a colour
	// so the eye picks up "this is a bluesky post / mastodon toot /
	// github commit" at a glance without parsing the source-name.
	srcRSSStyle      = lipgloss.NewStyle().Foreground(accentCyan)
	srcBlueskyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#6db7ff"))
	srcMastodonStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#b48eff"))
	srcGitHubStyle   = lipgloss.NewStyle().Foreground(accent)
	srcRedditStyle   = lipgloss.NewStyle().Foreground(accentAmber)
	srcIOCStyle      = lipgloss.NewStyle().Foreground(accentRed)
)

// srcIcon returns a coloured glyph for a source_type so the row's
// origin reads at a glance. ◆ is single-cell wide on every standard
// terminal font - safer than emoji which can render 1 or 2 cells
// depending on Windows Terminal version.
func srcIcon(sourceType string) string {
	switch sourceType {
	case "bluesky":
		return srcBlueskyStyle.Render("◆")
	case "mastodon":
		return srcMastodonStyle.Render("◆")
	case "github":
		return srcGitHubStyle.Render("◆")
	case "reddit":
		return srcRedditStyle.Render("◆")
	case "ioc_feed":
		return srcIOCStyle.Render("◆")
	default: // rss + anything unknown
		return srcRSSStyle.Render("◆")
	}
}

// scoreStyle picks a colour tier for the score badge. KEV-listed
// articles pulse red regardless of score (in the web reader the
// KEV chip is a separate amber/red badge; in the terminal we fold it
// into the score colour for compactness).
func scoreStyle(score int, kev bool) lipgloss.Style {
	switch {
	case kev:
		return lipgloss.NewStyle().Foreground(textBright).Background(accentRed).Bold(true)
	case score >= 60:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#0a0e14")).Background(accent).Bold(true)
	case score >= 30:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#0a0e14")).Background(accentAmber).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(textDim).Background(lipgloss.Color("#14191f"))
	}
}

// tagChip renders a single tag as a colored chip. Tag colour is keyed
// off the tag name so the same tag is the same colour across rows.
// Tags starting with "kev" pulse red; "cve-" style tags get cyan;
// everything else falls into the dim default. This matches the web
// reader's tag colouring convention.
func tagChip(tag string) lipgloss.Style {
	switch {
	case len(tag) >= 3 && tag[:3] == "kev":
		return lipgloss.NewStyle().Foreground(textBright).Background(accentRed).Bold(true).MarginRight(1)
	case len(tag) >= 4 && tag[:4] == "cve-":
		return lipgloss.NewStyle().Foreground(textBright).Background(accentCyan).MarginRight(1)
	case tag == "0day" || tag == "zero-day" || tag == "exploit" || tag == "rce":
		return lipgloss.NewStyle().Foreground(textBright).Background(accentAmber).MarginRight(1)
	default:
		return lipgloss.NewStyle().Foreground(textDim).Background(lipgloss.Color("#14191f")).MarginRight(1)
	}
}
