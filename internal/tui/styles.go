package tui

import "github.com/charmbracelet/lipgloss"

// Palette mirrors the web reader's CSS custom properties.
var (
	accent       = lipgloss.Color("#00e5a0")
	accentCyan   = lipgloss.Color("#56e2ff")
	accentAmber  = lipgloss.Color("#ffb547")
	accentRed    = lipgloss.Color("#ff5470")
	textBright   = lipgloss.Color("#ffffff")
	textDim      = lipgloss.Color("#b8c4d4")
	border       = lipgloss.Color("#2a3340")
	borderBright = lipgloss.Color("#3f4d62")
)

var (
	headerBrandStyle = lipgloss.NewStyle().
				Foreground(accent).
				Bold(true)
	headerBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0e1218")).
			Foreground(textBright)

	titleStyle         = lipgloss.NewStyle().Foreground(textBright).Bold(true)
	readTitleStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6a7686"))
	selectedTitleStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)
	dimStyle           = lipgloss.NewStyle().Foreground(textDim)
	errorStyle         = lipgloss.NewStyle().Foreground(accentRed).Bold(true).Padding(1, 2)

	rowStyle         = lipgloss.NewStyle()
	selectedRowStyle = lipgloss.NewStyle().Background(lipgloss.Color("#1a2530"))
	selectedBarStyle = lipgloss.NewStyle().Background(accent)

	paneBorderStyle = lipgloss.NewStyle().Foreground(border)
	paneTitleStyle  = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)
	paneTitleAltStyle = lipgloss.NewStyle().
				Foreground(accentCyan).
				Bold(true)

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

	// Fallback container used while pane-frame rolls out.
	previewPaneStyle = lipgloss.NewStyle().
				Padding(1, 2).
				BorderStyle(lipgloss.NormalBorder()).
				BorderLeft(true).
				BorderForeground(border)

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0e1218"))

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

	modalBackdropStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#050709"))

	modalSectionStyle = lipgloss.NewStyle().
				Foreground(accentCyan).
				Bold(true)

	kevPulseBannerStyle = lipgloss.NewStyle().
				Background(accentRed).
				Foreground(textBright).
				Bold(true).
				Padding(0, 1)

	srcRSSStyle      = lipgloss.NewStyle().Foreground(accentCyan)
	srcBlueskyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#6db7ff"))
	srcMastodonStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#b48eff"))
	srcGitHubStyle   = lipgloss.NewStyle().Foreground(accent)
	srcRedditStyle   = lipgloss.NewStyle().Foreground(accentAmber)
	srcIOCStyle      = lipgloss.NewStyle().Foreground(accentRed)
)

// srcIcon returns a coloured single-cell glyph for a source_type.
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
	default:
		return srcRSSStyle.Render("◆")
	}
}

// scoreStyle picks a colour tier for the score badge. KEV-listed pulses red.
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

// tagChip colours a tag by category: kev red, cve cyan, exploit amber, default dim.
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
