package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

// Color palette — dark, professional, cyberpunk-inspired with
// purple/magenta accents.
var (
	colAccent  = lipgloss.AdaptiveColor{Light: "#7b2cbf", Dark: "#c77dff"}
	colAccent2 = lipgloss.AdaptiveColor{Light: "#a21caf", Dark: "#e05fff"}
	colText    = lipgloss.AdaptiveColor{Light: "#1f2430", Dark: "#e6e9ef"}
	colDim     = lipgloss.AdaptiveColor{Light: "#5b6472", Dark: "#8b93a3"}
	colGreen   = lipgloss.AdaptiveColor{Light: "#166534", Dark: "#3ddc84"}
	colRed     = lipgloss.AdaptiveColor{Light: "#991b1b", Dark: "#ff5c5c"}
	colYellow  = lipgloss.AdaptiveColor{Light: "#854d0e", Dark: "#ffd166"}
	colCyan    = lipgloss.AdaptiveColor{Light: "#0e7490", Dark: "#4dd0e1"}
	colBlue    = lipgloss.AdaptiveColor{Light: "#1e3a8a", Dark: "#7aa2ff"}
	colGray    = lipgloss.AdaptiveColor{Light: "#4b5563", Dark: "#6b7280"}
	colBorder  = lipgloss.AdaptiveColor{Light: "#7b2cbf", Dark: "#9d4edd"}
)

// styles holds every lipgloss style the TUI uses.
type styles struct {
	title   lipgloss.Style
	state   func(string) string
	section lipgloss.Style
	key     lipgloss.Style
	value   lipgloss.Style
	dim     lipgloss.Style
	header  lipgloss.Style
	footer  lipgloss.Style
	target  lipgloss.Style
	status  func(string) string
	message lipgloss.Style
	border  lipgloss.Style
	success lipgloss.Style
	summary lipgloss.Style
}

// newStyles builds the style set. When color is false (NO_COLOR or a
// non-TTY terminal) only weight/borders remain — no hues.
func newStyles(color bool) styles {
	base := func() lipgloss.Style { return lipgloss.NewStyle() }

	if !color {
		st := styles{
			title:   base().Bold(true),
			section: base().Bold(true),
			key:     base(),
			value:   base().Bold(true),
			dim:     base(),
			header:  base().Bold(true),
			footer:  base(),
			target:  base(),
			message: base(),
			border:  lipgloss.NewStyle().Border(lipgloss.RoundedBorder()),
			success: base().Bold(true),
		}
		st.state = func(s string) string { return st.section.Render(s) }
		st.status = func(s string) string { return s }
		return st
	}

	st := styles{
		title:   base().Foreground(colAccent).Bold(true),
		section: base().Foreground(colAccent2).Bold(true),
		key:     base().Foreground(colDim),
		value:   base().Foreground(colText).Bold(true),
		dim:     base().Foreground(colDim),
		header:  base().Foreground(colAccent).Bold(true),
		footer:  base().Foreground(colDim),
		target:  base().Foreground(colBlue),
		message: base().Foreground(colDim),
		border:  lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder),
		success: base().Foreground(colGreen).Bold(true),
		summary: base().Foreground(colText),
	}
	st.state = func(s string) string {
		switch s {
		case "RUNNING":
			return lipgloss.NewStyle().Foreground(colGreen).Bold(true).Render(s)
		case "PAUSED":
			return lipgloss.NewStyle().Foreground(colYellow).Bold(true).Render(s)
		case "STOPPING":
			return lipgloss.NewStyle().Foreground(colYellow).Render(s)
		case "DONE":
			return lipgloss.NewStyle().Foreground(colCyan).Bold(true).Render(s)
		default:
			return st.dim.Render(s)
		}
	}
	st.status = func(s string) string {
		switch s {
		case "OPEN":
			return lipgloss.NewStyle().Foreground(colGreen).Render(s)
		case "AUTH_SUCCESS":
			return lipgloss.NewStyle().Foreground(colGreen).Bold(true).Render(s)
		case "AUTH_FAILURE", "ERROR":
			return lipgloss.NewStyle().Foreground(colRed).Render(s)
		case "TIMEOUT", "RATE_LIMITED", "ATTEMPT_LIMIT":
			return lipgloss.NewStyle().Foreground(colYellow).Render(s)
		case "INFO":
			return lipgloss.NewStyle().Foreground(colCyan).Render(s)
		case "CANCELLED":
			return lipgloss.NewStyle().Foreground(colGray).Render(s)
		default:
			return st.dim.Render(s)
		}
	}
	return st
}

// colorEnabled reports whether color output should be used: disabled
// by NO_COLOR (any value) or when stdout is not a terminal.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(os.Stdout)
}
