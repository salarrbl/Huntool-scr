package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/salarrbl/raven-rdp/internal/engine"
	"github.com/salarrbl/raven-rdp/internal/output"
)

// View renders the full frame.
func (m *Model) View() string {
	if m.state == StateDone {
		return m.renderDone()
	}

	w := m.contentWidth()
	var b strings.Builder
	b.WriteString(m.renderHeader(w))
	b.WriteString(m.renderStats(w))
	b.WriteString("\n")
	b.WriteString(m.renderEvents(w))
	b.WriteString(m.renderFooter())
	return b.String()
}

// contentWidth is the usable frame width.
func (m *Model) contentWidth() int {
	w := m.width - 1
	if w > 78 {
		w = 78
	}
	if w < 40 {
		w = 40
	}
	return w
}

func (m *Model) renderHeader(w int) string {
	title := "🐦‍⬛ RAVENRDP"
	state := "RUNNING"
	switch m.state {
	case StatePaused:
		state = "PAUSED"
	case StateStopping:
		state = "STOPPING"
	case StateDone:
		state = "DONE"
	}
	left := m.st.title.Render(title)
	right := m.st.state(state)
	gap := w - 2 - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return "╭" + strings.Repeat("─", w) + "╮\n" +
		"│ " + left + strings.Repeat(" ", gap) + right + " │\n" +
		"╰" + strings.Repeat("─", w) + "╯\n"
}

// renderStats draws the two-column statistics panel.
func (m *Model) renderStats(w int) string {
	met := m.eng.Metrics()

	type cell struct{ k, v string }
	left := []cell{
		{"Targets", fmtS(met.Targets.Load())},
		{"RDP Open", fmtS(met.Open.Load())},
		{"Closed", fmtS(met.Closed.Load())},
		{"Timeout", fmtS(met.Timeout.Load())},
		{"Completed", fmtS(met.Completed.Load())},
		{"Remaining", fmtS(met.Remaining())},
		{"Skipped", fmtS(met.SkippedAuth.Load())},
	}
	right := []cell{
		{"Attempts", fmtS(met.Attempts.Load())},
		{"Successful", fmtS(met.Success.Load())},
		{"Failed", fmtS(met.Failed.Load())},
		{"Errors", fmtS(met.ProbeError.Load() + met.AuthError.Load() + met.AuthTimeout.Load())},
		{"Workers", fmtS(int64(m.eng.Policy().Workers))},
		{"Rate", fmt.Sprintf("%.1f/s", met.AttemptsPerSec())},
		{"Elapsed", formatDuration(met.Elapsed())},
	}

	kw, vw := 0, 0
	for _, c := range left {
		kw = max(kw, len(c.k))
		vw = max(vw, len(c.v))
	}
	for _, c := range right {
		kw = max(kw, len(c.k))
		vw = max(vw, len(c.v))
	}
	colW := kw + 2 + vw
	gap := w - 2*colW - 2
	if gap < 2 {
		gap = 2
	}

	var b strings.Builder
	// L5: iterate over the longer column and pad the shorter one, so
	// right[i] is never indexed beyond its length.
	rows := max(len(left), len(right))
	for i := 0; i < rows; i++ {
		var lc, rc cell
		if i < len(left) {
			lc = left[i]
		}
		if i < len(right) {
			rc = right[i]
		}
		b.WriteString(m.st.key.Render(padRight(lc.k, kw)) + "  " + m.st.value.Render(padRight(lc.v, vw)))
		b.WriteString(strings.Repeat(" ", gap))
		b.WriteString(m.st.key.Render(padRight(rc.k, kw)) + "  " + m.st.value.Render(padRight(rc.v, vw)))
		b.WriteString("\n")
	}
	return b.String()
}

// renderEvents draws the bounded live event feed.
func (m *Model) renderEvents(w int) string {
	inner := w - 4
	if inner < 30 {
		inner = 30
	}

	// Header(3) + stats(7) + blank(1) + footer(1) + margins.
	avail := m.height - 12
	if avail < 3 {
		avail = 3
	}

	events := m.visible()
	n := avail
	if n > len(events) {
		n = len(events)
	}

	var b strings.Builder
	title := "LIVE EVENTS"
	b.WriteString("╭" + m.st.section.Render(title) + " " + strings.Repeat("─", inner-lipgloss.Width(title)-2) + "╮\n")

	start := len(events) - n - m.scroll
	if start < 0 {
		start = 0
	}
	for i := 0; i < n; i++ {
		ev := events[start+i]
		b.WriteString("│ " + m.renderEvent(ev, inner-2) + " │\n")
	}
	b.WriteString("╰" + strings.Repeat("─", inner) + "╯\n")
	return b.String()
}

// renderEvent formats one feed line, truncated to fit.
func (m *Model) renderEvent(ev engine.Event, width int) string {
	s := ev.Time.Format("15:04:05") + "  " + m.st.target.Render(ev.Target) + "  " + m.st.status(ev.Status.String())
	if ev.Username != "" {
		s += "  user=" + ev.Username
	}
	if ev.Message != "" {
		s += "  " + ev.Message
	}
	return truncate(s, width)
}

func (m *Model) renderFooter() string {
	return m.st.footer.Render("  q quit   p pause   r resume   ↑↓ scroll   g bottom") + "\n"
}

// renderDone shows the final summary after the run finishes.
func (m *Model) renderDone() string {
	met := m.eng.Metrics()
	s := output.Summary{
		Targets:     met.Targets.Load(),
		Open:        met.Open.Load(),
		Closed:      met.Closed.Load(),
		Timeout:     met.Timeout.Load(),
		ProbeError:  met.ProbeError.Load(),
		SkippedAuth: met.SkippedAuth.Load(),
		Attempts:    met.Attempts.Load(),
		Success:     met.Success.Load(),
		Failed:      met.Failed.Load(),
		AuthTimeout: met.AuthTimeout.Load(),
		AuthError:   met.AuthError.Load(),
		Cancelled:   met.Cancelled.Load(),
		Duration:    met.Elapsed(),
	}

	var b strings.Builder
	b.WriteString(output.RenderSummary(s, m.color))
	b.WriteString("\n")
	if m.runErr != nil {
		b.WriteString(" " + m.st.status("ERROR") + " " + m.st.message.Render(m.runErr.Error()) + "\n")
	}
	b.WriteString(m.st.footer.Render("  q quit") + "\n")
	return b.String()
}

// helpers

func fmtS(v int64) string { return fmt.Sprintf("%d", v) }

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

// truncate shortens s to at most width cells, appending an ellipsis.
func truncate(s string, width int) string {
	if lipgloss.Width(s) <= width {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 && lipgloss.Width(string(runes)+"…") > width {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 {
		return "…"
	}
	return string(runes) + "…"
}
