package output

import (
	"fmt"
	"strings"
	"time"
)

// RenderSummary renders the final statistics box as a plain string.
// Both the console renderer and the TUI use it.
func RenderSummary(s Summary, color bool) string {
	st := buildStyles(color)

	rows := [][2]string{
		{"Targets tested", fmt.Sprintf("%d", s.Targets)},
		{"RDP reachable", fmt.Sprintf("%d", s.Open)},
		{"Closed", fmt.Sprintf("%d", s.Closed)},
		{"Timeout", fmt.Sprintf("%d", s.Timeout)},
		{"Probe errors", fmt.Sprintf("%d", s.ProbeError)},
		{"Skipped (no NLA)", fmt.Sprintf("%d", s.SkippedAuth)},
		{"Attempts", fmt.Sprintf("%d", s.Attempts)},
		{"Successful auth", fmt.Sprintf("%d", s.Success)},
		{"Failed auth", fmt.Sprintf("%d", s.Failed)},
		{"Auth errors", fmt.Sprintf("%d", s.AuthError+s.AuthTimeout)},
		{"Cancelled", fmt.Sprintf("%d", s.Cancelled)},
		{"Dropped events", fmt.Sprintf("%d", s.Dropped)},
		{"Duration", s.Duration.Round(time.Second).String()},
	}

	keyW, valW := 0, 0
	for _, r := range rows {
		keyW = max(keyW, len(r[0]))
		valW = max(valW, len(r[1]))
	}
	width := keyW + valW + 8

	line := strings.Repeat("─", width)
	var b strings.Builder
	b.WriteString("┌─" + line + "┐\n")
	title := "RAVENRDP SUMMARY"
	pad := width - len(title) - 2
	if pad < 0 {
		pad = 0
	}
	b.WriteString("│" + st.header(strings.Repeat(" ", pad/2)+title+strings.Repeat(" ", pad-pad/2)) + "│\n")
	b.WriteString("├─" + line + "┤\n")
	for _, r := range rows {
		b.WriteString("│ " + st.key(r[0]) + strings.Repeat(" ", keyW-len(r[0])) +
			"  " + st.value(r[1]) + strings.Repeat(" ", valW-len(r[1])) + "  │\n")
	}
	b.WriteString("└─" + line + "┘")
	return b.String()
}

// Summary prints the final statistics box to the console.
func (c *Console) Summary(s Summary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.out, RenderSummary(s, c.color))
}

// ConfigSummary prints the startup configuration block.
func (c *Console) ConfigSummary(lines []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range lines {
		key, val, _ := strings.Cut(l, ": ")
		if key == "" {
			fmt.Fprintln(c.out, l)
			continue
		}
		fmt.Fprintln(c.out, "  "+c.st.key(key+": ")+" "+c.st.value(val))
	}
}

// SafetyLimits prints the active safety controls.
func (c *Console) SafetyLimits(summary string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.out, "  "+c.st.header("Safety")+"  "+c.st.value(summary))
}
