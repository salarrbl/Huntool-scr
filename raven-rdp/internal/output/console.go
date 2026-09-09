// Package output renders audit results: a colored console renderer,
// and structured JSON/CSV report writers.
//
// Security invariant: no type or method in this package accepts a
// password or any equivalent secret. Result rows carry only target,
// status, username, timing and a credential-safe error summary.
package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Redacted is shown instead of a secret value.
const Redacted = "[REDACTED]"

// Summary is the final per-run statistic block, filled by the app
// from engine metrics.
type Summary struct {
	Targets        int64
	Open           int64
	Closed         int64
	Timeout        int64
	ProbeError     int64
	SkippedAuth    int64
	Attempts       int64
	Success        int64
	Failed         int64
	AuthTimeout    int64
	AuthError      int64
	Cancelled      int64
	LimitReached   int64
	RateNotices    int64
	Users          int
	Passwords      int
	TargetsInvalid int64
	TargetsDups    int64
	Duration       time.Duration
}

// Console is a thread-safe, line-oriented colored renderer.
type Console struct {
	out   io.Writer
	color bool
	quiet bool
	mu    sync.Mutex

	st styles
}

// NewConsole builds a console renderer. color should be false when
// NO_COLOR is set or stdout is not a TTY.
func NewConsole(out io.Writer, color, quiet bool) *Console {
	c := &Console{out: out, color: color, quiet: quiet}
	c.st = buildStyles(color)
	return c
}

// Quiet reports whether minimal output mode is active.
func (c *Console) Quiet() bool { return c.quiet }

// Header renders a header string (used for the banner).
func (c *Console) Header(s string) string { return c.st.header(s) }

// Value renders a value string.
func (c *Console) Value(s string) string { return c.st.value(s) }

// Event renders one audit event as a single line:
//
//	12:31:04  192.168.1.10:3389  OPEN  (NLA enforced)
func (c *Console) Event(t time.Time, target string, status, username, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.quiet && !isInteresting(status) {
		return
	}
	line := fmt.Sprintf("%s  %s", t.Format("15:04:05"), c.st.target(target))
	if username != "" {
		line += "  user=" + username
	}
	line += "  " + c.st.status(status)
	if message != "" && !c.quiet {
		line += "  " + c.st.message(message)
	}
	fmt.Fprintln(c.out, line)
}

// Success renders the highlighted credential-verified lines. The
// password is always redacted.
func (c *Console) Success(t time.Time, target, username string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.out,
		c.st.successTag("[SUCCESS]")+" "+c.st.target(target)+
			"\n  Username: "+username+
			"\n  Password: "+Redacted)
}

// isInteresting reports whether a status is worth printing in quiet
// mode (outcomes the operator cares about most).
func isInteresting(status string) bool {
	switch status {
	case "AUTH_SUCCESS", "AUTH_FAILURE", "ERROR":
		return true
	}
	return false
}

// join renders its arguments with a single space separator.
func join(s ...string) string { return strings.Join(s, " ") }

// styles bundles the lipgloss styles used by the console renderer.
type styles struct {
	target     func(...string) string
	status     func(string) string
	message    func(...string) string
	successTag func(...string) string
	header     func(...string) string
	key        func(...string) string
	value      func(...string) string
	box        lipgloss.Style
}

func buildStyles(color bool) styles {
	if !color {
		return styles{
			target:     join,
			status:     func(s string) string { return s },
			message:    join,
			successTag: join,
			header:     join,
			key:        join,
			value:      join,
		}
	}

	return styles{
		target:     lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render,
		status:     statusStyle,
		message:    lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render,
		successTag: lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render,
		header:     lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true).Render,
		key:        lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Render,
		value:      lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Render,
		box:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("90")),
	}
}

// statusStyle colors a status token by its semantic meaning.
func statusStyle(s string) string {
	switch s {
	case "OPEN":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(s)
	case "AUTH_SUCCESS":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render(s)
	case "AUTH_FAILURE", "ERROR":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(s)
	case "TIMEOUT", "RATE_LIMITED", "ATTEMPT_LIMIT":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(s)
	case "INFO":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render(s)
	case "CANCELLED":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(s)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(s)
	}
}
