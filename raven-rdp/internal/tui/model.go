// Package tui implements the interactive Bubble Tea front end: live
// statistics, a bounded event feed, and pause/resume/scroll controls.
package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/salarrbl/raven-rdp/internal/engine"
)

// historySize bounds the in-memory event feed (spec: 100 events).
const historySize = 100

// tickInterval drives elapsed-time and rate refresh.
const tickInterval = 250 * time.Millisecond

// State is the TUI lifecycle state.
type State int

// TUI states.
const (
	StateRunning State = iota
	StatePaused
	StateStopping
	StateDone
)

// Messages.
type (
	// EventMsg delivers one engine event to the TUI.
	EventMsg struct{ Ev engine.Event }
	// EngineDoneMsg marks the end of the run.
	EngineDoneMsg struct{ Err error }
	// SIGINTMsg signals a Ctrl+C delivery from the signal handler.
	SIGINTMsg struct{}
	tickMsg   time.Time
)

// Model is the Bubble Tea model for the audit TUI.
type Model struct {
	eng    *engine.Engine
	cancel context.CancelFunc
	st     styles
	color  bool
	out    io.Writer

	width   int
	height  int
	state   State
	start   time.Time
	runErr  error
	stopped bool

	hist       [historySize]engine.Event
	histCount  int
	scroll     int
	autoScroll bool
	forced     bool

	// N3: viaSignal records whether the stop was initiated by a
	// signal (Ctrl+C / SIGTERM) rather than by the in-TUI quit key.
	// Both paths cancel the run context, so this is the only way to
	// tell them apart when choosing an exit code.
	viaSignal bool
}

// New builds the TUI model. cancel stops the engine (graceful stop).
func New(eng *engine.Engine, cancel context.CancelFunc) *Model {
	color := colorEnabled()
	return &Model{
		eng:        eng,
		cancel:     cancel,
		st:         newStyles(color),
		color:      color,
		out:        os.Stdout,
		width:      80,
		height:     24,
		start:      time.Now(),
		autoScroll: true,
	}
}

// Init starts the refresh tick.
func (m *Model) Init() tea.Cmd { return tickCmd() }

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update handles messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case EventMsg:
		m.push(msg.Ev)
		return m, nil

	case EngineDoneMsg:
		m.state = StateDone
		m.runErr = msg.Err
		return m, nil

	case SIGINTMsg:
		// N3: mark the stop as signal-driven before delegating, so
		// the exit code can distinguish Ctrl+C from an in-TUI quit.
		m.viaSignal = true
		return m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})

	case tickMsg:
		return m, tickCmd()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// push appends an event to the bounded ring buffer.
func (m *Model) push(ev engine.Event) {
	m.hist[m.histCount%historySize] = ev
	m.histCount++
	if m.autoScroll {
		m.scroll = 0
	}
	if m.scroll > historySize {
		m.scroll = historySize
	}
}

// Forced reports whether the user force-quit (second Ctrl+C).
func (m *Model) Forced() bool { return m.forced }

// StoppedBySignal reports whether the stop came from a signal
// (Ctrl+C / SIGTERM) rather than an in-TUI quit key.
func (m *Model) StoppedBySignal() bool { return m.viaSignal }

// Stop issues the graceful stop sequence (first Ctrl+C / q):
// cancel scheduling, drain in-flight work, then show the summary.
func (m *Model) Stop() {
	if m.stopped {
		return
	}
	m.stopped = true
	m.state = StateStopping
	if m.cancel != nil {
		m.cancel()
	}
}

// EventCount reports how many events were produced (untruncated).
func (m *Model) EventCount() int { return m.histCount }

// isTerminal reports whether f refers to a terminal device.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// visible returns the events currently in the feed, oldest first.
func (m *Model) visible() []engine.Event {
	if m.histCount == 0 {
		return nil
	}
	n := m.histCount
	if n > historySize {
		n = historySize
	}
	out := make([]engine.Event, 0, n)
	start := m.histCount - n
	for i := 0; i < n; i++ {
		out = append(out, m.hist[(start+i)%historySize])
	}
	return out
}

// formatDuration renders an MM:SS or H:MM:SS duration.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	mn := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, mn, s)
	}
	return fmt.Sprintf("%02d:%02d", mn, s)
}
