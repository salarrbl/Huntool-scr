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

	"github.com/salarrbl/raven-rdp/internal/rdp"
	"github.com/salarrbl/raven-rdp/internal/engine"
)

// historySize bounds the in-memory event feed (spec: 100 events).
const (
	historySize     = 100
	solvedSize      = 50 // Number of successful auths to keep in solved panel
	currentEvents   = 100 // Events shown in current feed (popped up)
	fadeDelay       = 5 * time.Second
	unsolvedSize    = 75 // Number of recent unsolved events
	currentEventsVel= 2   // Events popped every X seconds (reduce velocity)
)

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

	// Event history
	current   [currentEvents]engine.Event
	currentLen int
	solved    [solvedSize]engine.Event
	solvedLen  int
	unsolved   [unsolvedSize]engine.Event
	unsolvedLen int

	// Fade out unsolved events
	fadeTimer time.Time

	// Navigation
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

// push appends an event to the bounded ring buffers.
func (m *Model) push(ev engine.Event) {
	switch ev.Status {
	case rdp.StatusAuthSuccess:
		// Add to solved panel at the front
		if m.solvedLen < solvedSize {
			m.solved[m.solvedLen] = ev
			m.solvedLen++
		} else {
			// Shift left
			for i := 0; i < solvedSize-1; i++ {
				m.solved[i] = m.solved[i+1]
			}
			m.solved[solvedSize-1] = ev
		}
	case rdp.StatusAuthFailure, rdp.StatusTimeout, rdp.StatusClosed:
		// Add unsolved panel at front
		if m.unsolvedLen < unsolvedSize {
			m.unsolved[m.unsolvedLen] = ev
			m.unsolvedLen++
		} else {
			// Shift left
			for i := 0; i < unsolvedSize-1; i++ {
				m.unsolved[i] = m.unsolved[i+1]
			}
			m.unsolved[unsolvedSize-1] = ev
		}
	default:
		// Admin / probe events go to current
		if m.currentLen < currentEvents {
			m.current[m.currentLen] = ev
			m.currentLen++
		} else {
			// Shift left
			for i := 0; i < currentEvents-1; i++ {
				m.current[i] = m.current[i+1]
			}
			m.current[currentEvents-1] = ev
		}
	}

	if m.autoScroll {
		m.scroll = 0
	}
	if m.scroll > currentEvents {
		m.scroll = currentEvents
	}
}

// Forced reports whether the user force-quit (second Ctrl+C).
func (m *Model) Forced() bool { return m.forced }

// StoppedBySignal reports whether the stop came from a signal
// (Ctrl+C / SIGTERM) rather than an in-TUI quit key.
func (m *Model) StoppedBySignal() bool { return m.viaSignal }

// Stop issues the graceful stop sequence (first Ctrl+C / q): cancel scheduling, drain in-flight work, then show the summary.
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
func (m *Model) EventCount() int { return m.solvedLen + m.unsolvedLen + m.currentLen }

// isTerminal reports whether f refers to a terminal device.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// visible returns the current events oldest first.
func (m *Model) visible() []engine.Event {
	if m.currentLen == 0 {
		return nil
	}
	n := m.currentLen
	if n > currentEvents {
		n = currentEvents
	}
	out := make([]engine.Event, 0, n)
	start := m.currentLen - n
	for i := 0; i < n; i++ {
		ev := m.current[(start+i)%currentEvents]
		out = append(out, ev)
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