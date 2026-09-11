package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestQuitKeyIsNotASignal pins N3: an in-TUI quit cancels the run
// context exactly like Ctrl+C does, so the model has to remember
// which one it was — otherwise the process exit code cannot tell a
// graceful `q` apart from an interrupt.
func TestQuitKeyIsNotASignal(t *testing.T) {
	cancelled := false
	m := New(nil, func() { cancelled = true })

	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); cmd != nil {
		t.Fatal("first q must start the graceful stop, not quit the program")
	}
	if !cancelled {
		t.Fatal("q must cancel the run context")
	}
	if m.StoppedBySignal() {
		t.Fatal("StoppedBySignal = true after an in-TUI quit, want false")
	}
	if m.state != StateStopping {
		t.Fatalf("state = %v, want StateStopping", m.state)
	}
}

// TestSignalStopIsReportedAsSignal covers the other half of N3, and
// that the stop source survives into the done state.
func TestSignalStopIsReportedAsSignal(t *testing.T) {
	cancelled := false
	m := New(nil, func() { cancelled = true })

	m.Update(SIGINTMsg{})
	if !cancelled {
		t.Fatal("SIGINT must cancel the run context")
	}
	if !m.StoppedBySignal() {
		t.Fatal("StoppedBySignal = false after SIGINT, want true")
	}
	if m.Forced() {
		t.Fatal("first SIGINT must not be a forced quit")
	}

	// The run finishes; quitting from the done screen keeps the
	// signal as the reason for the stop.
	m.Update(EngineDoneMsg{})
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); cmd == nil {
		t.Fatal("q in the done state must quit the program")
	}
	if !m.StoppedBySignal() {
		t.Fatal("StoppedBySignal = false after a signal-driven run, want true")
	}

	// A second SIGINT forces the exit.
	m.Update(SIGINTMsg{})
	if !m.Forced() {
		t.Fatal("second SIGINT must force the quit")
	}
}
