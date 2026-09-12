package tui

import tea "github.com/charmbracelet/bubbletea"

// handleKey implements the control scheme:
//
//	q / ctrl+c  graceful stop (second press forces exit)
//	p           pause authentication scheduling
//	r           resume
//	↑ / k       scroll the event feed back
//	↓ / j       scroll forward (bottom re-arms auto-scroll)
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case msg.Type == tea.KeyCtrlC:
		if m.state == StateStopping || m.state == StateDone {
			m.forced = true
			return m, tea.Quit
		}
		m.Stop()
		return m, nil

	case msg.Type == tea.KeyBreak:
		return m, tea.Quit

	// M1: arrow keys arrive as KeyUp/KeyDown with empty Runes, so
	// they must be matched on msg.Type, not on rune contents.
	case msg.Type == tea.KeyUp:
		if m.currentLen > 0 {
			m.autoScroll = false
			if m.scroll < m.currentLen {
				m.scroll++
			}
		}
		return m, nil

	case msg.Type == tea.KeyDown:
		if m.scroll > 0 {
			m.scroll--
			if m.scroll == 0 {
				m.autoScroll = true
			}
		}
		return m, nil

	case len(msg.Runes) > 0:
		switch string(msg.Runes) {
		case "q":
			if m.state == StateStopping || m.state == StateDone {
				return m, tea.Quit
			}
			// N3: quitting from inside the TUI is a graceful stop,
			// not an interrupt, even though it cancels the run.
			m.viaSignal = false
			m.Stop()
			return m, nil
		case "p":
			if m.state == StateRunning {
				m.eng.Pause()
				m.state = StatePaused
			}
			return m, nil
		case "r":
			if m.state == StatePaused {
				m.eng.Resume()
				m.state = StateRunning
			}
			return m, nil
		case "k":
				if m.currentLen > 0 {
					m.autoScroll = false
					if m.scroll < m.currentLen {
						m.scroll++
					}
				}
				return m, nil
		case "j":
			if m.scroll > 0 {
				m.scroll--
				if m.scroll == 0 {
					m.autoScroll = true
				}
			}
			return m, nil
		case "g":
			m.scroll = 0
			m.autoScroll = true
			return m, nil
		}
	}
	return m, nil
}
