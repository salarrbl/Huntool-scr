#[allow(clippy::new_without_default, deprecated, clippy::collapsible_match)]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use nyx_core::{Contact, Identity, QueueEntry, Session};

pub struct App {
    pub contacts: Vec<Contact>,
    pub selected_contact_idx: usize,
    pub messages: Vec<(String, String)>,
    pub input: String,
    pub identity: Option<Identity>,
    pub session: Option<Session>,
}

impl App {
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            selected_contact_idx: 0,
            messages: Vec::new(),
            input: String::new(),
            identity: None,
            session: None,
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        match key {
            KeyEvent { code: KeyCode::Char('q'), modifiers: KeyModifiers::CONTROL, .. } => {}
            KeyEvent { code: KeyCode::Char('c'), modifiers: KeyModifiers::CONTROL, .. } => {}
            KeyEvent { code: KeyCode::Enter, .. } if !self.input.is_empty() => {
                let msg = self.input.clone();
                self.messages.push(("You".into(), msg));
                self.input.clear();
            }
            KeyEvent { code: KeyCode::Char(c), .. } => self.input.push(c),
            KeyEvent { code: KeyCode::Backspace, .. } => { self.input.pop(); }
            KeyEvent { code: KeyCode::Up, .. } if self.selected_contact_idx > 0 => { self.selected_contact_idx -= 1; }
            KeyEvent { code: KeyCode::Down, .. } if self.selected_contact_idx + 1 < self.contacts.len() => { self.selected_contact_idx += 1; }
            _ => {}
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        let status = if self.session.is_some() { "Session: online | Identity: alice" } else { "No active session" };
        let status_para = Paragraph::new(status)
            .block(Block::default().borders(Borders::BOTTOM))
            .style(Style::default().fg(Color::Green));
        frame.render_widget(status_para, rects[0]);

        let contacts: Vec<ListItem> = self.contacts.iter().enumerate().map(|(i, c)| {
            let style = if i == self.selected_contact_idx { Style::default().fg(Color::Yellow) } else { Style::default() };
            ListItem::new(Line::from(Span::styled(format!("• {} ({})", c.display_name, c.onion_address), style)))
        }).collect();
        let contacts_list = List::new(contacts).block(Block::default().title("Contacts").borders(Borders::RIGHT));
        frame.render_widget(contacts_list, rects[1]);

        let input_para = Paragraph::new(self.input.as_str())
            .block(Block::default().borders(Borders::TOP).title(">"))
            .wrap(Wrap { trim: true });
        frame.render_widget(input_para, rects[2]);
    }
}
