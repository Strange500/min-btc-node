use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use std::{io, time::Duration};
use crate::protocol::CHAIN_STATE;

pub struct AppState {
    pub peers: Vec<(String, String)>,
    pub logs: Vec<String>,
}

pub static APP_STATE: std::sync::LazyLock<std::sync::Mutex<AppState>> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(AppState {
        peers: Vec::new(),
        logs: Vec::new(),
    })
});

pub fn add_log(msg: String) {
    let mut state = APP_STATE.lock().unwrap();
    state.logs.push(msg);
    if state.logs.len() > 100 {
        state.logs.remove(0);
    }
}

pub fn update_peer(idx: usize, address: String, status: String) {
    let mut state = APP_STATE.lock().unwrap();
    if idx >= state.peers.len() {
        state.peers.resize(idx + 1, ("".to_string(), "Déconnecté ❌".to_string()));
    }
    state.peers[idx] = (address, status);
}

pub async fn run_tui() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),      // Chain status text
                    Constraint::Length(3),      // Gauge
                    Constraint::Length(7),      // Peers
                    Constraint::Min(0),         // Logs
                ].as_ref())
                .split(f.area());

            let (best_height, best_hash, target_height) = {
                let chain = CHAIN_STATE.lock().unwrap();
                (chain.best_block_height, chain.best_block_hash, chain.target_height)
            };

            let mut hash_hex = String::with_capacity(64);
            for byte in best_hash.iter().rev() {
                hash_hex.push_str(&format!("{:02x}", byte));
            }

            let chain_text = format!("Hauteur: {} | Cible: {} | Dernier Hash: {}", best_height, target_height, hash_hex);
            let chain_block = Paragraph::new(chain_text)
                .block(Block::default().title(" 🔗 BITCOIN MINI-NODE ").borders(Borders::ALL).style(Style::default().fg(Color::Yellow)));
            f.render_widget(chain_block, chunks[0]);

            let ratio = if target_height > 0 {
                (best_height as f64 / target_height as f64).min(1.0)
            } else {
                0.0
            };
            let gauge = Gauge::default()
                .block(Block::default().title(" Synchronisation ").borders(Borders::ALL))
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(ratio)
                .label(format!("{:.2}%", ratio * 100.0));
            f.render_widget(gauge, chunks[1]);

            let state = APP_STATE.lock().unwrap();
            let mut peer_items = Vec::new();
            for (addr, status) in &state.peers {
                if !addr.is_empty() {
                    peer_items.push(ListItem::new(format!("{:20} | {}", addr, status)));
                }
            }
            let peers_list = List::new(peer_items)
                .block(Block::default().title(" Pairs Connectés ").borders(Borders::ALL).style(Style::default().fg(Color::Cyan)));
            f.render_widget(peers_list, chunks[2]);

            let mut log_items = Vec::new();
            for log in state.logs.iter().rev() {
                log_items.push(ListItem::new(log.clone()));
            }
            let logs_list = List::new(log_items)
                .block(Block::default().title(" Logs Réseau ").borders(Borders::ALL).style(Style::default().fg(Color::DarkGray)));
            f.render_widget(logs_list, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
