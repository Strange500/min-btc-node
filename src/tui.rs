//! Terminal User Interface (TUI) components.
//!
//! This module uses `ratatui` and `crossterm` to draw an interactive dashboard
//! displaying node connection status, synchronization progress, recent transactions,
//! and network logs. It maintains a global thread-safe state buffer to decouple
//! rendering logic from asynchronous networking tasks.

use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        event::{self, Event, KeyCode},
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

/// Holds the internal text buffers for the dashboard.
///
/// Limits the size of vectors to prevent unbounded memory growth during long runs.
pub struct AppState {
    /// List of peer addresses and their connection status.
    pub peers: Vec<(String, String)>,
    /// Ring buffer for generic system logs.
    pub logs: Vec<String>,
    /// Ring buffer for incoming live transaction logs.
    pub txs: Vec<String>,
}

/// Thread-safe global singleton storing the application's TUI state.
pub static APP_STATE: std::sync::LazyLock<std::sync::Mutex<AppState>> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(AppState {
        peers: Vec::new(),
        logs: Vec::new(),
        txs: Vec::new(),
    })
});

/// Appends a new transaction string to the TUI display.
///
/// Limits the historical list to 100 transactions to save memory.
///
/// # Arguments
///
/// * `msg` - The transaction summary formatted as a String.
pub fn add_tx(msg: String) {
    let mut state = APP_STATE.lock().unwrap();
    state.txs.push(msg);
    if state.txs.len() > 100 {
        state.txs.remove(0);
    }
}

/// Appends a general network log message to the TUI display.
///
/// Limits the historical list to 100 messages to save memory.
///
/// # Arguments
///
/// * `msg` - The log message to display.
pub fn add_log(msg: String) {
    let mut state = APP_STATE.lock().unwrap();
    state.logs.push(msg);
    if state.logs.len() > 100 {
        state.logs.remove(0);
    }
}

/// Updates the status of a specific peer in the dashboard.
///
/// Ensures the internal peer list expands automatically to accommodate new indexes.
///
/// # Arguments
///
/// * `idx` - The zero-based index of the connection slot.
/// * `address` - The peer's `SocketAddr` formatted as a string.
/// * `status` - A human-readable string indicating the current connection state.
pub fn update_peer(idx: usize, address: String, status: String) {
    let mut state = APP_STATE.lock().unwrap();
    if idx >= state.peers.len() {
        state.peers.resize(idx + 1, ("".to_string(), "Déconnecté ❌".to_string()));
    }
    state.peers[idx] = (address, status);
}

/// Enters the alternate screen buffer and blocks the current thread to draw the TUI loop.
///
/// Polls for keyboard input (`q` to quit) and renders the UI every 100ms.
///
/// # Errors
///
/// Returns an `io::Error` if terminal mode switching fails or rendering encounters an error.
///
/// # Exit Status
///
/// Restores the user's normal terminal on exit.
pub async fn run_tui() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
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
                    Constraint::Percentage(50), // Txs
                    Constraint::Percentage(50), // Logs
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

            let mut tx_items = Vec::new();
            for tx in state.txs.iter().rev() {
                tx_items.push(ListItem::new(tx.clone()));
                tx_items.push(ListItem::new("─".repeat(40))); // Separator
            }
            let txs_list = List::new(tx_items)
                .block(Block::default().title(" Transactions Live ").borders(Borders::ALL).style(Style::default().fg(Color::Magenta)));
            f.render_widget(txs_list, chunks[3]);

            let mut log_items = Vec::new();
            for log in state.logs.iter().rev() {
                log_items.push(ListItem::new(log.clone()));
            }
            let logs_list = List::new(log_items)
                .block(Block::default().title(" Logs Réseau ").borders(Borders::ALL).style(Style::default().fg(Color::DarkGray)));
            f.render_widget(logs_list, chunks[4]);
        })?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
                && key.code == KeyCode::Char('q') {
                    break;
                }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
