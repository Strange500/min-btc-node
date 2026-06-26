mod codec;
mod messages;
mod protocol;
mod tui;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use protocol::{MessageCommand, Network};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SyncState {
    best_block_hash: [u8; 32],
    best_block_height: u32,
}

impl SyncState {
    fn load() -> Option<Self> {
        let data = std::fs::read_to_string("sync_state.json").ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&self) {
        if let Ok(data) = serde_json::to_string(self) {
            let _ = std::fs::write("sync_state.json", data);
        }
    }
}

struct SyncNodeGuard {
    has_sync_node: Arc<AtomicBool>,
    pub is_sync_node: bool,
    pub peer_idx: usize,
}

impl Drop for SyncNodeGuard {
    fn drop(&mut self) {
        if self.is_sync_node {
            self.has_sync_node.store(false, Ordering::SeqCst);
        }
        tui::update_peer(self.peer_idx, "".to_string(), "Déconnecté ❌".to_string());
    }
}

struct TuiWriter;
impl std::io::Write for TuiWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf).to_string();
        tui::add_log(s.trim_end().to_string());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TuiWriter {
    type Writer = TuiWriter;
    fn make_writer(&'a self) -> Self::Writer { TuiWriter }
}

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "Mini-nœud SPV Bitcoin interactif", long_about = None)]
struct Args {
    /// Le réseau Bitcoin à rejoindre (mainnet, signet, regtest)
    #[arg(short, long, default_value = "mainnet")]
    network: Network,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(TuiWriter)
        .without_time()
        .init();

    let network = args.network;
    let pool_size = 3;
    
    if let Some(state) = SyncState::load() {
        let mut chain = protocol::CHAIN_STATE.lock().unwrap();
        chain.best_block_hash = state.best_block_hash;
        chain.best_block_height = state.best_block_height;
        info!("💾 Checkpoint chargé : Reprise au bloc {}", state.best_block_height);
    }

    info!("Démarrage du mini-nœud Bitcoin sur le réseau {:?} avec un pool de {} pairs...", network, pool_size);

    let peer_pool = discover_peers(network);
    if peer_pool.is_empty() {
        error!("Impossible de trouver des nœuds via DNS !");
        return Ok(());
    }
    info!("📍 {} adresses IP récupérées via DNS.", peer_pool.len());

    let peer_pool = Arc::new(peer_pool);
    let peer_index = Arc::new(AtomicUsize::new(0));

    let has_sync_node = Arc::new(AtomicBool::new(false));

    for peer_idx in 0..pool_size {
        let has_sync_node = has_sync_node.clone();
        let peer_pool = peer_pool.clone();
        let peer_index = peer_index.clone();
        
        tokio::spawn(async move {
            loop {
                let idx = peer_index.fetch_add(1, Ordering::SeqCst) % peer_pool.len();
                let target_peer = peer_pool[idx];

                tui::update_peer(peer_idx, target_peer.to_string(), "Connexion... ⏳".to_string());
                info!("Tentative de connexion à {}...", target_peer);
                
                let connect_result = timeout(Duration::from_secs(5), TcpStream::connect(&target_peer)).await;
                
                match connect_result {
                    Ok(Ok(mut stream)) => {
                        info!("✅ Connecté avec succès au peer {}!", target_peer);
                        tui::update_peer(peer_idx, target_peer.to_string(), "Connecté 🤝".to_string());
                        
                        if let Err(e) = handle_connection(&mut stream, network, peer_idx, target_peer, has_sync_node.clone()).await {
                            error!("❌ Erreur avec {} : {}", target_peer, e);
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("❌ Impossible de se connecter à {} : {}", target_peer, e);
                    }
                    Err(_) => {
                        warn!("⏱️ Timeout : Le nœud {} met trop de temps.", target_peer);
                    }
                }
                
                tui::update_peer(peer_idx, target_peer.to_string(), "Déconnecté ❌".to_string());
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    // Le TUI tourne sur le thread principal et bloque
    tui::run_tui().await?;

    Ok(())
}

fn discover_peers(network: Network) -> Vec<SocketAddr> {
    info!("🔍 Recherche de nœuds via DNS Seeds pour {:?}...", network);
    let mut peers = Vec::new();
    for seed in network.dns_seeds() {
        let address = format!("{}:{}", seed, network.default_port());
        if let Ok(addrs) = address.to_socket_addrs() {
            peers.extend(addrs);
        }
    }
    peers
}

async fn handle_connection(stream: &mut TcpStream, network: Network, peer_idx: usize, target_peer: SocketAddr, has_sync_node: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let version_message = MessageCommand::version(network).encode(network);

    stream.write_all(&version_message).await?;

    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    let mut guard = SyncNodeGuard { has_sync_node, is_sync_node: false, peer_idx };
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            info!("🔌 Le nœud {} a fermé la connexion proprement.", target_peer);
            break;
        }
        
        pending.extend_from_slice(&buffer[..n]);

        loop {
            let Some((message, consumed)) = MessageCommand::from_packet(&pending, network) else {
                break;
            };
            pending.drain(0..consumed);

            if let MessageCommand::Version(ref v) = message {
                let new_len = v.start_height as u32;
                let mut chain = protocol::CHAIN_STATE.lock().unwrap();
                if new_len > chain.target_height {
                    chain.target_height = new_len;
                }
            }

            if let MessageCommand::Header(mut msg) = message {
                let headers = std::mem::take(&mut msg.headers);
                if headers.is_empty() {
                    continue;
                }
                
                let headers_len = headers.len();
                let added = tokio::task::spawn_blocking(move || protocol::save_new_headers(&headers))
                    .await??;

                let (height, best_hash) = {
                    let chain = protocol::CHAIN_STATE.lock().unwrap();
                    (chain.best_block_height, chain.best_block_hash)
                };

                if added > 0 {
                    SyncState {
                        best_block_hash: best_hash,
                        best_block_height: height,
                    }.save();
                }

                if guard.is_sync_node && added > 0 && headers_len == 2000 {
                    sleep(Duration::from_millis(50)).await;
                    let getheaders = MessageCommand::getheaders(network);
                    stream.write_all(&getheaders.encode(network)).await?;
                }
            } else {
                if let Some(response_message) = MessageCommand::respond_to(&message) {
                    let response_packet = response_message.encode(network);
                    stream.write_all(&response_packet).await?;
                }

                if matches!(message, MessageCommand::Verack) {
                    if !guard.has_sync_node.swap(true, Ordering::SeqCst) {
                        guard.is_sync_node = true;
                        tui::update_peer(peer_idx, target_peer.to_string(), "Sync Node 👑".to_string());
                        info!("👑 {} devient le Sync Node. Envoi de 'getheaders'...", target_peer);
                        
                        let getheaders = MessageCommand::getheaders(network);
                        stream.write_all(&getheaders.encode(network)).await?;
                    } else {
                        tui::update_peer(peer_idx, target_peer.to_string(), "Standby 🎧".to_string());
                        info!("🎧 {} est en Standby (Listener).", target_peer);
                    }
                }
            }
        }
    }

    Ok(())
}