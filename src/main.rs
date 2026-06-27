mod codec;
mod messages;
mod protocol;
mod tui;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use protocol::{MessageCommand, Network};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

macro_rules! info {
    ($($arg:tt)*) => { crate::tui::add_log(format!("INFO: {}", format_args!($($arg)*))) };
}
macro_rules! warn {
    ($($arg:tt)*) => { crate::tui::add_log(format!("WARN: {}", format_args!($($arg)*))) };
}
macro_rules! error {
    ($($arg:tt)*) => { crate::tui::add_log(format!("ERROR: {}", format_args!($($arg)*))) };
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

    let network = args.network;
    let pool_size = 3;
    
    match protocol::load_headers() {
        Ok(count) if count > 0 => {
            let chain = protocol::CHAIN_STATE.lock().unwrap();
            info!("💾 {} en-têtes chargés depuis le disque. Reprise au bloc {}", count, chain.best_block_height);
        }
        Ok(_) => info!("💾 Aucun en-tête trouvé, on part de zéro !"),
        Err(e) => error!("❌ Erreur lors du chargement des en-têtes : {}", e),
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

        while let Some((message, consumed)) = MessageCommand::from_packet(&pending, network) {
            pending.drain(0..consumed);

            info!("📥 {}", message);

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



                if guard.is_sync_node && added > 0 && headers_len == 2000 {
                    sleep(Duration::from_millis(50)).await;
                    let getheaders = MessageCommand::getheaders(network);
                    stream.write_all(&getheaders.encode(network)).await?;
                }
            } else {
                if let Some(response_message) = MessageCommand::respond_to(&message) {
                    info!("📤 {}", response_message);
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