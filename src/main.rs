mod codec;
mod messages;
mod protocol;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use protocol::{MessageCommand, Network};
use indicatif::{ProgressBar, ProgressStyle};
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
}

impl Drop for SyncNodeGuard {
    fn drop(&mut self) {
        if self.is_sync_node {
            self.has_sync_node.store(false, Ordering::SeqCst);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let network = Network::Signet;
    let pool_size = 3;
    
    if let Some(state) = SyncState::load() {
        let mut chain = protocol::CHAIN_STATE.lock().unwrap();
        chain.best_block_hash = state.best_block_hash;
        chain.best_block_height = state.best_block_height;
        info!("💾 Checkpoint chargé : Reprise au bloc {}", state.best_block_height);
    }

    info!("Démarrage du mini-nœud Bitcoin sur le réseau {:?} avec un pool de {} pairs...", network, pool_size);

    // 1. Resolve DNS once
    let peer_pool = discover_peers(network);
    if peer_pool.is_empty() {
        error!("Impossible de trouver des nœuds via DNS !");
        return Ok(());
    }
    info!("📍 {} adresses IP récupérées via DNS.", peer_pool.len());

    let peer_pool = Arc::new(peer_pool);
    let peer_index = Arc::new(AtomicUsize::new(0));

    let pb = ProgressBar::new(0);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocs ({percent}%) {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let has_sync_node = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for _ in 0..pool_size {
        let pb = pb.clone();
        let has_sync_node = has_sync_node.clone();
        let peer_pool = peer_pool.clone();
        let peer_index = peer_index.clone();
        
        handles.push(tokio::spawn(async move {
            loop {
                // Round-robin over the shared pool
                let idx = peer_index.fetch_add(1, Ordering::SeqCst) % peer_pool.len();
                let target_peer = peer_pool[idx];

                info!("Tentative de connexion à {}...", target_peer);
                
                let connect_result = timeout(Duration::from_secs(5), TcpStream::connect(&target_peer)).await;
                
                match connect_result {
                    Ok(Ok(mut stream)) => {
                        info!("✅ Connecté avec succès au peer {}!", target_peer);
                        if let Err(e) = handle_connection(&mut stream, network, pb.clone(), has_sync_node.clone()).await {
                            error!("❌ Erreur de connexion avec {} : {}", target_peer, e);
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("❌ Impossible de se connecter à {} : {}", target_peer, e);
                    }
                    Err(_) => {
                        warn!("⏱️ Timeout : Le nœud {} met trop de temps à répondre.", target_peer);
                    }
                }
                
                info!("🔄 Nouvelle tentative de reconnexion dans 5 secondes...");
                sleep(Duration::from_secs(5)).await;
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

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

async fn handle_connection(stream: &mut TcpStream, network: Network, pb: ProgressBar, has_sync_node: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let version_message = MessageCommand::version(network).encode(network);

    debug!("Envoi du message 'version'...");
    stream.write_all(&version_message).await?;
    debug!("🚀 Message envoyé ! En attente des données réseau...");

    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    let mut guard = SyncNodeGuard { has_sync_node, is_sync_node: false };
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            info!("🔌 Le nœud distant a fermé la connexion proprement.");
            break;
        }
        
        pending.extend_from_slice(&buffer[..n]);

        loop {
            let Some((message, consumed)) = MessageCommand::from_packet(&pending, network) else {
                break;
            };
            pending.drain(0..consumed);

            if let MessageCommand::Version(ref v) = message {
                let current_len = pb.length().unwrap_or(0);
                let new_len = v.start_height as u64;
                if new_len > current_len {
                    pb.set_length(new_len);
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

                pb.set_position(height as u64);
                if height as u64 >= pb.length().unwrap_or(0) && pb.length().unwrap_or(0) > 0 {
                    pb.set_message("✅ Synchronisation terminée !");
                }

                if guard.is_sync_node && added > 0 && headers_len == 2000 {
                    sleep(Duration::from_millis(50)).await;
                    let getheaders = MessageCommand::getheaders(network);
                    stream.write_all(&getheaders.encode(network)).await?;
                }
            } else {
                info!("🧩 Message reçu:\n{}", message.display());
                
                if let Some(response_message) = MessageCommand::respond_to(&message) {
                    let response_packet = response_message.encode(network);
                    debug!("Envoi de la réponse '{}'...", response_message.display());
                    stream.write_all(&response_packet).await?;
                }

                if matches!(message, MessageCommand::Verack) {
                    if !guard.has_sync_node.swap(true, Ordering::SeqCst) {
                        guard.is_sync_node = true;
                        info!("👑 Handshake complété ! Ce pair devient le Sync Node. Envoi de 'getheaders'...");
                        let getheaders = MessageCommand::getheaders(network);
                        let packet = getheaders.encode(network);
                        stream.write_all(&packet).await?;
                    } else {
                        info!("🎧 Handshake complété ! Ce pair est en Standby (Listener).");
                    }
                }
            }
        }
    }

    Ok(())
}