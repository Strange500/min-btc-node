//! A lightweight, interactive Bitcoin SPV (Simplified Payment Verification) mini-node.
//!
//! This application connects to the Bitcoin peer-to-peer network, discovers peers
//! via DNS seeds, and maintains an asynchronous connection pool. It uses a terminal
//! user interface (TUI) to visualize the real-time status of connections and network activity.
//!
//! # Terminal Usage
//!
//! ```sh
//! $ btc-new --network mainnet
//! $ btc-new --network testnet
//! $ btc-new --network signet
//! ```



mod protocol;
mod tui;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use protocol::MessageCommand;
use primitives::network::Network;
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

/// Guard that ensures a peer relinquishes the `Sync Node` role upon disconnection.
///
/// Only one peer in the pool can be designated as the active "Sync Node" responsible
/// for fetching headers and blocks. This guard drops the role atomically if the connection
/// goes down.
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

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliNetwork {
    Mainnet,
    Signet,
    Regtest,
}

impl Into<Network> for CliNetwork {
    fn into(self) -> Network {
        match self {
            CliNetwork::Mainnet => Network::Mainnet,
            CliNetwork::Signet => Network::Signet,
            CliNetwork::Regtest => Network::Regtest,
        }
    }
}

/// Command-line arguments for the Bitcoin mini-node.
///
/// # Examples
///
/// ```sh
/// $ btc-new --network testnet
/// ```
#[derive(Parser, Debug)]
#[command(author, version, about = "Mini-nœud SPV Bitcoin interactif", long_about = None)]
struct Args {
    /// The Bitcoin network to join (mainnet, signet, testnet, regtest).
    ///
    /// # Default
    /// Defaults to `mainnet`.
    #[arg(short, long, default_value = "mainnet")]
    network: CliNetwork,

    /// Specific Bitcoin addresses to track locally (Client-Side Filtering).
    /// Can be specified multiple times (e.g., -a ADDR1 -a ADDR2).
    #[arg(short, long)]
    address: Vec<String>,
}

/// The main entry point of the application.
///
/// This async function sets up the peer pool, connects to peers found via DNS seeds,
/// and spins up the Terminal User Interface.
///
/// # Errors
///
/// Returns an error if the async runtime fails or if the TUI cannot be initialized.
///
/// # Exit Status
///
/// Returns `0` on successful shutdown, or a non-zero exit code if a fatal error occurs.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let network: Network = args.network.into();
    let pool_size = 3;

    let mut filter_hashes = Vec::new();
    for addr_str in &args.address {
        if let Some(decoded) = primitives::codec::decode_base58(addr_str) {
            if decoded.len() >= 25 {
                let hash_only = &decoded[1..21];
                filter_hashes.push(hash_only.to_vec());
                info!("🔍 Tracking address {} (Hash: {:x?})", addr_str, hash_only);
            } else {
                warn!("⚠️ Invalid address length for {}. Skipping.", addr_str);
            }
        } else {
            warn!("⚠️ Failed to decode Base58 address: {}. Skipping.", addr_str);
        }
    }
    
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
    let filter_hashes = Arc::new(filter_hashes);

    for peer_idx in 0..pool_size {
        let has_sync_node = has_sync_node.clone();
        let peer_pool = peer_pool.clone();
        let peer_index = peer_index.clone();
        let filter_hashes = filter_hashes.clone();
        
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
                        
                        if let Err(e) = handle_connection(&mut stream, network, peer_idx, target_peer, has_sync_node.clone(), filter_hashes.clone()).await {
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

/// Discovers Bitcoin peers by querying predefined DNS seeds for the specified network.
///
/// # Arguments
///
/// * `network` - The Bitcoin network to query seeds for.
///
/// # Returns
///
/// A vector of resolved `SocketAddr`s representing potential peers.
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

/// Handles the full lifecycle of a connected Bitcoin peer.
///
/// Reads continuously from the `TcpStream` into a buffer, parses complete network
/// messages, and dispatches them to `handle_peer_actions`.
///
/// # Arguments
///
/// * `stream` - The active TCP connection to the peer.
/// * `network` - The active network (e.g., Mainnet).
/// * `peer_idx` - The internal TUI index of this peer.
/// * `target_peer` - The IP address of the peer.
/// * `has_sync_node` - Shared atomic flag indicating if any peer is currently syncing.
///
/// # Errors
///
/// Returns an error if the TCP stream disconnects abruptly or if writing fails.
async fn handle_connection(stream: &mut TcpStream, network: Network, peer_idx: usize, target_peer: SocketAddr, has_sync_node: Arc<AtomicBool>, filter_hashes: Arc<Vec<Vec<u8>>>) -> Result<(), Box<dyn std::error::Error>> {
    let version_message = MessageCommand::Version(primitives::messages::VersionMessage::new(network)).encode(network);
    stream.write_all(&version_message).await?;

    if !filter_hashes.is_empty() {
        info!("🛡️  Filtrage Client-Side activé pour {} adresses sur le nœud {}.", filter_hashes.len(), target_peer);
    }

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
            
            if message.matches_filter(&filter_hashes) {
                info!("📥 {}", message);
            }

            let actions = message.process();
            handle_peer_actions(stream, actions, network, peer_idx, target_peer, &mut guard).await?;
        }
    }

    Ok(())
}

/// Processes a series of actions resulting from parsing a network message.
///
/// Actions can include replying with `pong`, saving headers to disk, or
/// attempting to take over the `Sync Node` role.
///
/// # Arguments
///
/// * `stream` - The TCP connection to send replies over.
/// * `actions` - A vector of state-machine actions to execute.
/// * `network` - The active Bitcoin network.
/// * `peer_idx` - TUI index of the peer.
/// * `target_peer` - Peer's socket address.
/// * `guard` - The synchronization role guard for this peer.
///
/// # Errors
///
/// Returns an error if disk IO fails while saving headers, or if network writing fails.
async fn handle_peer_actions(
    stream: &mut TcpStream,
    actions: Vec<protocol::PeerAction>,
    network: Network,
    peer_idx: usize,
    target_peer: SocketAddr,
    guard: &mut SyncNodeGuard,
) -> Result<(), Box<dyn std::error::Error>> {
    for action in actions {
        match action {
            protocol::PeerAction::Reply(reply) => {
                info!("📤 {}", reply);
                stream.write_all(&reply.encode(network)).await?;
            }
            protocol::PeerAction::UpdateTargetHeight(height) => {
                let mut chain = protocol::CHAIN_STATE.lock().unwrap();
                if height > chain.target_height {
                    chain.target_height = height;
                }
            }
            protocol::PeerAction::SaveHeaders(headers) => {
                let headers_len = headers.len();
                let added = tokio::task::spawn_blocking(move || protocol::save_new_headers(&headers)).await??;

                if guard.is_sync_node && added > 0 && headers_len == 2000 {
                    sleep(Duration::from_millis(50)).await;
                    request_headers(stream, network).await?;
                }
            }
            protocol::PeerAction::TryBecomeSyncNode => {
                if !guard.has_sync_node.swap(true, Ordering::SeqCst) {
                    guard.is_sync_node = true;
                    tui::update_peer(peer_idx, target_peer.to_string(), "Sync Node 👑".to_string());
                    info!("👑 {} devient le Sync Node. Envoi de 'getheaders'...", target_peer);
                    request_headers(stream, network).await?;
                } else if !guard.is_sync_node {
                    tui::update_peer(peer_idx, target_peer.to_string(), "Standby 🎧".to_string());
                    info!("🎧 {} est en Standby (Listener).", target_peer);
                }
            }
        }
    }
    Ok(())
}

/// Constructs and sends a `getheaders` message to the peer.
///
/// Automatically retrieves the latest locator hash from the internal chain state
/// and requests subsequent headers from the network.
///
/// # Arguments
///
/// * `stream` - The TCP connection to send the request over.
/// * `network` - The active Bitcoin network.
///
/// # Errors
///
/// Returns an error if writing to the stream fails.
async fn request_headers(stream: &mut TcpStream, network: Network) -> Result<(), Box<dyn std::error::Error>> {
    let locator_hash = get_locator_hash(network);
    let getheaders = MessageCommand::GetHeaders(primitives::messages::GetHeadersMessage::new(locator_hash));
    stream.write_all(&getheaders.encode(network)).await?;
    Ok(())
}

/// Retrieves the best known block hash to use as a locator.
///
/// If no blocks have been downloaded, returns the genesis block hash for the active network.
///
/// # Arguments
///
/// * `network` - The active Bitcoin network.
///
/// # Returns
///
/// A 32-byte array containing the double-SHA256 hash of the block.
fn get_locator_hash(network: Network) -> [u8; 32] {
    let state = crate::protocol::CHAIN_STATE.lock().unwrap();
    if state.best_block_hash == [0u8; 32] {
        network.genesis_hash()
    } else {
        state.best_block_hash
    }
}