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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialisation du logging avec le niveau INFO par défaut
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let network = Network::Signet;
    let target_peer = format!("127.0.0.1:{}", network.default_port());
    
    info!("Démarrage du mini-nœud Bitcoin sur le réseau {:?}...", network);

    loop {
        info!("Tentative de connexion à {}...", target_peer);
        
        let connect_result = timeout(Duration::from_secs(5), TcpStream::connect(&target_peer)).await;
        
        match connect_result {
            Ok(Ok(mut stream)) => {
                info!("✅ Connecté avec succès au peer !");
                if let Err(e) = handle_connection(&mut stream, network).await {
                    error!("❌ Erreur de connexion ou déconnexion inattendue : {}", e);
                }
            }
            Ok(Err(e)) => {
                warn!("❌ Impossible de se connecter : {}", e);
            }
            Err(_) => {
                warn!("⏱️ Timeout : Le nœud distant met trop de temps à répondre.");
            }
        }
        
        info!("🔄 Nouvelle tentative de reconnexion dans 5 secondes...");
        sleep(Duration::from_secs(5)).await;
    }
}

async fn handle_connection(stream: &mut TcpStream, network: Network) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialisation du Handshake avec le message Version
    let version_message = MessageCommand::version(network).encode(network);

    debug!("Envoi du message 'version'...");
    stream.write_all(&version_message).await?;
    debug!("🚀 Message envoyé ! En attente des données réseau...");

    // 2. Boucle de lecture asynchrone pour traiter le flux réseau
    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    let mut pb: Option<ProgressBar> = None;
    
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
                let bar = ProgressBar::new(v.start_height as u64);
                bar.set_style(ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocs ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("#>-"));
                pb = Some(bar);
            }

            if matches!(message, MessageCommand::Header(_)) {
                if let Some(ref bar) = pb {
                    let height = protocol::CHAIN_STATE.lock().unwrap().best_block_height as u64;
                    bar.set_position(height);
                    if height >= bar.length().unwrap_or(0) {
                        bar.finish_with_message("✅ Synchronisation terminée !");
                    }
                }
            } else {
                info!("🧩 Message reçu:\n{}", message.display());
            }

            // Réponse automatique (ex: pong en réponse à un ping, ou verack après version)
            if let Some(response_message) = MessageCommand::respond_to(&message) {
                let response_packet = response_message.encode(network);
                debug!("Envoi de la réponse '{}'...", response_message.display());
                stream.write_all(&response_packet).await?;
            }

            // Une fois le peer prêt (Handshake terminé avec le Verack du peer)
            if matches!(message, MessageCommand::Verack) {
                info!("🤝 Handshake complété ! Envoi de 'getheaders'...");
                let getheaders = MessageCommand::getheaders(network);
                let packet = getheaders.encode(network);
                stream.write_all(&packet).await?;
            }
        }
    }

    Ok(())
}