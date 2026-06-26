mod codec;
mod messages;
mod protocol;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use protocol::MessageCommand;

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

    let target_peer = "127.0.0.1:18444";
    
    info!("Démarrage du mini-nœud Bitcoin...");

    loop {
        info!("Tentative de connexion à {}...", target_peer);
        
        // Timeout de connexion fixé à 5 secondes
        let connect_result = timeout(Duration::from_secs(5), TcpStream::connect(target_peer)).await;
        
        match connect_result {
            Ok(Ok(mut stream)) => {
                info!("✅ Connecté avec succès au peer !");
                if let Err(e) = handle_connection(&mut stream).await {
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

async fn handle_connection(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialisation du Handshake avec le message Version
    let version_message = MessageCommand::version().encode();

    debug!("Envoi du message 'version'...");
    stream.write_all(&version_message).await?;
    debug!("🚀 Message envoyé ! En attente des données réseau...");

    // 2. Boucle de lecture asynchrone pour traiter le flux réseau
    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            info!("🔌 Le nœud distant a fermé la connexion proprement.");
            break;
        }
        
        pending.extend_from_slice(&buffer[..n]);

        loop {
            let Some((message, consumed)) = MessageCommand::from_packet(&pending) else {
                break;
            };

            info!("🧩 Message reçu:\n{}", message.display());
            pending.drain(0..consumed);

            // Réponse automatique (ex: pong en réponse à un ping, ou verack après version)
            if let Some(response_message) = MessageCommand::respond_to(&message) {
                let response_packet = response_message.encode();
                debug!("Envoi de la réponse '{}'...", response_message.display());
                stream.write_all(&response_packet).await?;
            }

            // Une fois le peer prêt (Handshake terminé avec le Verack du peer)
            if matches!(message, MessageCommand::Verack) {
                info!("🤝 Handshake complété ! Envoi de 'getheaders'...");
                let getheaders = MessageCommand::getheaders();
                let packet = getheaders.encode();
                stream.write_all(&packet).await?;
            }
        }
    }

    Ok(())
}