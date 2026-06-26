mod protocol;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use protocol::MessageCommand;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_peer = "127.0.0.1:18444";
    
    println!("Démarrage du mini-nœud Bitcoin...");

    loop {
        println!("Tentative de connexion à {}...", target_peer);
        
        // Timeout de connexion fixé à 5 secondes
        let connect_result = timeout(Duration::from_secs(5), TcpStream::connect(target_peer)).await;
        
        match connect_result {
            Ok(Ok(mut stream)) => {
                println!("✅ Connecté avec succès au peer !");
                if let Err(e) = handle_connection(&mut stream).await {
                    eprintln!("❌ Erreur de connexion ou déconnexion inattendue : {}", e);
                }
            }
            Ok(Err(e)) => {
                eprintln!("❌ Impossible de se connecter : {}", e);
            }
            Err(_) => {
                eprintln!("⏱️ Timeout : Le nœud distant met trop de temps à répondre.");
            }
        }
        
        println!("🔄 Nouvelle tentative de reconnexion dans 5 secondes...\n");
        sleep(Duration::from_secs(5)).await;
    }
}

async fn handle_connection(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let version_message = MessageCommand::version().encode();

    println!("Envoi du message 'version'...");
    stream.write_all(&version_message).await?;
    println!("🚀 Message envoyé ! En attente des données réseau...");

    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            println!("🔌 Le nœud distant a fermé la connexion proprement.");
            break;
        }
        
        pending.extend_from_slice(&buffer[..n]);

        loop {
            let Some((message, consumed)) = MessageCommand::from_packet(&pending) else {
                break;
            };

            println!("\n🧩 Message reçu:\n{}\n", message.display());
            pending.drain(0..consumed);

            // Réponse automatique (ex: pong en réponse à un ping, ou verack après version)
            if let Some(response_message) = MessageCommand::respond_to(&message) {
                let response_packet = response_message.encode();
                println!("Envoi de la réponse '{}'...", response_message.display());
                stream.write_all(&response_packet).await?;
            }
        }
    }

    Ok(())
}