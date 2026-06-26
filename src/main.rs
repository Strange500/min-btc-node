mod protocol;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use protocol::MessageCommand;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_peer = "127.0.0.1:18444";
    
    println!("Démarrage du mini-nœud Bitcoin...");
    let mut stream = TcpStream::connect(target_peer).await?;
    println!("✅ Connecté avec succès au peer !");

    // Construction du message via l'enum
    let version_message = MessageCommand::version().encode();

    // Envoi
    println!("Envoi du message 'version'...");
    stream.write_all(&version_message).await?;
    println!("🚀 Envoyé ! En attente de la réponse...");

    // Boucle de lecture pour intercepter les retours
    let mut buffer = [0u8; 1024];
    let mut pending = Vec::new();
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                println!("Le nœud distant a fermé la connexion.");
                break;
            }
            Ok(n) => {
                println!("📥 Reçu {} octets du nœud !", n);
                pending.extend_from_slice(&buffer[..n]);

                loop {
                    let Some((message, consumed)) = MessageCommand::from_packet(&pending) else {
                        break;
                    };

                    println!("\n🧩 Message reçu:\n{}\n", message.display());
                    pending.drain(0..consumed);

                    let response = MessageCommand::respond_to(&message);
                    if let Some(response_message) = response {
                        let response_packet = response_message.encode();
                        println!("Envoi de la réponse '{}'...", response_message.display());
                        stream.write_all(&response_packet).await?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Erreur de lecture réseau : {}", e);
                break;
            }
        }
    }

    Ok(())
}