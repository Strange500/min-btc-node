use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use sha2::{Sha256, Digest};

// Configuration du réseau Regtest
const REGTEST_MAGIC: [u8; 4] = [0xFA, 0xBF, 0xB5, 0xDA];
const PROTOCOL_VERSION: i32 = 70015;



#[derive(Debug)]
#[allow(dead_code)]
enum MessageCommand {
    Version(i32, u64, i64, [u8; 26], [u8; 26], u64, String, i32, u8),
    Verack,
}


impl MessageCommand {
    fn version() -> MessageCommand {
        let mut addr_recv = [0u8; 26];
        addr_recv[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        addr_recv[24..26].copy_from_slice(&18444u16.to_be_bytes());

        let mut addr_from = [0u8; 26];
        addr_from[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        addr_from[24..26].copy_from_slice(&0u16.to_be_bytes());

        MessageCommand::Version(
            PROTOCOL_VERSION,
            0,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            addr_recv,
            addr_from,
            123456789,
            "/mini-node:0.1/".to_string(),
            0,
            0,
        )
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            MessageCommand::Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay) => {
                let mut payload = Vec::with_capacity(81 + user_agent.len() + 5);

                payload.extend_from_slice(&version.to_le_bytes());
                payload.extend_from_slice(&services.to_le_bytes());
                payload.extend_from_slice(&timestamp.to_le_bytes());
                payload.extend_from_slice(addr_recv);
                payload.extend_from_slice(addr_from);
                payload.extend_from_slice(&nonce.to_le_bytes());
                payload.push(user_agent.len() as u8);
                payload.extend_from_slice(user_agent.as_bytes());
                payload.extend_from_slice(&start_height.to_le_bytes());
                payload.push(*relay);

                forge_packet("version", &payload)
            }
            MessageCommand::Verack => forge_packet("verack", &[]),
        }
    }

    fn from_packet(packet: &[u8]) -> Option<(MessageCommand, usize)> {
        if packet.len() < 24 {
            return None;
        }

        if packet[0..4] != REGTEST_MAGIC {
            return None;
        }

        let command_bytes = &packet[4..16];
        let command_len = command_bytes.iter().position(|byte| *byte == 0).unwrap_or(12);
        let command = std::str::from_utf8(&command_bytes[..command_len]).ok()?;
        let payload_len = u32::from_le_bytes(packet[16..20].try_into().ok()?) as usize;
        if packet.len() < 24 + payload_len {
            return None;
        }

        let payload = &packet[24..24 + payload_len];
        let message = Self::decipher(command, payload)?;
        Some((message, 24 + payload_len))
    }

    fn display(&self) -> String {
        match self {
            MessageCommand::Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay) => {
                let addr_recv_ip = format!("{}.{}.{}.{}",
                    addr_recv[20], addr_recv[21], addr_recv[22], addr_recv[23]);
                let addr_from_ip = format!("{}.{}.{}.{}",
                    addr_from[20], addr_from[21], addr_from[22], addr_from[23]);
                format!(
                    "VERSION\n  Protocol: {}\n  Services: {}\n  Timestamp: {}\n  Recv Addr: {}\n  From Addr: {}\n  Nonce: {}\n  User Agent: {}\n  Start Height: {}\n  Relay: {}",
                    version, services, timestamp, addr_recv_ip, addr_from_ip, nonce, user_agent, start_height, relay
                )
            }
            MessageCommand::Verack => "VERACK (Acknowledgement)".to_string(),
        }
    }

    #[allow(dead_code)]
    fn decipher(command: &str, payload: &[u8]) -> Option<MessageCommand> {
        match command {
            "version" => {
                if payload.len() < 86 {
                    return None; // Vérification de la taille minimale
                }
                let version = i32::from_le_bytes(payload[0..4].try_into().unwrap());
                let services = u64::from_le_bytes(payload[4..12].try_into().unwrap());
                let timestamp = i64::from_le_bytes(payload[12..20].try_into().unwrap());
                let addr_recv = payload[20..46].try_into().unwrap();
                let addr_from = payload[46..72].try_into().unwrap();
                let nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());
                
                // User Agent (VarStr)
                let user_agent_len = payload[80] as usize;
                if payload.len() < 81 + user_agent_len + 5 {
                    return None; // Vérification de la taille pour le User Agent
                }
                let user_agent = String::from_utf8_lossy(&payload[81..81 + user_agent_len]).to_string();
                
                let start_height = i32::from_le_bytes(payload[81 + user_agent_len..85 + user_agent_len].try_into().unwrap());
                let relay = payload[85 + user_agent_len];
                
                Some(MessageCommand::Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay))
            }
            "verack" => Some(MessageCommand::Verack),
            _ => None,
        }
    }


}

/// Calcule le double SHA-256 standard de Bitcoin
fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Forge un paquet Bitcoin complet (Header + Payload) pour n'importe quelle commande
fn forge_packet(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(24 + payload.len());
    
    // 1. Magic Bytes (4 octets)
    packet.extend_from_slice(&REGTEST_MAGIC);
    
    // 2. Command Name (12 octets, complété par des zéros)
    let mut cmd_bytes = [0u8; 12];
    let cmd_len = command.len().min(12);
    cmd_bytes[..cmd_len].copy_from_slice(&command.as_bytes()[..cmd_len]);
    packet.extend_from_slice(&cmd_bytes);
    
    // 3. Payload Length (4 octets, Little-Endian)
    packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    
    // 4. Checksum (4 premiers octets du double SHA-256)
    let checksum = double_sha256(payload);
    packet.extend_from_slice(&checksum[..4]);
    
    // 5. Payload
    packet.extend_from_slice(payload);
    
    packet
}

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

                    if matches!(message, MessageCommand::Version(..)) {
                        let verack_message = MessageCommand::Verack.encode();
                        println!("Envoi du message 'verack'...");
                        stream.write_all(&verack_message).await?;
                        println!("✅ 'verack' envoyé !");
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