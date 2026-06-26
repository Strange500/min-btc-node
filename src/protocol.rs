use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

use crate::messages::{VersionMessage, GetHeadersMessage};
use crate::codec::{WriteExt, ReadExt};

// Configuration du réseau Regtest
pub const REGTEST_MAGIC: [u8; 4] = [0xFA, 0xBF, 0xB5, 0xDA];
pub const PROTOCOL_VERSION: i32 = 70015;

#[derive(Debug, Clone)]
pub enum MessageCommand {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(GetHeadersMessage),
    Unknown { command: String, payload: Vec<u8> },
}

impl MessageCommand {
    pub fn version() -> MessageCommand {
        let mut addr_recv = [0u8; 26];
        addr_recv[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        addr_recv[24..26].copy_from_slice(&18444u16.to_be_bytes());

        let mut addr_from = [0u8; 26];
        addr_from[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        addr_from[24..26].copy_from_slice(&0u16.to_be_bytes());

        MessageCommand::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            addr_recv,
            addr_from,
            nonce: 123456789,
            user_agent: "/mini-node:0.1/".to_string(),
            start_height: 0,
            relay: 0,
        })
    }

    pub fn getheaders() -> MessageCommand {
        // Regtest genesis block hash in internal byte order
        let genesis_hash = [
            0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
            0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
            0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
            0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f
        ];

        MessageCommand::GetHeaders(GetHeadersMessage {
            version: PROTOCOL_VERSION as u32,
            hash_count: 1,
            block_locator_hashes: vec![genesis_hash],
            stop_hash: [0u8; 32],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            MessageCommand::Version(msg) => {
                let _ = msg.write(&mut payload);
                forge_packet("version", &payload)
            }
            MessageCommand::Verack => forge_packet("verack", &[]),
            MessageCommand::Pong(nonce) => {
                let _ = payload.write_u64_le(*nonce);
                forge_packet("pong", &payload)
            }
            MessageCommand::GetHeaders(msg) => {
                let _ = msg.write(&mut payload);
                forge_packet("getheaders", &payload)
            }
            _ => unreachable!("Only version, verack, pong, and getheaders are encoded"),
        }
    }

    pub fn from_packet(packet: &[u8]) -> Option<(MessageCommand, usize)> {
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
        let message = Self::decipher(command, payload).ok()?;
        Some((message, 24 + payload_len))
    }

    pub fn display(&self) -> String {
        match self {
            MessageCommand::Version(msg) => {
                let addr_recv_ip = format!("{}.{}.{}.{}",
                    msg.addr_recv[20], msg.addr_recv[21], msg.addr_recv[22], msg.addr_recv[23]);
                let addr_from_ip = format!("{}.{}.{}.{}",
                    msg.addr_from[20], msg.addr_from[21], msg.addr_from[22], msg.addr_from[23]);
                format!(
                    "VERSION\n  Protocol: {}\n  Services: {}\n  Timestamp: {}\n  Recv Addr: {}\n  From Addr: {}\n  Nonce: {}\n  User Agent: {}\n  Start Height: {}\n  Relay: {}",
                    msg.version, msg.services, msg.timestamp, addr_recv_ip, addr_from_ip, msg.nonce, msg.user_agent, msg.start_height, msg.relay
                )
            }
            MessageCommand::Verack => "VERACK (Acknowledgement)".to_string(),
            MessageCommand::Ping(nonce) => format!("PING (Nonce: {})", nonce),
            MessageCommand::Pong(nonce) => format!("PONG (Nonce: {})", nonce),
            MessageCommand::Unknown { command, payload } => {
                format!("UNKNOWN (Command: {}, Payload: {:?})", command, payload)
            }
            MessageCommand::GetHeaders(msg) => {
                format!("GETHEADERS\n  Version: {}\n  Hash Count: {}\n  Stop Hash: {:?}", 
                        msg.version, msg.hash_count, msg.stop_hash)
            }
        }
    }

    fn decipher(command: &str, payload: &[u8]) -> io::Result<MessageCommand> {
        let mut reader = io::Cursor::new(payload);
        match command {
            "ping" => {
                let nonce = reader.read_u64_le()?;
                Ok(MessageCommand::Ping(nonce))
            }
            "pong" => {
                let nonce = reader.read_u64_le()?;
                Ok(MessageCommand::Pong(nonce))
            }
            "version" => {
                let version_msg = VersionMessage::read(&mut reader)?;
                Ok(MessageCommand::Version(version_msg))
            }
            "getheaders" => {
                let getheaders_msg = GetHeadersMessage::read(&mut reader)?;
                Ok(MessageCommand::GetHeaders(getheaders_msg))
            }
            "verack" => Ok(MessageCommand::Verack),
            _ => Ok(MessageCommand::Unknown {
                command: command.to_string(),
                payload: payload.to_vec(),
            }),
        }
    }

    pub fn respond_to(message: &MessageCommand) -> Option<MessageCommand> {
        match message {
            MessageCommand::Ping(nonce) => Some(MessageCommand::Pong(*nonce)),
            MessageCommand::Verack => None, 
            MessageCommand::Version(_) => Some(MessageCommand::Verack),
            MessageCommand::GetHeaders(_) => Some(MessageCommand::Verack),
            _ => None,
        }
    }
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

pub fn forge_packet(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(24 + payload.len());
    packet.extend_from_slice(&REGTEST_MAGIC);
    
    let mut cmd_bytes = [0u8; 12];
    let cmd_len = command.len().min(12);
    cmd_bytes[..cmd_len].copy_from_slice(&command.as_bytes()[..cmd_len]);
    packet.extend_from_slice(&cmd_bytes);
    
    packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    
    let checksum = double_sha256(payload);
    packet.extend_from_slice(&checksum[..4]);
    
    packet.extend_from_slice(payload);
    
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_encode_decode() {
        let original = MessageCommand::version();
        let encoded_packet = original.encode();
        
        let decoded = MessageCommand::from_packet(&encoded_packet);
        assert!(decoded.is_some(), "Le paquet doit être décodable");
        
        let (message, consumed) = decoded.unwrap();
        assert_eq!(consumed, encoded_packet.len(), "Le paquet entier doit être consommé");
        
        match message {
            MessageCommand::Version(v) => {
                assert_eq!(v.version, PROTOCOL_VERSION);
                assert_eq!(v.user_agent, "/mini-node:0.1/");
                assert_eq!(v.nonce, 123456789);
            }
            _ => panic!("Expected Version message"),
        }
    }

    #[test]
    fn test_getheaders_encode_decode() {
        let original = MessageCommand::getheaders();
        let encoded_packet = original.encode();

        let decoded = MessageCommand::from_packet(&encoded_packet);
        assert!(decoded.is_some(), "Le paquet doit être décodable");

        let (message, consumed) = decoded.unwrap();
        assert_eq!(consumed, encoded_packet.len(), "Le paquet entier doit être consommé");

        match message {
            MessageCommand::GetHeaders(g) => {
                assert_eq!(g.version, PROTOCOL_VERSION as u32);
                assert_eq!(g.hash_count, 1);
                assert_eq!(g.block_locator_hashes.len(), 1);
                assert_eq!(g.stop_hash, [0u8; 32]);
            }
            _ => panic!("Expected GetHeaders message"),
        }

    }

    #[test]
    fn test_ping_pong_encode_decode() {
        let nonce = 999;
        let pong = MessageCommand::Pong(nonce);
        let encoded_packet = pong.encode();
        
        let decoded = MessageCommand::from_packet(&encoded_packet);
        assert!(decoded.is_some());
        
        let (message, _) = decoded.unwrap();
        match message {
            MessageCommand::Pong(decoded_nonce) => {
                assert_eq!(decoded_nonce, nonce);
            }
            _ => panic!("Expected Pong message"),
        }
    }

    #[test]
    fn test_from_packet_incomplete() {
        let packet = MessageCommand::version().encode();
        
        let incomplete = &packet[0..packet.len() - 10];
        let decoded = MessageCommand::from_packet(incomplete);
        assert!(decoded.is_none(), "Un paquet incomplet ne doit pas être parsé");
    }

    #[test]
    fn test_from_packet_corrupted_magic() {
        let mut packet = MessageCommand::version().encode();
        packet[0] = 0x00; 
        
        let decoded = MessageCommand::from_packet(&packet);
        assert!(decoded.is_none(), "Un paquet avec des magic bytes invalides doit être rejeté");
    }

    #[test]
    fn test_forge_packet_checksum() {
        let payload = b"hello bitcoin";
        let packet = forge_packet("testcmd", payload);
        
        let expected_checksum = double_sha256(payload);
        assert_eq!(&packet[20..24], &expected_checksum[..4], "Le checksum du header doit correspondre au double SHA-256 du payload");
    }
}
