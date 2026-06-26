use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

use crate::messages::{BlockHeader, GetHeadersMessage, HeadersMessage, VersionMessage};
use crate::codec::{read_varint, write_varint};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

pub const PROTOCOL_VERSION: i32 = 70015;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xF9, 0xBE, 0xB4, 0xD9],
            Network::Signet => [0x0A, 0x03, 0xCF, 0x40],
            Network::Regtest => [0xFA, 0xBF, 0xB5, 0xDA],
        }
    }

    pub fn genesis_hash(self) -> [u8; 32] {
        match self {
            Network::Mainnet => [
                0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
                0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
                0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
                0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            Network::Signet => [
                0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 
                0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9, 
                0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 
                0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
            ],
            Network::Regtest => [
                0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
                0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
                0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
                0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f
            ],
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    pub fn dns_seeds(self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &[
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
            ],
            Network::Signet => &[
                "seed.signet.bitcoin.sprovoost.nl",
            ],
            Network::Regtest => &["127.0.0.1"],
        }
    }
}


pub struct ChainState {
    pub best_block_hash: [u8; 32],
    pub best_block_height: u32,
    pub target_height: u32,
    pub header_cache: HashMap<[u8; 32], BlockHeader>,
}

pub static CHAIN_STATE: LazyLock<Mutex<ChainState>> = LazyLock::new(|| {
    Mutex::new(ChainState {
        best_block_hash: [0u8; 32],
        best_block_height: 0,
        target_height: 0,
        header_cache: HashMap::new(),
    })
});
fn verify_block_header(header: &BlockHeader, prev_header: Option<&BlockHeader>) -> bool {
    // Check proof of work
    if !header.check_proof_of_work() {
        return false;
    }

    // If there's a previous header, check the linkage
    if let Some(prev) = prev_header {
        if header.prev_block != prev.get_hash() {
            return false;
        }
    }

    true
}

pub fn save_new_headers(headers: &[BlockHeader]) -> io::Result<usize> {
    let mut state = CHAIN_STATE.lock().unwrap();
    let mut added = 0;
    // verify and save the new headers to the chain state
    for header in headers {
        let hash = header.get_hash();
        if state.header_cache.contains_key(&hash) {
            continue;
        }

        let prev_header = state.header_cache.get(&header.prev_block);
        if !verify_block_header(header, prev_header) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid block header"));
        }
        
        state.header_cache.insert(hash, header.clone());
        state.best_block_hash = hash;
        state.best_block_height += 1;
        added += 1;
    }
    Ok(added)
}


#[derive(Debug, Clone)]
pub enum MessageCommand {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(GetHeadersMessage),
    Header(HeadersMessage),
    Unknown { command: String, payload: Vec<u8> },
}

impl MessageCommand {
    pub fn version(net: Network) -> MessageCommand {
        let mut addr_recv = [0u8; 26];
        addr_recv[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        addr_recv[24..26].copy_from_slice(&net.default_port().to_be_bytes());

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

    pub fn getheaders(net: Network) -> MessageCommand {
        let best_hash = {
            let state = CHAIN_STATE.lock().unwrap();
            state.best_block_hash
        };
        
        let locator_hash = if best_hash == [0u8; 32] {
            net.genesis_hash()
        } else {
            best_hash
        };

        MessageCommand::GetHeaders(GetHeadersMessage {
            version: PROTOCOL_VERSION as u32,
            hash_count: 1,
            block_locator_hashes: vec![locator_hash],
            stop_hash: [0u8; 32],
        })
    }

    pub fn encode(&self, net: Network) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            MessageCommand::Version(msg) => {
                let _ = msg.write(&mut payload);
                forge_packet("version", &payload, net)
            }
            MessageCommand::Verack => forge_packet("verack", &[], net),
            MessageCommand::Pong(nonce) => {
                payload.extend_from_slice(&nonce.to_le_bytes());
                forge_packet("pong", &payload, net)
            }
            MessageCommand::GetHeaders(msg) => {
                let _ = msg.write(&mut payload);
                forge_packet("getheaders", &payload, net)
            }
            _ => unreachable!("Only version, verack, pong, and getheaders are encoded"),
        }
    }

    pub fn from_packet(packet: &[u8], net: Network) -> Option<(MessageCommand, usize)> {
        if packet.len() < 24 {
            return None;
        }

        if packet[0..4] != net.magic() {
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
            MessageCommand::Header(msg) => {
                let count = msg.headers.len();
                if count == 0 {
                    "HEADERS\n  Count: 0\n  Headers: []".to_string()
                } else {
                    format!("HEADERS\n  Count: {}\n  [... {} headers omitted for brevity ...]", count, count)
                }
            }
        }
    }

    fn decipher(command: &str, payload: &[u8]) -> io::Result<MessageCommand> {
        let mut reader = io::Cursor::new(payload);
        match command {
            "ping" => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                Ok(MessageCommand::Ping(u64::from_le_bytes(buf)))
            }
            "pong" => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                Ok(MessageCommand::Pong(u64::from_le_bytes(buf)))
            }
            "version" => {
                let version_msg = VersionMessage::read(&mut reader)?;
                Ok(MessageCommand::Version(version_msg))
            }
            "headers" => {
                let headers_msg = HeadersMessage::read(&mut reader)?;
                Ok(MessageCommand::Header(headers_msg))
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

pub fn forge_packet(command: &str, payload: &[u8], net: Network) -> Vec<u8> {
    let mut packet = Vec::with_capacity(24 + payload.len());
    packet.extend_from_slice(&net.magic());
    
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
        let net = Network::Regtest;
        let original = MessageCommand::version(net);
        let encoded_packet = original.encode(net);
        
        let decoded = MessageCommand::from_packet(&encoded_packet, net);
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
    fn test_ping_pong_encode_decode() {
        let net = Network::Mainnet;
        let nonce = 999;
        let pong = MessageCommand::Pong(nonce);
        let encoded_packet = pong.encode(net);
        
        let decoded = MessageCommand::from_packet(&encoded_packet, net);
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
        let net = Network::Regtest;
        let packet = MessageCommand::version(net).encode(net);
        
        let incomplete = &packet[0..packet.len() - 10];
        let decoded = MessageCommand::from_packet(incomplete, net);
        assert!(decoded.is_none(), "Un paquet incomplet ne doit pas être parsé");
    }

    #[test]
    fn test_from_packet_corrupted_magic() {
        let net = Network::Regtest;
        let mut packet = MessageCommand::version(net).encode(net);
        packet[0] = 0x00; 
        
        let decoded = MessageCommand::from_packet(&packet, net);
        assert!(decoded.is_none(), "Un paquet avec des magic bytes invalides doit être rejeté");
    }

    #[test]
    fn test_forge_packet_checksum() {
        let net = Network::Regtest;
        let payload = b"hello bitcoin";
        let packet = forge_packet("testcmd", payload, net);
        
        let expected_checksum = double_sha256(payload);
        assert_eq!(&packet[20..24], &expected_checksum[..4], "Le checksum du header doit correspondre au double SHA-256 du payload");
    }
}
