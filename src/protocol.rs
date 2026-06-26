use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

// Configuration du réseau Regtest
pub const REGTEST_MAGIC: [u8; 4] = [0xFA, 0xBF, 0xB5, 0xDA];
pub const PROTOCOL_VERSION: i32 = 70015;

// Extention helper traits for sequential reading/writing
#[allow(dead_code)]
pub trait ReadExt: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
    
    fn read_i32_le(&mut self) -> io::Result<i32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }
    
    fn read_i64_le(&mut self) -> io::Result<i64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }
    
    fn read_u64_le(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

#[allow(dead_code)]
pub trait WriteExt: Write {
    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        self.write_all(&[val])
    }
    
    fn write_i32_le(&mut self, val: i32) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_u32_le(&mut self, val: u32) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_i64_le(&mut self, val: i64) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_u64_le(&mut self, val: u64) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

pub trait Codec {
    fn write(&self, writer: &mut impl Write) -> io::Result<()>;
    fn read(reader: &mut impl Read) -> io::Result<Self>
    where
        Self: Sized;
}

#[derive(Debug, Clone)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: [u8; 26],
    pub addr_from: [u8; 26],
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: u8,
}

impl Codec for VersionMessage {
    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_i32_le(self.version)?;
        writer.write_u64_le(self.services)?;
        writer.write_i64_le(self.timestamp)?;
        writer.write_all(&self.addr_recv)?;
        writer.write_all(&self.addr_from)?;
        writer.write_u64_le(self.nonce)?;
        
        let ua_bytes = self.user_agent.as_bytes();
        writer.write_u8(ua_bytes.len() as u8)?;
        writer.write_all(ua_bytes)?;
        
        writer.write_i32_le(self.start_height)?;
        writer.write_u8(self.relay)?;
        Ok(())
    }

    fn read(reader: &mut impl Read) -> io::Result<Self> {
        let version = reader.read_i32_le()?;
        let services = reader.read_u64_le()?;
        let timestamp = reader.read_i64_le()?;
        
        let mut addr_recv = [0u8; 26];
        reader.read_exact(&mut addr_recv)?;
        
        let mut addr_from = [0u8; 26];
        reader.read_exact(&mut addr_from)?;
        
        let nonce = reader.read_u64_le()?;
        
        let ua_len = reader.read_u8()? as usize;
        let mut ua_bytes = vec![0u8; ua_len];
        reader.read_exact(&mut ua_bytes)?;
        let user_agent = String::from_utf8_lossy(&ua_bytes).into_owned();
        
        let start_height = reader.read_i32_le()?;
        let relay = reader.read_u8()?;
        
        Ok(VersionMessage {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

#[derive(Debug, Clone)]
pub enum MessageCommand {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
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
            _ => unreachable!("Only version, verack, and pong are encoded"),
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
        
        // Test du décodage du paquet complet
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
        
        // On tronque délibérément le paquet
        let incomplete = &packet[0..packet.len() - 10];
        let decoded = MessageCommand::from_packet(incomplete);
        assert!(decoded.is_none(), "Un paquet incomplet ne doit pas être parsé");
    }

    #[test]
    fn test_from_packet_corrupted_magic() {
        let mut packet = MessageCommand::version().encode();
        // Corruption des magic bytes
        packet[0] = 0x00; 
        
        let decoded = MessageCommand::from_packet(&packet);
        assert!(decoded.is_none(), "Un paquet avec des magic bytes invalides doit être rejeté");
    }

    #[test]
    fn test_forge_packet_checksum() {
        let payload = b"hello bitcoin";
        let packet = forge_packet("testcmd", payload);
        
        // Le checksum est situé aux octets 20..24
        let expected_checksum = double_sha256(payload);
        assert_eq!(&packet[20..24], &expected_checksum[..4], "Le checksum du header doit correspondre au double SHA-256 du payload");
    }
}
