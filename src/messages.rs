use std::io::{self, Read, Write};
use crate::codec::{ReadExt, WriteExt, read_varint, write_varint};

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

impl VersionMessage {
    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
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

    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
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
pub struct GetHeadersMessage {
    pub version: u32,
    pub hash_count: u64,
    pub block_locator_hashes: Vec<[u8; 32]>,
    pub stop_hash: [u8; 32],
}

impl GetHeadersMessage {
    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_u32_le(self.version as u32)?;
        write_varint(writer, self.hash_count)?;
        for hash in &self.block_locator_hashes {
            writer.write_all(hash)?;
        }
        writer.write_all(&self.stop_hash)?;
        Ok(())
    }

    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let version = reader.read_u32_le()?;
        let hash_count = read_varint(reader)?;
        
        let mut block_locator_hashes = Vec::with_capacity(hash_count as usize);
        for _ in 0..hash_count {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            block_locator_hashes.push(hash);
        }
        
        let mut stop_hash = [0u8; 32];
        reader.read_exact(&mut stop_hash)?;
        
        Ok(GetHeadersMessage {
            version,
            hash_count,
            block_locator_hashes,
            stop_hash,
        })
    }
}
