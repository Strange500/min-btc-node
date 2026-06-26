use std::io::{self, Read, Write};
use crate::codec::{ReadExt, WriteExt, read_varint, write_varint};
use sha2::{Sha256, Digest};
use num_bigint::BigUint;


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
}

#[derive(Debug, Clone)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {


    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let version = reader.read_i32_le()?;
        
        let mut prev_block = [0u8; 32];
        reader.read_exact(&mut prev_block)?;
        
        let mut merkle_root = [0u8; 32];
        reader.read_exact(&mut merkle_root)?;
        
        let timestamp = reader.read_u32_le()?;
        let bits = reader.read_u32_le()?;
        let nonce = reader.read_u32_le()?;
        
        let _ = read_varint(reader)?; // discard txn_count
        
        Ok(BlockHeader {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    fn getRawHeader(&self) -> [u8; 80] {
        let mut raw_header = [0u8; 80];
        raw_header[0..4].copy_from_slice(&self.version.to_le_bytes());
        raw_header[4..36].copy_from_slice(&self.prev_block);
        raw_header[36..68].copy_from_slice(&self.merkle_root);
        raw_header[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        raw_header[72..76].copy_from_slice(&self.bits.to_le_bytes());
        raw_header[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        raw_header
    }

    pub fn getHash(&self) -> [u8; 32] {
        Sha256::digest(Sha256::digest(self.getRawHeader())).into()
    }

    pub fn get_target(&self) -> BigUint {
        let exponent = (self.bits >> 24) as usize;
        let mantissa = self.bits & 0x00ff_ffff;

        let mut target = BigUint::from(mantissa);

        if exponent >= 3 {
            target <<= 8 * (exponent - 3);
        } else {
            target >>= 8 * (3 - exponent);
        }

        target
    }

    pub fn check_proof_of_work(&self) -> bool {
        let hash_le = self.getHash();
        let hash_int = BigUint::from_bytes_le(&hash_le);
        let target = self.get_target();
        
        let is_valid = hash_int <= target;
        
        if is_valid {
            tracing::debug!(
                "✅ PoW valid\nHash:   {:064x}\nTarget: {:064x}", 
                hash_int, target
            );
        } else {
            tracing::warn!(
                "❌ PoW INVALID!\nHash:   {:064x}\nTarget: {:064x}", 
                hash_int, target
            );
        }
        
        is_valid
    }

}

impl HeadersMessage {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let count = read_varint(reader)?;
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let header = BlockHeader::read(reader)?;
            headers.push(header);
        }
        Ok(HeadersMessage { headers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_work_valid_huge_target() {
        let header = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1234567890,
            bits: 0xffffffff, // Exponent 255, Mantissa 0xffffff -> unimaginably huge target
            nonce: 0,
        };
        // The hash should definitely be smaller than this huge target
        assert!(header.check_proof_of_work(), "PoW should be valid against a max target");
    }

    #[test]
    fn test_proof_of_work_invalid_tiny_target() {
        let header = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1234567890,
            bits: 0x03000000, // Exponent 3, Mantissa 0 -> Target is 0
            nonce: 0,
        };
        // The hash will definitely be > 0
        assert!(!header.check_proof_of_work(), "PoW should be invalid against a 0 target");
    }
}
