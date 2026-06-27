use std::io::{self, Read, Write};
use crate::codec::{read_varint, write_varint};
use sha2::{Sha256, Digest};

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
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(&self.services.to_le_bytes())?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&self.addr_recv)?;
        writer.write_all(&self.addr_from)?;
        writer.write_all(&self.nonce.to_le_bytes())?;
        
        let ua_bytes = self.user_agent.as_bytes();
        writer.write_all(&[ua_bytes.len() as u8])?;
        writer.write_all(ua_bytes)?;
        
        writer.write_all(&self.start_height.to_le_bytes())?;
        writer.write_all(&[self.relay])?;
        Ok(())
    }

    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut buf4 = [0u8; 4];
        let mut buf8 = [0u8; 8];
        let mut buf1 = [0u8; 1];

        reader.read_exact(&mut buf4)?;
        let version = i32::from_le_bytes(buf4);

        reader.read_exact(&mut buf8)?;
        let services = u64::from_le_bytes(buf8);

        reader.read_exact(&mut buf8)?;
        let timestamp = i64::from_le_bytes(buf8);
        
        let mut addr_recv = [0u8; 26];
        reader.read_exact(&mut addr_recv)?;
        
        let mut addr_from = [0u8; 26];
        reader.read_exact(&mut addr_from)?;
        
        reader.read_exact(&mut buf8)?;
        let nonce = u64::from_le_bytes(buf8);
        
        reader.read_exact(&mut buf1)?;
        let ua_len = buf1[0] as usize;
        let mut ua_bytes = vec![0u8; ua_len];
        reader.read_exact(&mut ua_bytes)?;
        let user_agent = String::from_utf8_lossy(&ua_bytes).into_owned();
        
        reader.read_exact(&mut buf4)?;
        let start_height = i32::from_le_bytes(buf4);
        
        reader.read_exact(&mut buf1)?;
        let relay = buf1[0];
        
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
        writer.write_all(&self.version.to_le_bytes())?;
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
        let mut buf4 = [0u8; 4];

        reader.read_exact(&mut buf4)?;
        let version = i32::from_le_bytes(buf4);
        
        let mut prev_block = [0u8; 32];
        reader.read_exact(&mut prev_block)?;
        
        let mut merkle_root = [0u8; 32];
        reader.read_exact(&mut merkle_root)?;
        
        reader.read_exact(&mut buf4)?;
        let timestamp = u32::from_le_bytes(buf4);
        
        reader.read_exact(&mut buf4)?;
        let bits = u32::from_le_bytes(buf4);
        
        reader.read_exact(&mut buf4)?;
        let nonce = u32::from_le_bytes(buf4);
        
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

    pub fn read_from_disk(reader: &mut impl Read) -> io::Result<Self> {
        let mut buf4 = [0u8; 4];

        reader.read_exact(&mut buf4)?;
        let version = i32::from_le_bytes(buf4);
        
        let mut prev_block = [0u8; 32];
        reader.read_exact(&mut prev_block)?;
        
        let mut merkle_root = [0u8; 32];
        reader.read_exact(&mut merkle_root)?;
        
        reader.read_exact(&mut buf4)?;
        let timestamp = u32::from_le_bytes(buf4);
        
        reader.read_exact(&mut buf4)?;
        let bits = u32::from_le_bytes(buf4);
        
        reader.read_exact(&mut buf4)?;
        let nonce = u32::from_le_bytes(buf4);
        
        Ok(BlockHeader {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    pub fn as_bytes(&self) -> [u8; 80] {
        let mut raw_header = [0u8; 80];
        raw_header[0..4].copy_from_slice(&self.version.to_le_bytes());
        raw_header[4..36].copy_from_slice(&self.prev_block);
        raw_header[36..68].copy_from_slice(&self.merkle_root);
        raw_header[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        raw_header[72..76].copy_from_slice(&self.bits.to_le_bytes());
        raw_header[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        raw_header
    }

    pub fn write_to_disk(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.as_bytes())
    }

    pub fn get_hash(&self) -> [u8; 32] {
        Sha256::digest(Sha256::digest(self.as_bytes())).into()
    }

    pub fn get_target_bytes(&self) -> [u8; 32] {
        let mut target = [0u8; 32];
        let exponent = (self.bits >> 24) as usize;
        let mantissa = self.bits & 0x00ff_ffff;
        
        if (3..=32).contains(&exponent) {
            target[exponent - 1] = (mantissa >> 16) as u8;
            target[exponent - 2] = (mantissa >> 8) as u8;
            target[exponent - 3] = mantissa as u8;
        }
        target
    }

    pub fn check_proof_of_work(&self) -> bool {
        let hash_le = self.get_hash();
        let target = self.get_target_bytes();
        
        // Compare arrays from most significant to least significant byte (little-endian: reverse)
        let mut is_valid = true;
        for i in (0..32).rev() {
            if hash_le[i] < target[i] {
                break;
            } else if hash_le[i] > target[i] {
                is_valid = false;
                break;
            }
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
            bits: 0x20ffffff, // Exponent 32, Mantissa 0xffffff -> unimaginably huge target
            nonce: 0,
        };
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
        assert!(!header.check_proof_of_work(), "PoW should be invalid against a 0 target");
    }

    #[test]
    fn test_inv_message_deserialization() {
        let mut buffer = Vec::new();
        crate::codec::write_varint(&mut buffer, 2).unwrap();
        buffer.extend_from_slice(&1u32.to_le_bytes());
        buffer.extend_from_slice(&[1u8; 32]);
        buffer.extend_from_slice(&999u32.to_le_bytes());
        buffer.extend_from_slice(&[2u8; 32]);

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = InvMessage::read(&mut cursor).unwrap();

        assert_eq!(decoded.inventory.len(), 2);
        assert_eq!(decoded.inventory[0].inv_type, ObjectType::MsgTx);
        assert_eq!(decoded.inventory[0].hash, [1u8; 32]);
        assert_eq!(decoded.inventory[1].inv_type, ObjectType::Unknown(999));
        assert_eq!(decoded.inventory[1].hash, [2u8; 32]);
    }

    #[test]
    fn test_inv_message_exceeds_limit_read() {
        // Construct a raw var_int of 50,001 (which is 0xfd, 0x51, 0xc3 in little-endian format)
        // Actually, let's just use the `write_varint` helper directly if it's available,
        // or just manually craft a small payload.
        let mut buffer = Vec::new();
        crate::codec::write_varint(&mut buffer, 50_001).unwrap();
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = InvMessage::read(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_getdata_message_serialization() {
        let inv = InventoryVector {
            inv_type: ObjectType::MsgTx,
            hash: [0x42; 32],
        };
        let getdata = GetDataMessage {
            inventory: vec![inv.clone(), inv.clone()],
        };
        
        let mut buffer = Vec::new();
        getdata.write(&mut buffer).unwrap();
        
        // 1 byte for varint (2 elements) + 2 * (4 bytes type + 32 bytes hash)
        assert_eq!(buffer.len(), 1 + 2 * 36);
        assert_eq!(buffer[0], 2); // count = 2
        
        // First entry
        assert_eq!(&buffer[1..5], &1u32.to_le_bytes()); // MsgTx
        assert_eq!(&buffer[5..37], &[0x42; 32]);
        
        // Second entry
        assert_eq!(&buffer[37..41], &1u32.to_le_bytes()); // MsgTx
        assert_eq!(&buffer[41..73], &[0x42; 32]);
    }
}
#[derive(Debug, Clone)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}


#[derive(Debug, Clone)]
pub struct InventoryVector {
    pub inv_type: ObjectType,
    pub hash: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectType {
    Error,
    MsgTx,
    MsgBlock,
    MsgFilteredBlock,
    MsgCompactBlock,
    MsgWitnessTx,
    MsgWitnessBlock,
    MsgFilteredWitnessBlock,
    Unknown(u32),
}


impl ObjectType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => ObjectType::Error,
            1 => ObjectType::MsgTx,
            2 => ObjectType::MsgBlock,
            3 => ObjectType::MsgFilteredBlock,
            4 => ObjectType::MsgCompactBlock,
            0x40000001 => ObjectType::MsgWitnessTx,
            0x40000002 => ObjectType::MsgWitnessBlock,
            0x40000003 => ObjectType::MsgFilteredWitnessBlock,
            n => ObjectType::Unknown(n),
        }
    }
}

impl InvMessage {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let count = read_varint(reader)?;
        if count > 50_000 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Too many inventory entries"));
        }
        let mut inventory = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut buf4 = [0u8; 4];
            reader.read_exact(&mut buf4)?;
            let inv_type_u32 = u32::from_le_bytes(buf4);
            let inv_type = ObjectType::from_u32(inv_type_u32);
            
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            
            inventory.push(InventoryVector { inv_type, hash });
        }
        Ok(InvMessage { inventory })
    }
}

#[derive(Debug, Clone)]
pub struct GetDataMessage {
    pub inventory: Vec<InventoryVector>,
}


impl GetDataMessage {
    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        write_varint(writer, self.inventory.len() as u64)?;
        for inv in &self.inventory {
            writer.write_all(&(match inv.inv_type {
                ObjectType::Error => 0u32,
                ObjectType::MsgTx => 1u32,
                ObjectType::MsgBlock => 2u32,
                ObjectType::MsgFilteredBlock => 3u32,
                ObjectType::MsgCompactBlock => 4u32,
                ObjectType::MsgWitnessTx => 0x40000001u32,
                ObjectType::MsgWitnessBlock => 0x40000002u32,
                ObjectType::MsgFilteredWitnessBlock => 0x40000003u32,
                ObjectType::Unknown(n) => n,
            }).to_le_bytes())?;
            writer.write_all(&inv.hash)?;
        }
        Ok(())
    }
}
