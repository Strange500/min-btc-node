use std::io::{self, Read, Write};
use sha2::{Digest, Sha256};
use crate::codec::{read_varint, write_varint};

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash2);
    out
}

#[derive(Debug, Clone)]
pub struct TxMessage {
    pub version: i32,
    pub flag: u8, // If present, always 0001, and indicates the presence of witness data 
    pub tx_in: Vec<TxIn>, // never empty
    pub tx_out: Vec<TxOut>,
    pub tx_witness: Option<Vec<TxMessageWitness>>,
    pub lock_time: u32, // 0 not locked
                        // < 500000000 : block height, otherwise unix timestamp
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_txid: Outpoint,
    pub script_sig: Vec<u8>, // uchar
    pub sequence: u32,      
}

#[derive(Debug, Clone)]
pub struct Outpoint {
    pub hash: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: i64, // satoshi
    pub pk_script: Vec<u8>,    // uchar usually the pub key
}

#[derive(Debug, Clone)]
pub  struct TxMessageWitness {
    pub witness: Vec<TxWitness>,
}

#[derive(Debug, Clone)]
pub struct TxWitness { 
    pub witness_data: Vec<u8>, // uchar
}

impl TxMessage {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let version = i32::from_le_bytes(buf4);

        let mut buf1 = [0u8; 1];
        reader.read_exact(&mut buf1)?;
        
        let mut flag = 0;
        let mut has_witness = false;
        let tx_in_count;

        if buf1[0] == 0 {
            reader.read_exact(&mut buf1)?;
            flag = buf1[0];
            has_witness = flag == 1;
            tx_in_count = read_varint(reader)?;
        } else {
            let mut chain = std::io::Cursor::new([buf1[0]]).chain(&mut *reader);
            tx_in_count = read_varint(&mut chain)?;
        }

        let mut tx_in = Vec::with_capacity(tx_in_count as usize);
        if tx_in_count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Transaction must have at least one input"));
        }
        for _ in 0..tx_in_count {
            tx_in.push(TxIn::read(reader)?);
        }

        let tx_out_count = read_varint(reader)?;
        let mut tx_out = Vec::with_capacity(tx_out_count as usize);
        for _ in 0..tx_out_count {
            tx_out.push(TxOut::read(reader)?);
        }

        let tx_witness = if has_witness {
            let mut witnesses = Vec::with_capacity(tx_in_count as usize);
            for _ in 0..tx_in_count {
                witnesses.push(TxMessageWitness::read(reader)?);
            }
            Some(witnesses)
        } else {
            None
        };

        reader.read_exact(&mut buf4)?;
        let lock_time = u32::from_le_bytes(buf4);

        Ok(TxMessage { version, flag, tx_in, tx_out, tx_witness, lock_time })
    }

    /// Encodes the transaction in legacy format (no witness data) for SIGHASH calculation
    pub fn encode_legacy(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.version.to_le_bytes());
        let _ = write_varint(buf, self.tx_in.len() as u64);
        for input in &self.tx_in {
            buf.extend_from_slice(&input.prev_txid.hash);
            buf.extend_from_slice(&input.prev_txid.index.to_le_bytes());
            let _ = write_varint(buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let _ = write_varint(buf, self.tx_out.len() as u64);
        for output in &self.tx_out {
            buf.extend_from_slice(&output.value.to_le_bytes());
            let _ = write_varint(buf, output.pk_script.len() as u64);
            buf.extend_from_slice(&output.pk_script);
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    /// Calculates the legacy signature hash for a specific input
    pub fn signature_hash(&self, input_index: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
        if input_index >= self.tx_in.len() {
            let mut hash = [0u8; 32];
            hash[0] = 1;
            return hash;
        }

        let mut tx_copy = self.clone();

        // 1. Clear all input scripts
        for input in &mut tx_copy.tx_in {
            input.script_sig.clear();
        }

        // 2. Set the script of the input we are signing to script_code
        tx_copy.tx_in[input_index].script_sig = script_code.to_vec();

        let sighash_type = hash_type & 31;
        let anyone_can_pay = (hash_type & 0x80) != 0;

        // 3. Apply SIGHASH_NONE / SIGHASH_SINGLE / SIGHASH_ALL modifications
        if sighash_type == 2 { // SIGHASH_NONE
            tx_copy.tx_out.clear();
            for (i, input) in tx_copy.tx_in.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        } else if sighash_type == 3 { // SIGHASH_SINGLE
            if input_index >= tx_copy.tx_out.len() {
                let mut hash = [0u8; 32];
                hash[0] = 1;
                return hash;
            }
            tx_copy.tx_out.truncate(input_index + 1);
            for i in 0..input_index {
                tx_copy.tx_out[i].value = -1;
                tx_copy.tx_out[i].pk_script.clear();
            }
            for (i, input) in tx_copy.tx_in.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        }

        // 4. Apply SIGHASH_ANYONECANPAY modifications
        if anyone_can_pay {
            let current_input = tx_copy.tx_in[input_index].clone();
            tx_copy.tx_in.clear();
            tx_copy.tx_in.push(current_input);
        }

        // 5. Serialize and hash
        let mut buf = Vec::new();
        tx_copy.encode_legacy(&mut buf);
        buf.extend_from_slice(&hash_type.to_le_bytes()); // append hashtype as 4 bytes

        double_sha256(&buf)
    }
}

impl TxIn {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let prev_txid = Outpoint::read(reader)?;
        let script_length = read_varint(reader)?;
        let mut script_sig = vec![0u8; script_length as usize];
        reader.read_exact(&mut script_sig)?;
        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let sequence = u32::from_le_bytes(buf4);
        Ok(TxIn { prev_txid, script_sig, sequence })
    }
}

impl Outpoint {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let index = u32::from_le_bytes(buf4);
        Ok(Outpoint { hash, index })
    }
}

impl TxOut {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut buf8 = [0u8; 8];
        reader.read_exact(&mut buf8)?;
        let value = i64::from_le_bytes(buf8);
        let pk_script_length = read_varint(reader)?;
        let mut pk_script = vec![0u8; pk_script_length as usize];
        reader.read_exact(&mut pk_script)?;
        Ok(TxOut { value,  pk_script })
    }
}

impl TxMessageWitness {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let witness_count = read_varint(reader)?;
        let mut witness = Vec::with_capacity(witness_count as usize);
        for _ in 0..witness_count {
            witness.push(TxWitness::read(reader)?);
        }
        Ok(TxMessageWitness { witness })
    }
}

impl TxWitness {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let witness_length = read_varint(reader)?;
        let mut witness_data = vec![0u8; witness_length as usize];
        reader.read_exact(&mut witness_data)?;
        Ok(TxWitness { witness_data })
    }
}
