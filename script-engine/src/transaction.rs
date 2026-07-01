use sha2::{Digest, Sha256};

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash2);
    out
}

pub fn write_varint(n: u64, buf: &mut Vec<u8>) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: i64,
    pub pk_script: Vec<u8>,
}

impl Transaction {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u64, buf);
        for input in &self.inputs {
            buf.extend_from_slice(&input.prev_txid);
            buf.extend_from_slice(&input.prev_index.to_le_bytes());
            write_varint(input.script_sig.len() as u64, buf);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, buf);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_varint(output.pk_script.len() as u64, buf);
            buf.extend_from_slice(&output.pk_script);
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    /// Calculates the signature hash for a specific input, given a script_code and hashtype.
    /// strictly following the legacy SIGHASH algorithm.
    pub fn signature_hash(&self, input_index: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
        if input_index >= self.inputs.len() {
            // SIGHASH_SINGLE bug: returns 1 in uint256 if index is out of bounds
            let mut hash = [0u8; 32];
            hash[0] = 1;
            return hash;
        }

        let mut tx_copy = self.clone();

        // 1. Clear all input scripts
        for input in &mut tx_copy.inputs {
            input.script_sig.clear();
        }

        // 2. Set the script of the input we are signing to script_code
        // (Assume script_code is already stripped of OP_CODESEPARATOR and signatures by the VM)
        tx_copy.inputs[input_index].script_sig = script_code.to_vec();

        let sighash_type = hash_type & 31;
        let anyone_can_pay = (hash_type & 0x80) != 0;

        // 3. Apply SIGHASH_NONE / SIGHASH_SINGLE / SIGHASH_ALL modifications
        if sighash_type == 2 { // SIGHASH_NONE
            tx_copy.outputs.clear();
            for (i, input) in tx_copy.inputs.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        } else if sighash_type == 3 { // SIGHASH_SINGLE
            if input_index >= tx_copy.outputs.len() {
                let mut hash = [0u8; 32];
                hash[0] = 1;
                return hash;
            }
            // Resize outputs to input_index + 1
            tx_copy.outputs.truncate(input_index + 1);
            // Nullify all outputs before input_index
            for i in 0..input_index {
                tx_copy.outputs[i].value = -1;
                tx_copy.outputs[i].pk_script.clear();
            }
            // Nullify sequence of all other inputs
            for (i, input) in tx_copy.inputs.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        }

        // 4. Apply SIGHASH_ANYONECANPAY modifications
        if anyone_can_pay {
            let current_input = tx_copy.inputs[input_index].clone();
            tx_copy.inputs.clear();
            tx_copy.inputs.push(current_input);
        }

        // 5. Serialize and hash
        let mut buf = Vec::new();
        tx_copy.encode(&mut buf);
        buf.extend_from_slice(&hash_type.to_le_bytes()); // append hashtype as 4 bytes

        double_sha256(&buf)
    }
}
