use sha2::{Sha256, Digest};

pub mod transaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Op(OpCode),
    PushData(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    // ------------------------------------------------------------------------
    // Constants / Push Data (0x00, 0x4f - 0x60)
    // ------------------------------------------------------------------------
    Op0,             // 0x00
    // Note: Data push opcodes (0x01 - 0x4e) are consumed by the parser 
    // and yield `Instruction::PushData`. They do not exist in this enum.
    Op1Negate,       // 0x4f (Pushes -1)
    OpReserved,      // 0x50
    OpPushNum(u8),   // 0x51 - 0x60 (Pushes 1 through 16)

    // ------------------------------------------------------------------------
    // Control Flow (0x61 - 0x6a)
    // ------------------------------------------------------------------------
    OpNop,           // 0x61
    OpVer,           // 0x62
    OpIf,            // 0x63
    OpNotIf,         // 0x64
    OpVerIf,         // 0x65
    OpVerNotIf,      // 0x66
    OpElse,          // 0x67
    OpEndIf,         // 0x68
    OpVerify,        // 0x69
    OpReturn,        // 0x6a

    // ------------------------------------------------------------------------
    // Stack Operators (0x6b - 0x7d)
    // ------------------------------------------------------------------------
    OpToAltStack,    // 0x6b
    OpFromAltStack,  // 0x6c
    Op2Drop,         // 0x6d
    Op2Dup,          // 0x6e
    Op3Dup,          // 0x6f
    Op2Over,         // 0x70
    Op2Rot,          // 0x71
    Op2Swap,         // 0x72
    OpIfDup,         // 0x73
    OpDepth,         // 0x74
    OpDrop,          // 0x75
    OpDup,           // 0x76
    OpNip,           // 0x77
    OpOver,          // 0x78
    OpPick,          // 0x79
    OpRoll,          // 0x7a
    OpRot,           // 0x7b
    OpSwap,          // 0x7c
    OpTuck,          // 0x7d

    // ------------------------------------------------------------------------
    // Strings (0x7e - 0x82)
    // ------------------------------------------------------------------------
    OpCat,           // 0x7e
    OpSubStr,        // 0x7f
    OpLeft,          // 0x80
    OpRight,         // 0x81
    OpSize,          // 0x82

    // ------------------------------------------------------------------------
    // Bitwise Logic (0x83 - 0x8a)
    // ------------------------------------------------------------------------
    OpInvert,        // 0x83
    OpAnd,           // 0x84
    OpOr,            // 0x85
    OpXor,           // 0x86
    OpEqual,         // 0x87
    OpEqualVerify,   // 0x88
    OpReserved1,     // 0x89
    OpReserved2,     // 0x8a

    // ------------------------------------------------------------------------
    // Numeric (0x8b - 0xa5)
    // ------------------------------------------------------------------------
    Op1Add,               // 0x8b
    Op1Sub,               // 0x8c
    Op2Mul,               // 0x8d
    Op2Div,               // 0x8e
    OpNegate,             // 0x8f
    OpAbs,                // 0x90
    OpNot,                // 0x91
    Op0NotEqual,          // 0x92
    OpAdd,                // 0x93
    OpSub,                // 0x94
    OpMul,                // 0x95
    OpDiv,                // 0x96
    OpMod,                // 0x97
    OpLShift,             // 0x98
    OpRShift,             // 0x99
    OpBoolAnd,            // 0x9a
    OpBoolOr,             // 0x9b
    OpNumEqual,           // 0x9c
    OpNumEqualVerify,     // 0x9d
    OpNumNotEqual,        // 0x9e
    OpLessThan,           // 0x9f
    OpGreaterThan,        // 0xa0
    OpLessThanOrEqual,    // 0xa1
    OpGreaterThanOrEqual, // 0xa2
    OpMin,                // 0xa3
    OpMax,                // 0xa4
    OpWithin,             // 0xa5

    // ------------------------------------------------------------------------
    // Cryptography (0xa6 - 0xaf)
    // ------------------------------------------------------------------------
    OpRipemd160,          // 0xa6
    OpSha1,               // 0xa7
    OpSha256,             // 0xa8
    OpHash160,            // 0xa9
    OpHash256,            // 0xaa
    OpCodeSeparator,      // 0xab
    OpCheckSig,           // 0xac
    OpCheckSigVerify,     // 0xad
    OpCheckMultiSig,      // 0xae
    OpCheckMultiSigVerify,// 0xaf

    // ------------------------------------------------------------------------
    // Other (0xb0 - 0xff)
    // ------------------------------------------------------------------------
    OpCheckLockTimeVerify,// 0xb1
    OpCheckSequenceVerify,// 0xb2
    OpCheckSigAdd,        // 0xba
    
    // Groupings for upgradeable / NOP / success opcodes
    OpNopFuture(u8),      // 0xb0, 0xb3 - 0xb9
    OpReturnSuccess(u8),  // 0xbb - 0xfe
    OpInvalidOpcode,      // 0xff
}


impl OpCode {
    pub fn execute(&self, context: &mut ExecutionContext) -> Result<(), String> {
        match self {
            OpCode::Op0 => {
                context.stack.push(vec![]);
                Ok(())
            }
            OpCode::Op1Negate => {
                context.stack.push(vec![0x81]); // -1 in little-endian
                Ok(())
            }
            OpCode::OpPushNum(n) => {
                if *n == 0 {
                    context.stack.push(vec![]);
                } else {
                    context.stack.push(vec![*n]);
                }
                Ok(())
            }
            OpCode::OpDup => {
                if let Some(top) = context.stack.last() {
                    context.stack.push(top.clone());
                    Ok(())
                } else {
                    Err("Stack underflow on OP_DUP".to_string())
                }
            }
            OpCode::OpHash160 => {
                if let Some(top) = context.stack.pop() {
                    let sha256_hash = Sha256::digest(&top);
                    let hash = ripemd::Ripemd160::digest(&sha256_hash);
                    context.stack.push(hash.to_vec());
                    Ok(())
                } else {
                    Err("Stack underflow on OP_HASH160".to_string())
                }
            }
            OpCode::OpEqual => {
                if context.stack.len() < 2 {
                    return Err("Stack underflow on OP_EQUAL".to_string());
                }
                let a = context.stack.pop().unwrap();
                let b = context.stack.pop().unwrap();
                if a == b {
                    context.stack.push(vec![1]); // true
                } else {
                    context.stack.push(vec![]); // false
                }
                Ok(())
            }
            OpCode::OpEqualVerify => {
                if context.stack.len() < 2 {
                    return Err("Stack underflow on OP_EQUALVERIFY".to_string());
                }
                let a = context.stack.pop().unwrap();
                let b = context.stack.pop().unwrap();
                if a != b {
                    return Err("OP_EQUALVERIFY failed".to_string());
                }
                Ok(())
            }
            OpCode::OpCheckSig => {
                if context.stack.len() < 2 {
                    return Err("OP_CHECKSIG requires 2 items on stack".to_string());
                }
                let pubkey_bytes = context.stack.pop().unwrap();
                let sig_bytes = context.stack.pop().unwrap();

                if sig_bytes.is_empty() {
                    context.stack.push(vec![]); // Push false
                    return Ok(());
                }

                let hash_type = *sig_bytes.last().unwrap() as u32;
                let der_sig = &sig_bytes[..sig_bytes.len() - 1];

                // Compute the actual real signature hash using the transaction context!
                let hash = context.tx.signature_hash(context.input_index, &context.script_code, hash_type);

                use secp256k1::{Secp256k1, Message, ecdsa::Signature, PublicKey};
                let secp = Secp256k1::verification_only();
                
                let is_valid = match (PublicKey::from_slice(&pubkey_bytes), Signature::from_der(der_sig)) {
                    (Ok(pk), Ok(sig)) => {
                        let msg = Message::from_digest(hash);
                        secp.verify_ecdsa(msg, &sig, &pk).is_ok()
                    }
                    _ => false,
                };

                if is_valid {
                    context.stack.push(vec![1]); // True
                } else {
                    context.stack.push(vec![]); // False
                }
                Ok(())
            }

            _ => Err(format!("Opcode {:?} not implemented yet", self)),
        }
    }
}

pub fn parse_script(script: &[u8]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let byte = script[i];
        
        match byte {
            0x00 => {
                instructions.push(Instruction::Op(OpCode::Op0));
                i += 1;
            }
            0x01..=0x4b => {
                // OP_PUSHBYTES_N
                let len = byte as usize;
                if i + 1 + len <= script.len() {
                    let data = script[i + 1..i + 1 + len].to_vec();
                    instructions.push(Instruction::PushData(data));
                    i += 1 + len;
                } else {
                    instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                    break;
                }
            }
            0x4c => {
                // OP_PUSHDATA1
                if i + 2 <= script.len() {
                    let len = script[i + 1] as usize;
                    if i + 2 + len <= script.len() {
                        let data = script[i + 2..i + 2 + len].to_vec();
                        instructions.push(Instruction::PushData(data));
                        i += 2 + len;
                    } else {
                        instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                        break;
                    }
                } else {
                    instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                    break;
                }
            }
            // Small integer pushes (OP_1 to OP_16)
            0x51..=0x60 => { 
                instructions.push(Instruction::Op(OpCode::OpPushNum(byte - 0x50))); 
                i += 1; 
            },
            
            // Cryptography
            0xa9 => { instructions.push(Instruction::Op(OpCode::OpHash160)); i += 1; },
            0xac => { instructions.push(Instruction::Op(OpCode::OpCheckSig)); i += 1; },
            
            // NOPs
            0xb0 | 0xb3..=0xb9 => { 
                instructions.push(Instruction::Op(OpCode::OpNopFuture(byte))); 
                i += 1; 
            },
            
            // Return Successes
            0xbb..=0xfe => { 
                instructions.push(Instruction::Op(OpCode::OpReturnSuccess(byte))); 
                i += 1; 
            },
            
            0x4d => {
                // OP_PUSHDATA2
                if i + 3 <= script.len() {
                    let len = (script[i + 1] as usize) | ((script[i + 2] as usize) << 8);
                    if i + 3 + len <= script.len() {
                        let data = script[i + 3..i + 3 + len].to_vec();
                        instructions.push(Instruction::PushData(data));
                        i += 3 + len;
                    } else {
                        instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                        break;
                    }
                } else {
                    instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                    break;
                }
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 5 <= script.len() {
                    let len = (script[i + 1] as usize) | ((script[i + 2] as usize) << 8) | ((script[i + 3] as usize) << 16) | ((script[i + 4] as usize) << 24);
                    if i + 5 + len <= script.len() {
                        let data = script[i + 5..i + 5 + len].to_vec();
                        instructions.push(Instruction::PushData(data));
                        i += 5 + len;
                    } else {
                        instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                        break;
                    }
                } else {
                    instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                    break;
                }
            }
            0x4f => { instructions.push(Instruction::Op(OpCode::Op1Negate)); i += 1; }
            0x50 => { instructions.push(Instruction::Op(OpCode::OpReserved)); i += 1; }
            0x61 => { instructions.push(Instruction::Op(OpCode::OpNop)); i += 1; }
            0x62 => { instructions.push(Instruction::Op(OpCode::OpVer)); i += 1; }
            0x63 => { instructions.push(Instruction::Op(OpCode::OpIf)); i += 1; }
            0x64 => { instructions.push(Instruction::Op(OpCode::OpNotIf)); i += 1; }
            0x65 => { instructions.push(Instruction::Op(OpCode::OpVerIf)); i += 1; }
            0x66 => { instructions.push(Instruction::Op(OpCode::OpVerNotIf)); i += 1; }
            0x67 => { instructions.push(Instruction::Op(OpCode::OpElse)); i += 1; }
            0x68 => { instructions.push(Instruction::Op(OpCode::OpEndIf)); i += 1; }
            0x69 => { instructions.push(Instruction::Op(OpCode::OpVerify)); i += 1; }
            0x6a => { instructions.push(Instruction::Op(OpCode::OpReturn)); i += 1; }
            0x6b => { instructions.push(Instruction::Op(OpCode::OpToAltStack)); i += 1; }
            0x6c => { instructions.push(Instruction::Op(OpCode::OpFromAltStack)); i += 1; }
            0x6d => { instructions.push(Instruction::Op(OpCode::Op2Drop)); i += 1; }
            0x6e => { instructions.push(Instruction::Op(OpCode::Op2Dup)); i += 1; }
            0x6f => { instructions.push(Instruction::Op(OpCode::Op3Dup)); i += 1; }
            0x70 => { instructions.push(Instruction::Op(OpCode::Op2Over)); i += 1; }
            0x71 => { instructions.push(Instruction::Op(OpCode::Op2Rot)); i += 1; }
            0x72 => { instructions.push(Instruction::Op(OpCode::Op2Swap)); i += 1; }
            0x73 => { instructions.push(Instruction::Op(OpCode::OpIfDup)); i += 1; }
            0x74 => { instructions.push(Instruction::Op(OpCode::OpDepth)); i += 1; }
            0x75 => { instructions.push(Instruction::Op(OpCode::OpDrop)); i += 1; }
            0x76 => { instructions.push(Instruction::Op(OpCode::OpDup)); i += 1; }
            0x77 => { instructions.push(Instruction::Op(OpCode::OpNip)); i += 1; }
            0x78 => { instructions.push(Instruction::Op(OpCode::OpOver)); i += 1; }
            0x79 => { instructions.push(Instruction::Op(OpCode::OpPick)); i += 1; }
            0x7a => { instructions.push(Instruction::Op(OpCode::OpRoll)); i += 1; }
            0x7b => { instructions.push(Instruction::Op(OpCode::OpRot)); i += 1; }
            0x7c => { instructions.push(Instruction::Op(OpCode::OpSwap)); i += 1; }
            0x7d => { instructions.push(Instruction::Op(OpCode::OpTuck)); i += 1; }
            0x7e => { instructions.push(Instruction::Op(OpCode::OpCat)); i += 1; }
            0x7f => { instructions.push(Instruction::Op(OpCode::OpSubStr)); i += 1; }
            0x80 => { instructions.push(Instruction::Op(OpCode::OpLeft)); i += 1; }
            0x81 => { instructions.push(Instruction::Op(OpCode::OpRight)); i += 1; }
            0x82 => { instructions.push(Instruction::Op(OpCode::OpSize)); i += 1; }
            0x83 => { instructions.push(Instruction::Op(OpCode::OpInvert)); i += 1; }
            0x84 => { instructions.push(Instruction::Op(OpCode::OpAnd)); i += 1; }
            0x85 => { instructions.push(Instruction::Op(OpCode::OpOr)); i += 1; }
            0x86 => { instructions.push(Instruction::Op(OpCode::OpXor)); i += 1; }
            0x87 => { instructions.push(Instruction::Op(OpCode::OpEqual)); i += 1; }
            0x88 => { instructions.push(Instruction::Op(OpCode::OpEqualVerify)); i += 1; }
            0x89 => { instructions.push(Instruction::Op(OpCode::OpReserved1)); i += 1; }
            0x8a => { instructions.push(Instruction::Op(OpCode::OpReserved2)); i += 1; }
            0x8b => { instructions.push(Instruction::Op(OpCode::Op1Add)); i += 1; }
            0x8c => { instructions.push(Instruction::Op(OpCode::Op1Sub)); i += 1; }
            0x8d => { instructions.push(Instruction::Op(OpCode::Op2Mul)); i += 1; }
            0x8e => { instructions.push(Instruction::Op(OpCode::Op2Div)); i += 1; }
            0x8f => { instructions.push(Instruction::Op(OpCode::OpNegate)); i += 1; }
            0x90 => { instructions.push(Instruction::Op(OpCode::OpAbs)); i += 1; }
            0x91 => { instructions.push(Instruction::Op(OpCode::OpNot)); i += 1; }
            0x92 => { instructions.push(Instruction::Op(OpCode::Op0NotEqual)); i += 1; }
            0x93 => { instructions.push(Instruction::Op(OpCode::OpAdd)); i += 1; }
            0x94 => { instructions.push(Instruction::Op(OpCode::OpSub)); i += 1; }
            0x95 => { instructions.push(Instruction::Op(OpCode::OpMul)); i += 1; }
            0x96 => { instructions.push(Instruction::Op(OpCode::OpDiv)); i += 1; }
            0x97 => { instructions.push(Instruction::Op(OpCode::OpMod)); i += 1; }
            0x98 => { instructions.push(Instruction::Op(OpCode::OpLShift)); i += 1; }
            0x99 => { instructions.push(Instruction::Op(OpCode::OpRShift)); i += 1; }
            0x9a => { instructions.push(Instruction::Op(OpCode::OpBoolAnd)); i += 1; }
            0x9b => { instructions.push(Instruction::Op(OpCode::OpBoolOr)); i += 1; }
            0x9c => { instructions.push(Instruction::Op(OpCode::OpNumEqual)); i += 1; }
            0x9d => { instructions.push(Instruction::Op(OpCode::OpNumEqualVerify)); i += 1; }
            0x9e => { instructions.push(Instruction::Op(OpCode::OpNumNotEqual)); i += 1; }
            0x9f => { instructions.push(Instruction::Op(OpCode::OpLessThan)); i += 1; }
            0xa0 => { instructions.push(Instruction::Op(OpCode::OpGreaterThan)); i += 1; }
            0xa1 => { instructions.push(Instruction::Op(OpCode::OpLessThanOrEqual)); i += 1; }
            0xa2 => { instructions.push(Instruction::Op(OpCode::OpGreaterThanOrEqual)); i += 1; }
            0xa3 => { instructions.push(Instruction::Op(OpCode::OpMin)); i += 1; }
            0xa4 => { instructions.push(Instruction::Op(OpCode::OpMax)); i += 1; }
            0xa5 => { instructions.push(Instruction::Op(OpCode::OpWithin)); i += 1; }
            0xa6 => { instructions.push(Instruction::Op(OpCode::OpRipemd160)); i += 1; }
            0xa7 => { instructions.push(Instruction::Op(OpCode::OpSha1)); i += 1; }
            0xa8 => { instructions.push(Instruction::Op(OpCode::OpSha256)); i += 1; }
            0xaa => { instructions.push(Instruction::Op(OpCode::OpHash256)); i += 1; }
            0xab => { instructions.push(Instruction::Op(OpCode::OpCodeSeparator)); i += 1; }
            0xad => { instructions.push(Instruction::Op(OpCode::OpCheckSigVerify)); i += 1; }
            0xae => { instructions.push(Instruction::Op(OpCode::OpCheckMultiSig)); i += 1; }
            0xaf => { instructions.push(Instruction::Op(OpCode::OpCheckMultiSigVerify)); i += 1; }
            0xb1 => { instructions.push(Instruction::Op(OpCode::OpCheckLockTimeVerify)); i += 1; }
            0xb2 => { instructions.push(Instruction::Op(OpCode::OpCheckSequenceVerify)); i += 1; }
            0xba => { instructions.push(Instruction::Op(OpCode::OpCheckSigAdd)); i += 1; }
            0xff => { instructions.push(Instruction::Op(OpCode::OpInvalidOpcode)); i += 1; }
        }
    }
    instructions
}

use crate::transaction::Transaction;

pub struct ExecutionContext {
    pub stack: Vec<Vec<u8>>,
    pub alt_stack: Vec<Vec<u8>>,
    pub exec_stack: Vec<bool>,
    
    // Transaction context for signature hashing
    pub tx: Transaction,
    pub input_index: usize,
    pub script_code: Vec<u8>,
}

impl ExecutionContext {
    pub fn new(tx: Transaction, input_index: usize, script_code: Vec<u8>) -> Self {
        ExecutionContext {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            exec_stack: Vec::new(),
            tx,
            input_index,
            script_code,
        }
    }
}

#[cfg(test)]
mod vm_tests {
    use super::*;
    use crate::transaction::{Transaction, TxIn, TxOut};
    use secp256k1::{Secp256k1, SecretKey, Message};
    use sha2::{Sha256, Digest};

    #[test]
    fn test_minimal_p2pkh_execution() {
        // This test proves that the minimal opcodes implemented (DUP, HASH160, EQUALVERIFY, CHECKSIG)
        // are sufficient to fully accept and validate a standard P2PKH transaction script.
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize().to_vec();

        // Compute Hash160 of the public key
        let sha256_hash = Sha256::digest(&pubkey_bytes);
        let pubkey_hash = ripemd::Ripemd160::digest(&sha256_hash).to_vec();

        // Create a dummy transaction
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: [0u8; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: 50_000,
                pk_script: vec![],
            }],
            lock_time: 0,
        };

        // For P2PKH, the script_code that is hashed for SIGHASH is the scriptPubKey without any signatures 
        // We'll construct the raw bytes of the locking script to pass to signature_hash
        // OP_DUP (0x76) OP_HASH160 (0xa9) PUSH20 (0x14) <hash> OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.extend_from_slice(&pubkey_hash);
        script_code.push(0x88);
        script_code.push(0xac);

        let sighash_type = 1u32; // SIGHASH_ALL
        let sighash_bytes = tx.signature_hash(0, &script_code, sighash_type);
        
        let msg = Message::from_digest(sighash_bytes);
        let sig = secp.sign_ecdsa(msg, &secret_key);
        
        let mut sig_der = sig.serialize_der().to_vec();
        sig_der.push(sighash_type as u8); // Append SIGHASH_ALL byte

        // The unlocking script (scriptSig)
        let script_sig_instructions = vec![
            Instruction::PushData(sig_der),
            Instruction::PushData(pubkey_bytes),
        ];

        // The locking script (scriptPubKey)
        let script_pubkey_instructions = parse_script(&script_code);

        // Execute both
        let mut context = ExecutionContext::new(tx, 0, script_code);
        
        context.execute(&script_sig_instructions).expect("ScriptSig failed");
        context.execute(&script_pubkey_instructions).expect("ScriptPubKey failed");

        // The final stack must contain exactly one element, which is non-zero (true)
        assert_eq!(context.stack.len(), 1);
        assert_eq!(context.stack[0], vec![1]);
    }

    #[test]
    fn test_failed_p2pkh_wrong_signature() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes");
        let wrong_secret = SecretKey::from_slice(&[0xef; 32]).expect("32 bytes");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize().to_vec();

        let sha256_hash = Sha256::digest(&pubkey_bytes);
        let pubkey_hash = ripemd::Ripemd160::digest(&sha256_hash).to_vec();

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn { prev_txid: [0u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffffffff }],
            outputs: vec![],
            lock_time: 0,
        };

        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.extend_from_slice(&pubkey_hash);
        script_code.push(0x88);
        script_code.push(0xac);

        let sighash_type = 1u32;
        let sighash_bytes = tx.signature_hash(0, &script_code, sighash_type);
        let msg = Message::from_digest(sighash_bytes);
        
        // SIGN WITH WRONG SECRET
        let sig = secp.sign_ecdsa(msg, &wrong_secret);
        
        let mut sig_der = sig.serialize_der().to_vec();
        sig_der.push(sighash_type as u8);

        let script_sig_instructions = vec![Instruction::PushData(sig_der), Instruction::PushData(pubkey_bytes)];
        let script_pubkey_instructions = parse_script(&script_code);

        let mut context = ExecutionContext::new(tx, 0, script_code);
        
        context.execute(&script_sig_instructions).expect("ScriptSig failed");
        context.execute(&script_pubkey_instructions).expect("ScriptPubKey should not crash, just push false");

        assert_eq!(context.stack.len(), 1);
        assert_eq!(context.stack[0], Vec::<u8>::new()); // OP_CHECKSIG pushes empty vec on failure
    }
}

impl ExecutionContext {
    pub fn execute(&mut self, instructions: &[Instruction]) -> Result<(), String> {
        for inst in instructions {
            match inst {
                Instruction::Op(op) => op.execute(self)?,
                Instruction::PushData(data) => self.stack.push(data.clone()),
            }
        }
        Ok(())
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_constants() {
        let script = vec![0x00, 0x4f, 0x51, 0x60];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 4);
        assert_eq!(inst[0], Instruction::Op(OpCode::Op0));
        assert_eq!(inst[1], Instruction::Op(OpCode::Op1Negate));
        assert_eq!(inst[2], Instruction::Op(OpCode::OpPushNum(1)));
        assert_eq!(inst[3], Instruction::Op(OpCode::OpPushNum(16)));
    }

    #[test]
    fn test_parse_push_bytes() {
        // OP_PUSHBYTES_3 (0x03) followed by 3 bytes
        let script = vec![0x03, 0xaa, 0xbb, 0xcc];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0], Instruction::PushData(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn test_parse_push_bytes_out_of_bounds() {
        // OP_PUSHBYTES_5 (0x05) but only 3 bytes provided
        let script = vec![0x05, 0xaa, 0xbb, 0xcc];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0], Instruction::Op(OpCode::OpInvalidOpcode));
    }

    #[test]
    fn test_parse_pushdata1() {
        // OP_PUSHDATA1 (0x4c), length is 1 byte (0x02), then 2 bytes data
        let script = vec![0x4c, 0x02, 0x11, 0x22];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0], Instruction::PushData(vec![0x11, 0x22]));
    }

    #[test]
    fn test_parse_pushdata2() {
        // OP_PUSHDATA2 (0x4d), length is 2 bytes (0x02 0x00 -> 2), then 2 bytes data
        let script = vec![0x4d, 0x02, 0x00, 0xaa, 0xbb];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0], Instruction::PushData(vec![0xaa, 0xbb]));
    }

    #[test]
    fn test_parse_pushdata4() {
        // OP_PUSHDATA4 (0x4e), length is 4 bytes (0x02 0x00 0x00 0x00 -> 2), then 2 bytes data
        let script = vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0x99, 0x88];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0], Instruction::PushData(vec![0x99, 0x88]));
    }

    #[test]
    fn test_parse_control_and_logic() {
        let script = vec![0x63, 0x68, 0x69, 0x6a];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 4);
        assert_eq!(inst[0], Instruction::Op(OpCode::OpIf));
        assert_eq!(inst[1], Instruction::Op(OpCode::OpEndIf));
        assert_eq!(inst[2], Instruction::Op(OpCode::OpVerify));
        assert_eq!(inst[3], Instruction::Op(OpCode::OpReturn));
    }

    #[test]
    fn test_parse_nops_and_success() {
        let script = vec![0x61, 0xb0, 0xb3, 0xbb, 0xfe];
        let inst = parse_script(&script);
        assert_eq!(inst.len(), 5);
        assert_eq!(inst[0], Instruction::Op(OpCode::OpNop));
        assert_eq!(inst[1], Instruction::Op(OpCode::OpNopFuture(0xb0)));
        assert_eq!(inst[2], Instruction::Op(OpCode::OpNopFuture(0xb3)));
        assert_eq!(inst[3], Instruction::Op(OpCode::OpReturnSuccess(0xbb)));
        assert_eq!(inst[4], Instruction::Op(OpCode::OpReturnSuccess(0xfe)));
    }

    #[test]
    fn test_parse_standard_p2pkh() {
        // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        let hash = vec![0xab; 20];
        script.extend(&hash);
        script.push(0x88);
        script.push(0xac);

        let inst = parse_script(&script);
        assert_eq!(inst.len(), 5);
        assert_eq!(inst[0], Instruction::Op(OpCode::OpDup));
        assert_eq!(inst[1], Instruction::Op(OpCode::OpHash160));
        assert_eq!(inst[2], Instruction::PushData(hash));
        assert_eq!(inst[3], Instruction::Op(OpCode::OpEqualVerify));
        assert_eq!(inst[4], Instruction::Op(OpCode::OpCheckSig));
    }
}
