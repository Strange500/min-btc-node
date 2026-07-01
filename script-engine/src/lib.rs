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
            
            // Temporary fallback for mapped opcodes we haven't explicitely added to match yet
            _ => {
                // For now, if we don't have it matched, just push invalid opcode
                // (In the full version, we will match byte to the specific enum variant)
                instructions.push(Instruction::Op(OpCode::OpInvalidOpcode));
                i += 1;
            }
        }
    }
    instructions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_script_op_0() {
        // OP_0 OP_PUSHBYTES_1 0x42 OP_5
        let script = vec![0x00, 0x01, 0x42, 0x55];
        let instructions = parse_script(&script);
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0], Instruction::Op(OpCode::Op0));
        assert_eq!(instructions[1], Instruction::PushData(vec![0x42]));
        assert_eq!(instructions[2], Instruction::Op(OpCode::OpPushNum(5)));
    }
}
