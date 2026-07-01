//! Utilities for encoding and decoding Bitcoin-specific data types.
//!
//! This module provides functions for serializing and deserializing core
//! primitive types used in the Bitcoin network protocol. Currently, it
//! handles the Bitcoin `varint` (variable-length integer) format.

use std::io::{self, Read, Write};

/// Reads a variable-length integer (`varint`) from a byte stream.
///
/// The Bitcoin `varint` format is used to save space when encoding counts
/// or lengths. It uses 1, 3, 5, or 9 bytes depending on the value:
/// - `< 0xFD`: 1 byte (value itself)
/// - `<= 0xFFFF`: 3 bytes (`0xFD` followed by the 2-byte value in little-endian)
/// - `<= 0xFFFFFFFF`: 5 bytes (`0xFE` followed by the 4-byte value in little-endian)
/// - `> 0xFFFFFFFF`: 9 bytes (`0xFF` followed by the 8-byte value in little-endian)
///
/// # Arguments
///
/// * `reader` - Any type that implements `std::io::Read`.
///
/// # Returns
///
/// * `io::Result<u64>` - The decoded `varint` value as a `u64`.
///
/// # Errors
///
/// Returns an `io::Error` if the reader fails to provide enough bytes.
pub fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut first_byte = [0u8; 1];
    reader.read_exact(&mut first_byte)?;
    match first_byte[0] {
        0x00..=0xFC => Ok(first_byte[0] as u64),
        0xFD => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xFE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xFF => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

/// Writes an integer into a byte stream using the Bitcoin `varint` format.
///
/// Encodes the integer to minimize byte usage using the standard Bitcoin
/// variable-length integer rules.
///
/// # Arguments
///
/// * `writer` - Any type that implements `std::io::Write`.
/// * `value` - The `u64` value to encode.
///
/// # Returns
///
/// * `io::Result<()>` - Indicates successful writing.
///
/// # Errors
///
/// Returns an `io::Error` if writing to the underlying stream fails.
pub fn write_varint(writer: &mut impl Write, value: u64) -> io::Result<()> {
    if value < 0xFD {
        writer.write_all(&[value as u8])
    } else if value <= 0xFFFF {
        writer.write_all(&[0xFD])?;
        writer.write_all(&(value as u16).to_le_bytes())
    } else if value <= 0xFFFF_FFFF {
        writer.write_all(&[0xFE])?;
        writer.write_all(&(value as u32).to_le_bytes())
    } else {
        writer.write_all(&[0xFF])?;
        writer.write_all(&value.to_le_bytes())
    }
}

/// Decodes a Base58 string (like a Bitcoin address) into raw bytes.
pub fn decode_base58(s: &str) -> Option<Vec<u8>> {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = vec![0u8; s.len() * 733 / 1000 + 1];
    let mut leading_zeros = 0;
    let mut zeros_done = false;
    for &ch in s.as_bytes() {
        if ch == b'1' && !zeros_done {
            leading_zeros += 1;
            continue;
        }
        zeros_done = true;
        let mut val = alphabet.iter().position(|&c| c == ch)? as u32;
        for byte in result.iter_mut().rev() {
            let num = (*byte as u32) * 58 + val;
            *byte = (num & 0xff) as u8;
            val = num >> 8;
        }
    }
    let start = result.iter().position(|&x| x != 0).unwrap_or(result.len());
    let mut decoded = vec![0u8; leading_zeros];
    decoded.extend_from_slice(&result[start..]);
    Some(decoded)
}

/// Encodes raw bytes into a Base58 string.
pub fn encode_base58(data: &[u8]) -> String {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut zeros = 0;
    while zeros < data.len() && data[zeros] == 0 {
        zeros += 1;
    }
    
    let mut result = Vec::new();
    let mut payload = data.to_vec();
    
    while !payload.is_empty() {
        let mut rem = 0;
        let mut new_payload = Vec::new();
        for &byte in &payload {
            let acc = (rem << 8) | (byte as usize);
            let quo = acc / 58;
            rem = acc % 58;
            if !new_payload.is_empty() || quo != 0 {
                new_payload.push(quo as u8);
            }
        }
        result.push(alphabet[rem]);
        payload = new_payload;
    }
    
    for _ in 0..zeros {
        result.push(alphabet[0]);
    }
    
    result.reverse();
    String::from_utf8(result).unwrap()
}

use sha2::{Sha256, Digest};

/// Encodes a payload into a Base58Check string with a version byte.
pub fn encode_base58check(version: u8, payload: &[u8]) -> String {
    let mut data = vec![version];
    data.extend_from_slice(payload);
    
    let hash1 = Sha256::digest(&data);
    let hash2 = Sha256::digest(&hash1);
    
    data.extend_from_slice(&hash2[0..4]);
    encode_base58(&data)
}

/// Attempts to parse a standard Bitcoin address from a locking script.
pub fn pk_script_to_address(script: &[u8]) -> Option<String> {
    if script.len() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
        Some(encode_base58check(0x00, &script[3..23]))
    } else if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        Some(encode_base58check(0x05, &script[2..22]))
    } else if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        let hash_hex: String = script[2..22].iter().map(|b| format!("{:02x}", b)).collect();
        Some(format!("bc1_p2wpkh_{}", hash_hex))
    } else {
        None
    }
}
