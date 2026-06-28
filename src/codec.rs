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
