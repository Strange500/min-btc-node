use std::io::{self, Read, Write};

#[allow(dead_code)]
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

#[allow(dead_code)]
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
