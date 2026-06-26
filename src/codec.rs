use std::io::{self, Read, Write};

#[allow(dead_code)]
pub trait ReadExt: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
    
    fn read_i32_le(&mut self) -> io::Result<i32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }
    
    fn read_u32_le(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
    
    fn read_i64_le(&mut self) -> io::Result<i64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }
    
    fn read_u64_le(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

#[allow(dead_code)]
pub trait WriteExt: Write {
    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        self.write_all(&[val])
    }
    
    fn write_i32_le(&mut self, val: i32) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_u32_le(&mut self, val: u32) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_i64_le(&mut self, val: i64) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
    
    fn write_u64_le(&mut self, val: u64) -> io::Result<()> {
        self.write_all(&val.to_le_bytes())
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

#[allow(dead_code)]
pub fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let first_byte = reader.read_u8()?;
    match first_byte {
        0x00..=0xFC => Ok(first_byte as u64),
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
        writer.write_u8(value as u8)
    } else if value <= 0xFFFF {
        writer.write_u8(0xFD)?;
        writer.write_all(&(value as u16).to_le_bytes())
    } else if value <= 0xFFFF_FFFF {
        writer.write_u8(0xFE)?;
        writer.write_all(&(value as u32).to_le_bytes())
    } else {
        writer.write_u8(0xFF)?;
        writer.write_all(&value.to_le_bytes())
    }
}
