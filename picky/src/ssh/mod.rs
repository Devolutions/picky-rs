use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod certificate;
pub mod private_key;
#[allow(dead_code)]
#[allow(unused)]
pub mod public_key;

pub trait SshParser {
    type Error;

    fn decode(stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub struct SshTime(pub(crate) DateTime<Utc>);

impl SshTime {
    pub fn now() -> Self {
        SshTime(DateTime::<Utc>::from(SystemTime::now()))
    }

    pub fn year(&self) -> u16 {
        self.0.year() as u16
    }

    pub fn month(&self) -> u8 {
        self.0.month() as u8
    }

    pub fn day(&self) -> u8 {
        self.0.day() as u8
    }

    pub fn hour(&self) -> u8 {
        self.0.hour() as u8
    }

    pub fn minute(&self) -> u8 {
        self.0.minute() as u8
    }

    pub fn second(&self) -> u8 {
        self.0.second() as u8
    }
}

impl SshParser for SshTime {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let timestamp = stream.read_u64::<BigEndian>()?;
        Ok(SshTime(DateTime::<Utc>::from(
            UNIX_EPOCH + Duration::from_secs(timestamp),
        )))
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u64::<BigEndian>(self.0.timestamp() as u64)?;
        Ok(())
    }
}

pub(crate) struct Mpint(pub(crate) Vec<u8>);

impl SshParser for Mpint {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let size = stream.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        stream.read_exact(&mut buffer)?;

        if buffer[0] == 0 {
            buffer.remove(0);
        }

        Ok(Mpint(buffer))
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let size = self.0.len() as u32;
        // If the most significant bit would be set for
        // a positive number, the number MUST be preceded by a zero byte.
        if size > 0 && self.0[0] & 0b10000000 != 0 {
            stream.write_u32::<BigEndian>(size + 1)?;
            stream.write_u8(0)?;
        } else {
            stream.write_u32::<BigEndian>(size)?;
        }
        stream.write_all(&self.0)
    }
}

#[derive(Debug)]
pub(crate) struct SshString(pub(crate) String);

impl SshParser for SshString {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let size = stream.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        stream.read_exact(&mut buffer)?;

        Ok(SshString(String::from_utf8_lossy(&buffer).to_string()))
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let size = self.0.len();
        stream.write_u32::<BigEndian>(size as u32)?;
        stream.write_all(self.0.as_bytes())
    }
}

#[derive(Debug)]
pub(crate) struct ByteArray(pub(crate) Vec<u8>);

impl SshParser for ByteArray {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let size = stream.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        stream.read_exact(&mut buffer)?;

        Ok(ByteArray(buffer))
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let size = self.0.len();
        stream.write_u32::<BigEndian>(size as u32)?;
        stream.write_all(&self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn mpint_decoding() {
        let mpint: Mpint = SshParser::decode(Cursor::new(vec![
            0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7,
        ]))
        .unwrap();
        assert_eq!(mpint.0, vec![0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);

        let mpint: Mpint = SshParser::decode(Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80])).unwrap();
        assert_eq!(mpint.0, vec![0x00, 0x80]);

        let mpint: Mpint = SshParser::decode(Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0xed, 0xcc])).unwrap();
        assert_eq!(mpint.0, vec![0xed, 0xcc]);
    }

    #[test]
    fn mpint_encoding() {
        let mpint = Mpint(vec![0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
        let mut cursor = Cursor::new(Vec::new());
        mpint.encode(&mut cursor).unwrap();

        assert_eq!(
            cursor.into_inner(),
            vec![0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        );

        let mpint = Mpint(vec![0x80]);
        let mut cursor = Cursor::new(Vec::new());
        mpint.encode(&mut cursor).unwrap();

        assert_eq!(cursor.into_inner(), vec![0x00, 0x00, 0x00, 0x01, 0x80]);
    }
}
