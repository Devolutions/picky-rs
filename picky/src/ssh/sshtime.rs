use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::io;
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait SshTimeEncoder {
    type Error;

    fn ssh_time_encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

pub trait SshTimeDecoder {
    type Error;

    fn ssh_time_decode(&mut self) -> Result<SshTime, Self::Error>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl From<u64> for SshTime {
    fn from(timestamp: u64) -> Self {
        Self(DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(timestamp)))
    }
}

impl From<SshTime> for u64 {
    fn from(time: SshTime) -> u64 {
        time.0.second() as u64
    }
}

impl From<DateTime<Utc>> for SshTime {
    fn from(date: DateTime<Utc>) -> Self {
        Self(date)
    }
}

impl From<SshTime> for DateTime<Utc> {
    fn from(time: SshTime) -> Self {
        time.0
    }
}
impl SshTimeEncoder for SshTime {
    type Error = io::Error;

    fn ssh_time_encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u64::<BigEndian>(self.0.timestamp() as u64)?;
        Ok(())
    }
}

impl<T> SshTimeDecoder for T
where
    T: Read,
{
    type Error = io::Error;

    fn ssh_time_decode(&mut self) -> Result<SshTime, Self::Error> {
        let timestamp = self.read_u64::<BigEndian>()?;
        Ok(SshTime::from(timestamp))
    }
}
