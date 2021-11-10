use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
use chrono::{DateTime, Datelike, Timelike, Utc};
#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::io;
use std::io::{Read, Write};

#[cfg(feature = "time_conversion")]
use time::OffsetDateTime;

pub trait SshTimeEncoder {
    type Error;

    fn ssh_time_encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

pub trait SshTimeDecoder {
    type Error;

    fn ssh_time_decode(&mut self) -> Result<SshTime, Self::Error>;
}

#[cfg(feature = "time_conversion")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SshTime(pub(crate) OffsetDateTime);
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
pub struct SshTime(pub(crate) DateTime<Utc>);

impl SshTime {
    #[cfg(any(feature = "time_conversion", feature = "chrono_conversion"))]
    pub fn now() -> Self {
        #[cfg(feature = "time_conversion")]
        {
            SshTime(OffsetDateTime::now_utc())
        }
        #[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
        {
            SshTime(DateTime::<Utc>::from(SystemTime::now()))
        }
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

    pub fn timestamp(&self) -> i64 {
        #[cfg(feature = "time_conversion")]
        {
            self.0.unix_timestamp()
        }
        #[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
        {
            self.0.timestamp()
        }
    }
}

impl From<u64> for SshTime {
    fn from(timestamp: u64) -> Self {
        #[cfg(feature = "time_conversion")]
        {
            Self(OffsetDateTime::from_unix_timestamp(timestamp as i64).unwrap())
        }
        #[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
        {
            Self(DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(timestamp)))
        }
    }
}

impl From<SshTime> for u64 {
    fn from(time: SshTime) -> u64 {
        #[cfg(feature = "time_conversion")]
        {
            time.0.unix_timestamp() as u64
        }
        #[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
        {
            time.0.timestamp() as u64
        }
    }
}

#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
impl From<DateTime<Utc>> for SshTime {
    fn from(date: DateTime<Utc>) -> Self {
        Self(date)
    }
}

#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
impl From<SshTime> for DateTime<Utc> {
    fn from(time: SshTime) -> Self {
        time.0
    }
}

#[cfg(feature = "time_conversion")]
impl From<SshTime> for OffsetDateTime {
    fn from(time: SshTime) -> Self {
        time.0
    }
}

#[cfg(feature = "time_conversion")]
impl From<OffsetDateTime> for SshTime {
    fn from(time: OffsetDateTime) -> Self {
        Self::from(time.unix_timestamp() as u64)
    }
}

impl SshTimeEncoder for SshTime {
    type Error = io::Error;

    fn ssh_time_encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u64::<BigEndian>(self.timestamp() as u64)?;
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
