use crate::x509::private::validity::Time;
#[cfg(feature = "chrono_conversion")]
use chrono::{DateTime, Utc};
use picky_asn1::date::{Date, GeneralizedTime, UTCTime, UTCTimeRepr};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UTCDate(GeneralizedTime);

impl UTCDate {
    #[inline]
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
        Some(Self(GeneralizedTime::new(year, month, day, hour, minute, second)?))
    }

    #[inline]
    pub fn ymd(year: u16, month: u8, day: u8) -> Option<Self> {
        Some(Self(GeneralizedTime::new(year, month, day, 0, 0, 0)?))
    }

    #[cfg(feature = "chrono_conversion")]
    #[inline]
    pub fn now() -> Self {
        Self(chrono::offset::Utc::now().into())
    }

    #[inline]
    pub fn year(&self) -> u16 {
        self.0.year()
    }

    #[inline]
    pub fn month(&self) -> u8 {
        self.0.month()
    }

    #[inline]
    pub fn day(&self) -> u8 {
        self.0.day()
    }

    #[inline]
    pub fn hour(&self) -> u8 {
        self.0.hour()
    }

    #[inline]
    pub fn minute(&self) -> u8 {
        self.0.minute()
    }

    #[inline]
    pub fn second(&self) -> u8 {
        self.0.second()
    }
}

impl Into<UTCTime> for UTCDate {
    fn into(self) -> UTCTime {
        unsafe {
            UTCTime::new_unchecked(
                self.0.year(),
                self.0.month(),
                self.0.day(),
                self.0.hour(),
                self.0.minute(),
                self.0.second(),
            )
        }
    }
}

impl From<UTCTime> for UTCDate {
    fn from(date: Date<UTCTimeRepr>) -> Self {
        Self(unsafe {
            GeneralizedTime::new_unchecked(
                date.year(),
                date.month(),
                date.day(),
                date.hour(),
                date.minute(),
                date.second(),
            )
        })
    }
}

impl Into<GeneralizedTime> for UTCDate {
    fn into(self) -> GeneralizedTime {
        self.0
    }
}

impl From<GeneralizedTime> for UTCDate {
    fn from(date: GeneralizedTime) -> Self {
        Self(date)
    }
}

impl From<UTCDate> for Time {
    fn from(date: UTCDate) -> Self {
        Self::Generalized(date.0.into())
    }
}

impl From<Time> for UTCDate {
    fn from(time: Time) -> Self {
        match time {
            Time::UTC(utc) => utc.0.into(),
            Time::Generalized(gen_time) => gen_time.0.into(),
        }
    }
}

#[cfg(feature = "chrono_conversion")]
impl From<DateTime<Utc>> for UTCDate {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt.into())
    }
}

#[cfg(feature = "chrono_conversion")]
impl From<UTCDate> for DateTime<Utc> {
    fn from(date: UTCDate) -> Self {
        date.0.into()
    }
}

impl fmt::Display for UTCDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year(),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            self.second()
        )
    }
}
