#[cfg(feature = "chrono_conversion")]
use chrono::{DateTime, Utc};
use picky_asn1::date::{Date, GeneralizedTime, UTCTime, UTCTimeRepr};
use picky_asn1_x509::validity::Time;
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

impl From<UTCDate> for UTCTime {
    fn from(date: UTCDate) -> Self {
        unsafe {
            UTCTime::new_unchecked(
                date.0.year(),
                date.0.month(),
                date.0.day(),
                date.0.hour(),
                date.0.minute(),
                date.0.second(),
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

impl From<UTCDate> for GeneralizedTime {
    fn from(date: UTCDate) -> GeneralizedTime {
        date.0
    }
}

impl From<GeneralizedTime> for UTCDate {
    fn from(date: GeneralizedTime) -> Self {
        Self(date)
    }
}

impl From<UTCDate> for Time {
    fn from(date: UTCDate) -> Self {
        // Time is used to encode validity period.
        // As per RFC 5280,
        // > CAs conforming to this profile MUST always encode certificate
        // > validity dates through the year 2049 as UTCTime; certificate validity
        // > dates in 2050 or later MUST be encoded as GeneralizedTime.
        // > Conforming applications MUST be able to process validity dates that
        // > are encoded in either UTCTime or GeneralizedTime.
        if date.year() >= 2050 {
            Self::Generalized(Into::<GeneralizedTime>::into(date).into())
        } else {
            Self::Utc(Into::<UTCTime>::into(date).into())
        }
    }
}

impl From<Time> for UTCDate {
    fn from(time: Time) -> Self {
        match time {
            Time::Utc(utc) => utc.0.into(),
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
