// TODO: support `SshTime` without `chrono` nor `time`
#[cfg(not(any(feature = "chrono_conversion", feature = "time_conversion")))]
compile_error!(
    "Either feature \"chrono_conversion\" or \"time_conversion\" must be enabled when the feature \"ssh\" is set."
);

#[cfg(feature = "time_conversion")]
mod time_conversion {
    use time::OffsetDateTime;

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SshTime(pub(crate) OffsetDateTime);

    impl SshTime {
        pub fn now() -> Self {
            SshTime(OffsetDateTime::now_utc())
        }

        pub fn timestamp(&self) -> i64 {
            self.0.unix_timestamp()
        }
    }

    impl From<SshTime> for OffsetDateTime {
        fn from(time: SshTime) -> Self {
            time.0
        }
    }

    impl From<OffsetDateTime> for SshTime {
        fn from(time: OffsetDateTime) -> Self {
            Self::from(time.unix_timestamp() as u64)
        }
    }

    impl From<SshTime> for u64 {
        fn from(time: SshTime) -> u64 {
            time.0.unix_timestamp() as u64
        }
    }

    impl From<u64> for SshTime {
        fn from(timestamp: u64) -> Self {
            Self(OffsetDateTime::from_unix_timestamp(timestamp as i64).unwrap())
        }
    }
}

#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
mod chrono_conversion {
    use chrono::{DateTime, Utc};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SshTime(pub(crate) DateTime<Utc>);

    impl SshTime {
        pub fn now() -> Self {
            SshTime(DateTime::<Utc>::from(SystemTime::now()))
        }

        pub fn timestamp(&self) -> i64 {
            self.0.timestamp()
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

    impl From<SshTime> for u64 {
        fn from(time: SshTime) -> u64 {
            time.0.timestamp() as u64
        }
    }

    impl From<u64> for SshTime {
        fn from(timestamp: u64) -> Self {
            Self(DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(timestamp)))
        }
    }
}

#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
use chrono::{Datelike, Timelike};
#[cfg(all(feature = "chrono_conversion", not(feature = "time_conversion")))]
pub use chrono_conversion::SshTime;
#[cfg(feature = "time_conversion")]
pub use time_conversion::SshTime;

impl SshTime {
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
