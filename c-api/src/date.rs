#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::DiplomatResult;
    use picky::x509::date;

    /// UTC date and time.
    #[diplomat::opaque]
    pub struct UtcDate(pub date::UtcDate);

    impl UtcDate {
        pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Box<UtcDate>> {
            date::UtcDate::new(year, month, day, hour, minute, second).map(|date| Box::new(Self(date)))
        }

        pub fn ymd(year: u16, month: u8, day: u8) -> Option<Box<UtcDate>> {
            date::UtcDate::ymd(year, month, day).map(|date| Box::new(Self(date)))
        }

        pub fn now() -> Box<UtcDate> {
            Box::new(Self(date::UtcDate::now()))
        }

        pub fn from_timestamp(timestamp: i64) -> DiplomatResult<Box<UtcDate>, Box<PickyError>> {
            let date = err_check!(time::OffsetDateTime::from_unix_timestamp(timestamp));
            let date = Self(date.into());
            Ok(Box::new(date)).into()
        }

        pub fn get_timestamp(&self) -> DiplomatResult<i64, Box<PickyError>> {
            let date = err_check!(time::OffsetDateTime::try_from(self.0.clone()));
            Ok(date.unix_timestamp()).into()
        }

        pub fn get_month(&self) -> u8 {
            self.0.month()
        }

        pub fn get_day(&self) -> u8 {
            self.0.day()
        }

        pub fn get_hour(&self) -> u8 {
            self.0.hour()
        }

        pub fn get_minute(&self) -> u8 {
            self.0.minute()
        }

        pub fn get_second(&self) -> u8 {
            self.0.second()
        }

        pub fn get_year(&self) -> u16 {
            self.0.year()
        }
    }
}
