#[diplomat::bridge]
pub mod ffi {

    #[diplomat::opaque]
    pub struct UTCTime(pub picky_asn1::date::UTCTime);

    impl UTCTime {
        pub fn get_year(&self) -> u16 {
            self.0.year()
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
    }

    #[diplomat::opaque]
    pub struct UTCTimeIterator(pub Vec<UTCTime>);

    impl UTCTimeIterator {
        pub fn next(&mut self) -> Option<Box<UTCTime>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct Time(pub picky_asn1_x509::validity::Time);

    impl Time {
        pub fn get_year(&self) -> u16 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.year(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.year(),
            }
        }

        pub fn get_month(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.month(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.month(),
            }
        }

        pub fn get_day(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.day(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.day(),
            }
        }

        pub fn get_hour(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.hour(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.hour(),
            }
        }

        pub fn get_minute(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.minute(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.minute(),
            }
        }

        pub fn get_second(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.second(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.second(),
            }
        }

        pub fn is_utc(&self) -> bool {
            matches!(&self.0, picky_asn1_x509::validity::Time::Utc(_))
        }

        pub fn is_generalized(&self) -> bool {
            matches!(&self.0, picky_asn1_x509::validity::Time::Generalized(_))
        }
    }
}
