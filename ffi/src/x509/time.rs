#[diplomat::bridge]
pub mod ffi {

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct UTCTime(pub picky_asn1::date::UTCTime);

    impl UTCTime {
        #[diplomat::attr(auto, getter = "year")]
        pub fn get_year(&self) -> u16 {
            self.0.year()
        }

        #[diplomat::attr(auto, getter = "month")]
        pub fn get_month(&self) -> u8 {
            self.0.month()
        }

        #[diplomat::attr(auto, getter = "day")]
        pub fn get_day(&self) -> u8 {
            self.0.day()
        }

        #[diplomat::attr(auto, getter = "hour")]
        pub fn get_hour(&self) -> u8 {
            self.0.hour()
        }

        #[diplomat::attr(auto, getter = "minute")]
        pub fn get_minute(&self) -> u8 {
            self.0.minute()
        }

        #[diplomat::attr(auto, getter = "second")]
        pub fn get_second(&self) -> u8 {
            self.0.second()
        }
    }

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct UTCTimeIterator(pub Vec<UTCTime>);

    impl UTCTimeIterator {
        pub fn next(&mut self) -> Option<Box<UTCTime>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct Time(pub picky_asn1_x509::validity::Time);

    impl Time {
        #[diplomat::attr(auto, getter = "year")]
        pub fn get_year(&self) -> u16 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.year(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.year(),
            }
        }

        #[diplomat::attr(auto, getter = "month")]
        pub fn get_month(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.month(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.month(),
            }
        }

        #[diplomat::attr(auto, getter = "day")]
        pub fn get_day(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.day(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.day(),
            }
        }

        #[diplomat::attr(auto, getter = "hour")]
        pub fn get_hour(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.hour(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.hour(),
            }
        }

        #[diplomat::attr(auto, getter = "minute")]
        pub fn get_minute(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.minute(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.minute(),
            }
        }

        #[diplomat::attr(auto, getter = "second")]
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
