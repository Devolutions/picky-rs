use serde::{de, ser};
use serde_asn1_der::{
    asn1_wrapper::{Asn1Wrapper, GeneralizedTimeAsn1, UTCTimeAsn1},
    date::{GeneralizedTime, UTCTime},
    tag_peeker::TagPeeker,
};
use std::fmt;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Time {
    UTC(UTCTimeAsn1),
    Generalized(GeneralizedTimeAsn1),
}

impl From<UTCTimeAsn1> for Time {
    fn from(time: UTCTimeAsn1) -> Self {
        Self::UTC(time)
    }
}

impl From<UTCTime> for Time {
    fn from(time: UTCTime) -> Self {
        Self::UTC(time.into())
    }
}

impl From<GeneralizedTimeAsn1> for Time {
    fn from(time: GeneralizedTimeAsn1) -> Self {
        Self::Generalized(time)
    }
}

impl From<GeneralizedTime> for Time {
    fn from(time: GeneralizedTime) -> Self {
        Self::Generalized(time.into())
    }
}

impl ser::Serialize for Time {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            Time::UTC(time) => time.serialize(serializer),
            Time::Generalized(time) => time.serialize(serializer),
        }
    }
}

impl<'de> de::Deserialize<'de> for Time {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Time;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded Time")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // cannot panic with DER deserializer
                match seq.next_element::<TagPeeker>()?.unwrap().next_tag {
                    UTCTimeAsn1::TAG => Ok(Time::UTC(seq.next_element()?.unwrap())),
                    GeneralizedTimeAsn1::TAG => Ok(Time::Generalized(seq.next_element()?.unwrap())),
                    _ => Err(de::Error::invalid_value(
                        de::Unexpected::Other("[Time] invalid variant"),
                        &"either UTCTime or GeneralizedTime",
                    )),
                }
            }
        }

        deserializer.deserialize_enum("Time", &["UTC", "Generalized"], Visitor)
    }
}
