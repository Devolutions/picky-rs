use picky_asn1::wrapper::{ExplicitContextTag0, Optional};
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Version {
    V1 = 0x00,
    V2 = 0x01,
    V3 = 0x02,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

impl Version {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::V1),
            0x01 => Some(Self::V2),
            0x02 => Some(Self::V3),
            _ => None,
        }
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Version;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "nothing or a valid version number")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Version::from_u8(v).ok_or_else(|| {
                    E::invalid_value(
                        de::Unexpected::Other("unsupported version number"),
                        &"a valid integer representing a supported version number",
                    )
                })
            }
        }

        deserializer.deserialize_u8(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct OptionalVersionTestStruct {
    #[serde(skip_serializing_if = "implicit_app0_version_is_default")]
    version: Optional<ExplicitContextTag0<Version>>,
    other_non_optional_integer: u8,
}

pub fn implicit_app0_version_is_default(version: &Optional<ExplicitContextTag0<Version>>) -> bool {
    version.is_default()
}

#[test]
fn optional_version() {
    let buffer_with_version: [u8; 10] = [0x30, 0x08, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x6E];

    let non_default = OptionalVersionTestStruct {
        version: ExplicitContextTag0(Version::V3).into(),
        other_non_optional_integer: 0x6E,
    };

    check!(non_default: OptionalVersionTestStruct in buffer_with_version);

    let buffer_without_version: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x6E];

    let default = OptionalVersionTestStruct {
        version: ExplicitContextTag0(Version::default()).into(),
        other_non_optional_integer: 0x6E,
    };

    check!(default: OptionalVersionTestStruct in buffer_without_version);
}
