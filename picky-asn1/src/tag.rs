use serde::de;
use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Tag(u8);

impl Tag {
    pub const BOOLEAN: Self = Tag(0x01);
    pub const INTEGER: Self = Tag(0x02);
    pub const BIT_STRING: Self = Tag(0x03);
    pub const OCTET_STRING: Self = Tag(0x04);
    pub const NULL: Self = Tag(0x05);
    pub const OID: Self = Tag(0x06);
    pub const REAL: Self = Tag(0x09);
    pub const UTF8_STRING: Self = Tag(0x0C);
    pub const RELATIVE_OID: Self = Tag(0xD);
    pub const NUMERIC_STRING: Self = Tag(0x12);
    pub const PRINTABLE_STRING: Self = Tag(0x13);
    pub const TELETEX_STRING: Self = Tag(0x14);
    pub const VIDEOTEX_STRING: Self = Tag(0x15);
    pub const IA5_STRING: Self = Tag(0x16);
    pub const BMP_STRING: Self = Tag(0x1E);
    pub const UTC_TIME: Self = Tag(0x17);
    pub const GENERALIZED_TIME: Self = Tag(0x18);
    pub const SEQUENCE: Self = Tag(0x30);
    pub const SET: Self = Tag(0x31);
    pub const APP_0: Self = Tag::application(0);
    pub const APP_1: Self = Tag::application(1);
    pub const APP_2: Self = Tag::application(2);
    pub const APP_3: Self = Tag::application(3);
    pub const APP_4: Self = Tag::application(4);
    pub const APP_5: Self = Tag::application(5);
    pub const APP_6: Self = Tag::application(6);
    pub const APP_7: Self = Tag::application(7);
    pub const APP_8: Self = Tag::application(8);
    pub const APP_9: Self = Tag::application(9);
    pub const APP_10: Self = Tag::application(10);
    pub const APP_11: Self = Tag::application(11);
    pub const APP_12: Self = Tag::application(12);
    pub const APP_13: Self = Tag::application(13);
    pub const APP_14: Self = Tag::application(14);
    pub const APP_15: Self = Tag::application(15);
    pub const CTX_0: Self = Tag::context_specific(0);
    pub const CTX_1: Self = Tag::context_specific(1);
    pub const CTX_2: Self = Tag::context_specific(2);
    pub const CTX_3: Self = Tag::context_specific(3);
    pub const CTX_4: Self = Tag::context_specific(4);
    pub const CTX_5: Self = Tag::context_specific(5);
    pub const CTX_6: Self = Tag::context_specific(6);
    pub const CTX_7: Self = Tag::context_specific(7);
    pub const CTX_8: Self = Tag::context_specific(8);
    pub const CTX_9: Self = Tag::context_specific(9);
    pub const CTX_10: Self = Tag::context_specific(10);
    pub const CTX_11: Self = Tag::context_specific(11);
    pub const CTX_12: Self = Tag::context_specific(12);
    pub const CTX_13: Self = Tag::context_specific(13);
    pub const CTX_14: Self = Tag::context_specific(14);
    pub const CTX_15: Self = Tag::context_specific(15);

    #[inline]
    pub const fn application(number: u8) -> Self {
        Tag(0xA0 | number)
    }

    #[inline]
    pub const fn context_specific(number: u8) -> Self {
        Tag(0x80 | number)
    }

    #[inline]
    pub const fn number(self) -> u8 {
        self.0
    }

    #[inline]
    pub fn is_application(self) -> bool {
        self.0 >= Self::APP_0.0 && self.0 <= Self::APP_15.0
    }

    #[inline]
    pub fn is_context_specific(self) -> bool {
        self.0 >= Self::CTX_0.0 && self.0 <= Self::CTX_15.0
    }
}

impl From<u8> for Tag {
    fn from(tag: u8) -> Self {
        Self(tag)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Tag::BOOLEAN => write!(f, "BOOLEAN"),
            Tag::INTEGER => write!(f, "INTEGER"),
            Tag::BIT_STRING => write!(f, "BIT STRING"),
            Tag::OCTET_STRING => write!(f, "OCTET STRING"),
            Tag::NULL => write!(f, "NULL"),
            Tag::OID => write!(f, "OBJECT IDENTIFIER"),
            Tag::REAL => write!(f, "REAL"),
            Tag::UTF8_STRING => write!(f, "UTF8String"),
            Tag::RELATIVE_OID => write!(f, "RELATIVE-OID"),
            Tag::NUMERIC_STRING => write!(f, "NumericString"),
            Tag::PRINTABLE_STRING => write!(f, "PrintableString"),
            Tag::TELETEX_STRING => write!(f, "TeletexString"),
            Tag::VIDEOTEX_STRING => write!(f, "VideotexString"),
            Tag::IA5_STRING => write!(f, "IA5String"),
            Tag::BMP_STRING => write!(f, "BMPString"),
            Tag::UTC_TIME => write!(f, "UTCTime"),
            Tag::GENERALIZED_TIME => write!(f, "GeneralizedTime"),
            Tag::SEQUENCE => write!(f, "SEQUENCE"),
            Tag::SET => write!(f, "SET"),
            Tag::APP_0 => write!(f, "ApplicationTag0"),
            Tag::APP_1 => write!(f, "ApplicationTag1"),
            Tag::APP_2 => write!(f, "ApplicationTag2"),
            Tag::APP_3 => write!(f, "ApplicationTag3"),
            Tag::APP_4 => write!(f, "ApplicationTag4"),
            Tag::APP_5 => write!(f, "ApplicationTag5"),
            Tag::APP_6 => write!(f, "ApplicationTag6"),
            Tag::APP_7 => write!(f, "ApplicationTag7"),
            Tag::APP_8 => write!(f, "ApplicationTag8"),
            Tag::APP_9 => write!(f, "ApplicationTag9"),
            Tag::APP_10 => write!(f, "ApplicationTag10"),
            Tag::APP_11 => write!(f, "ApplicationTag11"),
            Tag::APP_12 => write!(f, "ApplicationTag12"),
            Tag::APP_13 => write!(f, "ApplicationTag13"),
            Tag::APP_14 => write!(f, "ApplicationTag14"),
            Tag::APP_15 => write!(f, "ApplicationTag15"),
            Tag::CTX_0 => write!(f, "ContextTag0"),
            Tag::CTX_1 => write!(f, "ContextTag1"),
            Tag::CTX_2 => write!(f, "ContextTag2"),
            Tag::CTX_3 => write!(f, "ContextTag3"),
            Tag::CTX_4 => write!(f, "ContextTag4"),
            Tag::CTX_5 => write!(f, "ContextTag5"),
            Tag::CTX_6 => write!(f, "ContextTag6"),
            Tag::CTX_7 => write!(f, "ContextTag7"),
            Tag::CTX_8 => write!(f, "ContextTag8"),
            Tag::CTX_9 => write!(f, "ContextTag9"),
            Tag::CTX_10 => write!(f, "ContextTag10"),
            Tag::CTX_11 => write!(f, "ContextTag11"),
            Tag::CTX_12 => write!(f, "ContextTag12"),
            Tag::CTX_13 => write!(f, "ContextTag13"),
            Tag::CTX_14 => write!(f, "ContextTag14"),
            Tag::CTX_15 => write!(f, "ContextTag15"),
            unknown => write!(f, "UNKNOWN({})", unknown.0),
        }
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tag({}[{}])", self, self.0)
    }
}

/// Used to peek next tag by using `Deserializer::deserialize_identifier`.
///
/// Can be used to implement ASN.1 Choice.
///
/// # Examples
/// ```
/// use serde::de;
/// use picky_asn1::{
///     wrapper::{IntegerAsn1, Utf8StringAsn1},
///     tag::{Tag, TagPeeker},
/// };
/// use std::fmt;
///
/// pub enum MyChoice {
///     Integer(u32),
///     Utf8String(String),
/// }
///
/// impl<'de> de::Deserialize<'de> for MyChoice {
///     fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
///     where
///         D: de::Deserializer<'de>,
///     {
///         struct Visitor;
///
///         impl<'de> de::Visitor<'de> for Visitor {
///             type Value = MyChoice;
///
///             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
///                 formatter.write_str("a valid MyChoice")
///             }
///
///             fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
///             where
///                 A: de::SeqAccess<'de>,
///             {
///                 match seq.next_element::<TagPeeker>()?.unwrap().next_tag {
///                     Tag::INTEGER => {
///                         let value = seq.next_element::<u32>()?.unwrap();
///                         Ok(MyChoice::Integer(value))
///                     }
///                     Tag::UTF8_STRING => {
///                         let value = seq.next_element::<String>()?.unwrap();
///                         Ok(MyChoice::Utf8String(value))
///                     }
///                     _ => Err(de::Error::invalid_value(
///                         de::Unexpected::Other(
///                             "[MyChoice] unsupported or unknown choice value",
///                         ),
///                         &"a supported choice value",
///                     ))
///                 }
///             }
///         }
///
///         deserializer.deserialize_enum("MyChoice", &["Integer", "Utf8String"], Visitor)
///     }
/// }
///
/// let buffer = b"\x0C\x06\xE8\x8B\x97\xE5\xAD\x97";
/// let my_choice: MyChoice = picky_asn1_der::from_bytes(buffer).unwrap();
/// match my_choice {
///     MyChoice::Integer(_) => panic!("wrong variant"),
///     MyChoice::Utf8String(string) => assert_eq!(string, "苗字"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagPeeker {
    pub next_tag: Tag,
}

impl<'de> de::Deserialize<'de> for TagPeeker {
    fn deserialize<D>(deserializer: D) -> Result<TagPeeker, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = TagPeeker;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid ASN.1 tag")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TagPeeker { next_tag: v.into() })
            }
        }

        deserializer.deserialize_identifier(Visitor)
    }
}
