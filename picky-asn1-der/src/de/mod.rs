mod boolean;
mod integer;
mod null;
mod sequence;
mod utf8_string;

use crate::{
    de::{boolean::Boolean, integer::UnsignedInteger, null::Null, sequence::Sequence, utf8_string::Utf8String},
    misc::{Length, PeekableReader, ReadExt},
    Asn1DerError, Result,
};
use picky_asn1::{tag::Tag, wrapper::*, Asn1Type};
use serde::{de::Visitor, Deserialize};
use std::io::{Cursor, Read};

/// Deserializes `T` from `bytes`
pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    debug_log!("deserialization using `from_bytes`");
    let mut deserializer = Deserializer::new_from_bytes(bytes);
    T::deserialize(&mut deserializer)
}

/// Deserializes `T` from `reader`
pub fn from_reader<'a, T: Deserialize<'a>>(reader: impl Read + 'a) -> Result<T> {
    debug_log!("deserialization using `from_reader`");
    let mut deserializer = Deserializer::new_from_reader(reader);
    T::deserialize(&mut deserializer)
}

/// An ASN.1-DER deserializer for `serde`
pub struct Deserializer<'de> {
    reader: PeekableReader<Box<dyn Read + 'de>>,
    buf: Vec<u8>,
    encapsulator_tag_stack: Vec<Tag>,
    header_only: bool,
}

impl<'de> Deserializer<'de> {
    /// Creates a new deserializer over `bytes`
    pub fn new_from_bytes(bytes: &'de [u8]) -> Self {
        Self::new_from_reader(Cursor::new(bytes))
    }
    /// Creates a new deserializer for `reader`
    pub fn new_from_reader(reader: impl Read + 'de) -> Self {
        Self {
            reader: PeekableReader::new(Box::new(reader)),
            buf: Vec::new(),
            encapsulator_tag_stack: Vec::with_capacity(3),
            header_only: false,
        }
    }

    /// Reads tag and length of the next DER object
    fn h_next_tag_len(&mut self) -> Result<(Tag, usize)> {
        // Read type and length
        let tag = Tag::from(self.reader.read_one()?);
        let len = Length::deserialized(&mut self.reader)?;
        Ok((tag, len))
    }

    /// Reads the next DER object into `self.buf` and returns the tag
    fn h_next_object(&mut self) -> Result<Tag> {
        let (tag, len) = if let Some((tag, len)) = self.h_decapsulate()? {
            if tag.is_context_specific() {
                (tag, len)
            } else {
                let tag = Tag::from(self.reader.read_one()?);
                let len = Length::deserialized(&mut self.reader)?;
                (tag, len)
            }
        } else {
            let tag = Tag::from(self.reader.read_one()?);
            let len = Length::deserialized(&mut self.reader)?;
            (tag, len)
        };

        self.buf.resize(len, 0);
        self.reader.read_exact(&mut self.buf)?;

        Ok(tag)
    }

    /// Peek next DER object tag (ignoring encapsulator)
    fn h_peek_object(&mut self) -> Result<Tag> {
        if self.encapsulator_tag_stack.is_empty() {
            Ok(Tag::from(self.reader.peek_one()?))
        } else {
            let peeked = self.reader.peek_buffer()?;
            let mut cursor = 0;
            for encapsulator_tag in self
                .encapsulator_tag_stack
                .iter()
                .filter(|tag| !tag.is_context_specific())
            {
                let encapsulator_tag = *encapsulator_tag;

                if peeked.len() < cursor + 2 {
                    debug_log!("peek_object: TRUNCATED DATA (couldn't read encapsulator tag or length)");
                    return Err(Asn1DerError::TruncatedData);
                }

                // check tag
                if peeked.buffer()[cursor] != encapsulator_tag.number() {
                    debug_log!(
                        "peek_object: INVALID (found {}, expected encapsulator tag {})",
                        Tag::from(peeked.buffer()[cursor]),
                        encapsulator_tag
                    );
                    self.encapsulator_tag_stack.clear();
                    return Err(Asn1DerError::InvalidData);
                }

                let length = {
                    let len = Length::deserialized(&mut Cursor::new(&peeked.buffer()[cursor + 1..]))?;
                    Length::encoded_len(len)
                };

                cursor = if encapsulator_tag == BitStringAsn1Container::<()>::TAG {
                    cursor + length + 2
                } else {
                    cursor + length + 1
                };
            }

            if peeked.len() < cursor {
                debug_log!("peek_object: TRUNCATED DATA (couldn't read object tag)");
                return Err(Asn1DerError::TruncatedData);
            }

            Ok(Tag::from(peeked.buffer()[cursor]))
        }
    }

    fn h_encapsulate(&mut self, tag: Tag) {
        debug_log!("> encapsulator ({})", tag);
        self.encapsulator_tag_stack.push(tag);
    }

    fn h_decapsulate(&mut self) -> Result<Option<(Tag, usize)>> {
        if self.encapsulator_tag_stack.is_empty() {
            Ok(None)
        } else {
            let mut tag = Tag::NULL;
            let mut len = 0;
            for encapsulator_tag in &self.encapsulator_tag_stack {
                let encapsulator_tag = *encapsulator_tag;

                tag = Tag::from(self.reader.peek_one()?);
                if tag == encapsulator_tag {
                    self.reader.read_one()?; // discard it
                } else {
                    debug_log!(
                        "decapsulate: INVALID (found {}, expected encapsulator tag {})",
                        tag,
                        encapsulator_tag
                    );
                    return Err(Asn1DerError::InvalidData);
                }

                len = Length::deserialized(&mut self.reader)?;

                if encapsulator_tag == Tag::BIT_STRING {
                    self.reader.read_one()?; // unused bits count
                }
            }

            self.encapsulator_tag_stack.clear();
            Ok(Some((tag, len)))
        }
    }
}

impl<'de, 'a> serde::de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Asn1DerError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_any");
        match self.h_peek_object()? {
            Tag::BOOLEAN => self.deserialize_bool(visitor),
            Tag::INTEGER => {
                debug_log!("deserialize_any: can't be used on INTEGER");
                Err(Asn1DerError::InvalidData)
            }
            Tag::NULL => self.deserialize_unit(visitor),
            Tag::OCTET_STRING => self.deserialize_byte_buf(visitor),
            Tag::SEQUENCE => self.deserialize_seq(visitor),
            Tag::UTF8_STRING => self.deserialize_string(visitor),
            Tag::OID => self.deserialize_bytes(visitor),
            Tag::BIT_STRING => self.deserialize_byte_buf(visitor),
            Tag::UTC_TIME => self.deserialize_bytes(visitor),
            Tag::GENERALIZED_TIME => self.deserialize_bytes(visitor),
            Tag::PRINTABLE_STRING => self.deserialize_byte_buf(visitor),
            Tag::NUMERIC_STRING => self.deserialize_byte_buf(visitor),
            Tag::IA5_STRING => self.deserialize_byte_buf(visitor),
            Tag::APP_0 => self.deserialize_newtype_struct(ApplicationTag0::<()>::NAME, visitor),
            Tag::APP_1 => self.deserialize_newtype_struct(ApplicationTag1::<()>::NAME, visitor),
            Tag::APP_2 => self.deserialize_newtype_struct(ApplicationTag2::<()>::NAME, visitor),
            Tag::APP_3 => self.deserialize_newtype_struct(ApplicationTag3::<()>::NAME, visitor),
            Tag::APP_4 => self.deserialize_newtype_struct(ApplicationTag4::<()>::NAME, visitor),
            Tag::APP_5 => self.deserialize_newtype_struct(ApplicationTag5::<()>::NAME, visitor),
            Tag::APP_6 => self.deserialize_newtype_struct(ApplicationTag6::<()>::NAME, visitor),
            Tag::APP_7 => self.deserialize_newtype_struct(ApplicationTag7::<()>::NAME, visitor),
            Tag::APP_8 => self.deserialize_newtype_struct(ApplicationTag8::<()>::NAME, visitor),
            Tag::APP_9 => self.deserialize_newtype_struct(ApplicationTag9::<()>::NAME, visitor),
            Tag::APP_10 => self.deserialize_newtype_struct(ApplicationTag10::<()>::NAME, visitor),
            Tag::APP_11 => self.deserialize_newtype_struct(ApplicationTag11::<()>::NAME, visitor),
            Tag::APP_12 => self.deserialize_newtype_struct(ApplicationTag12::<()>::NAME, visitor),
            Tag::APP_13 => self.deserialize_newtype_struct(ApplicationTag13::<()>::NAME, visitor),
            Tag::APP_14 => self.deserialize_newtype_struct(ApplicationTag14::<()>::NAME, visitor),
            Tag::APP_15 => self.deserialize_newtype_struct(ApplicationTag15::<()>::NAME, visitor),
            Tag::CTX_0 => self.deserialize_newtype_struct(ContextTag0::<()>::NAME, visitor),
            Tag::CTX_1 => self.deserialize_newtype_struct(ContextTag1::<()>::NAME, visitor),
            Tag::CTX_2 => self.deserialize_newtype_struct(ContextTag2::<()>::NAME, visitor),
            Tag::CTX_3 => self.deserialize_newtype_struct(ContextTag3::<()>::NAME, visitor),
            Tag::CTX_4 => self.deserialize_newtype_struct(ContextTag4::<()>::NAME, visitor),
            Tag::CTX_5 => self.deserialize_newtype_struct(ContextTag5::<()>::NAME, visitor),
            Tag::CTX_6 => self.deserialize_newtype_struct(ContextTag6::<()>::NAME, visitor),
            Tag::CTX_7 => self.deserialize_newtype_struct(ContextTag7::<()>::NAME, visitor),
            Tag::CTX_8 => self.deserialize_newtype_struct(ContextTag8::<()>::NAME, visitor),
            Tag::CTX_9 => self.deserialize_newtype_struct(ContextTag9::<()>::NAME, visitor),
            Tag::CTX_10 => self.deserialize_newtype_struct(ContextTag10::<()>::NAME, visitor),
            Tag::CTX_11 => self.deserialize_newtype_struct(ContextTag11::<()>::NAME, visitor),
            Tag::CTX_12 => self.deserialize_newtype_struct(ContextTag12::<()>::NAME, visitor),
            Tag::CTX_13 => self.deserialize_newtype_struct(ContextTag13::<()>::NAME, visitor),
            Tag::CTX_14 => self.deserialize_newtype_struct(ContextTag14::<()>::NAME, visitor),
            Tag::CTX_15 => self.deserialize_newtype_struct(ContextTag15::<()>::NAME, visitor),
            _ => {
                debug_log!("deserialize_any: INVALID");
                Err(Asn1DerError::InvalidData)
            }
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_bool");
        match self.h_peek_object()? {
            Tag::BOOLEAN => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_bool: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_bool(Boolean::deserialize(&self.buf)?)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_i8: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_i16: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_i32: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_i64: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_i128: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_u8");
        match self.h_peek_object()? {
            Tag::INTEGER => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_u8: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_u8(UnsignedInteger::deserialize(&self.buf)?)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_u16");
        match self.h_peek_object()? {
            Tag::INTEGER => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_u16: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_u16(UnsignedInteger::deserialize(&self.buf)?)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_u32");
        match self.h_peek_object()? {
            Tag::INTEGER => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_u32: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_u32(UnsignedInteger::deserialize(&self.buf)?)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_u64");
        match self.h_peek_object()? {
            Tag::INTEGER => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_u64: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_u64(UnsignedInteger::deserialize(&self.buf)?)
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_u128");
        match self.h_peek_object()? {
            Tag::INTEGER => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_u128: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_u128(UnsignedInteger::deserialize(&self.buf)?)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_f32: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_f64: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_char");
        match self.h_peek_object()? {
            Tag::UTF8_STRING => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_char: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }

        self.h_next_object()?;
        let s = Utf8String::deserialize(&self.buf)?;

        let c = s.chars().next().ok_or(Asn1DerError::UnsupportedValue)?;
        visitor.visit_char(c)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_str");
        match self.h_peek_object()? {
            Tag::UTF8_STRING => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_str: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_str(Utf8String::deserialize(&self.buf)?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_string");
        match self.h_peek_object()? {
            Tag::UTF8_STRING => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_string: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_string(Utf8String::deserialize(&self.buf)?.to_string())
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_bytes");
        match self.h_peek_object()? {
            Tag::OCTET_STRING => {}
            Tag::OID => {}
            Tag::BIT_STRING => {}
            Tag::INTEGER => {}
            Tag::UTC_TIME => {}
            Tag::GENERALIZED_TIME => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                if self.header_only {
                    self.header_only = false;
                    self.buf.resize(2, 0);
                    self.reader.read_exact(&mut self.buf)?;
                    return visitor.visit_bytes(&self.buf);
                }

                debug_log!("deserialize_bytes: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }

        self.h_next_object()?;
        visitor.visit_bytes(&self.buf)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_byte_buf");
        match self.h_peek_object()? {
            Tag::OCTET_STRING => {}
            Tag::BIT_STRING => {}
            Tag::INTEGER => {}
            Tag::UTF8_STRING => {}
            Tag::PRINTABLE_STRING => {}
            Tag::NUMERIC_STRING => {}
            Tag::IA5_STRING => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_byte_buf: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        visitor.visit_byte_buf(self.buf.to_vec())
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_option");
        visitor.visit_some(self)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_unit");
        match self.h_peek_object()? {
            Tag::NULL => {}
            tag if tag.is_context_specific() => {}
            _tag => {
                debug_log!("deserialize_unit: INVALID (found {})", _tag);
                return Err(Asn1DerError::InvalidData);
            }
        }
        self.h_next_object()?;
        Null::deserialize(&self.buf)?;
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_unit_struct");
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, name: &'static str, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_newtype_struct: {}", name);
        match name {
            BitStringAsn1Container::<()>::NAME => self.h_encapsulate(Tag::BIT_STRING),
            OctetStringAsn1Container::<()>::NAME => self.h_encapsulate(Tag::OCTET_STRING),
            ApplicationTag0::<()>::NAME => self.h_encapsulate(Tag::APP_0),
            ApplicationTag1::<()>::NAME => self.h_encapsulate(Tag::APP_1),
            ApplicationTag2::<()>::NAME => self.h_encapsulate(Tag::APP_2),
            ApplicationTag3::<()>::NAME => self.h_encapsulate(Tag::APP_3),
            ApplicationTag4::<()>::NAME => self.h_encapsulate(Tag::APP_4),
            ApplicationTag5::<()>::NAME => self.h_encapsulate(Tag::APP_5),
            ApplicationTag6::<()>::NAME => self.h_encapsulate(Tag::APP_6),
            ApplicationTag7::<()>::NAME => self.h_encapsulate(Tag::APP_7),
            ApplicationTag8::<()>::NAME => self.h_encapsulate(Tag::APP_8),
            ApplicationTag9::<()>::NAME => self.h_encapsulate(Tag::APP_9),
            ApplicationTag10::<()>::NAME => self.h_encapsulate(Tag::APP_10),
            ApplicationTag11::<()>::NAME => self.h_encapsulate(Tag::APP_11),
            ApplicationTag12::<()>::NAME => self.h_encapsulate(Tag::APP_12),
            ApplicationTag13::<()>::NAME => self.h_encapsulate(Tag::APP_13),
            ApplicationTag14::<()>::NAME => self.h_encapsulate(Tag::APP_14),
            ApplicationTag15::<()>::NAME => self.h_encapsulate(Tag::APP_15),
            ContextTag0::<()>::NAME => self.h_encapsulate(Tag::CTX_0),
            ContextTag1::<()>::NAME => self.h_encapsulate(Tag::CTX_1),
            ContextTag2::<()>::NAME => self.h_encapsulate(Tag::CTX_2),
            ContextTag3::<()>::NAME => self.h_encapsulate(Tag::CTX_3),
            ContextTag4::<()>::NAME => self.h_encapsulate(Tag::CTX_4),
            ContextTag5::<()>::NAME => self.h_encapsulate(Tag::CTX_5),
            ContextTag6::<()>::NAME => self.h_encapsulate(Tag::CTX_6),
            ContextTag7::<()>::NAME => self.h_encapsulate(Tag::CTX_7),
            ContextTag8::<()>::NAME => self.h_encapsulate(Tag::CTX_8),
            ContextTag9::<()>::NAME => self.h_encapsulate(Tag::CTX_9),
            ContextTag10::<()>::NAME => self.h_encapsulate(Tag::CTX_10),
            ContextTag11::<()>::NAME => self.h_encapsulate(Tag::CTX_11),
            ContextTag12::<()>::NAME => self.h_encapsulate(Tag::CTX_12),
            ContextTag13::<()>::NAME => self.h_encapsulate(Tag::CTX_13),
            ContextTag14::<()>::NAME => self.h_encapsulate(Tag::CTX_14),
            ContextTag15::<()>::NAME => self.h_encapsulate(Tag::CTX_15),
            HeaderOnly::<()>::NAME => self.header_only = true,
            _ => {}
        }

        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_seq");

        self.h_decapsulate()?;

        // Read tag and length
        let (tag, len) = self.h_next_tag_len()?;
        debug_log!("tag: {}, len: {}", tag, len);
        match tag {
            Tag::SEQUENCE => {}
            Asn1SetOf::<()>::TAG => {}
            tag => {
                if !tag.is_context_specific() {
                    debug_log!("deserialize_seq: INVALID (found {})", tag);
                    return Err(Asn1DerError::InvalidData);
                }
            }
        }

        visitor.visit_seq(Sequence::deserialize_lazy(&mut self, len))
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_tuple: {}", _len);
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        debug_log!("deserialize_tuple_struct: {}({})", _name, _len);
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_map: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        debug_log!("deserialize_struct: {}", _name);
        self.deserialize_seq(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        mut self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        debug_log!("deserialize_enum: deserialize sequence as choice");
        let peeked = self.reader.peek_buffer()?;
        if peeked.len() < 2 {
            debug_log!("TRUNCATED DATA (couldn't read length)");
            return Err(Asn1DerError::TruncatedData);
        }
        let payload_len = Length::deserialized(&mut Cursor::new(&peeked.buffer()[1..]))?;
        let len = 1 + payload_len + Length::encoded_len(payload_len);
        visitor.visit_seq(Sequence::deserialize_lazy(&mut self, len))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_identifier: peek next tag id");
        let tag = self.h_peek_object()?;
        debug_log!("next tag id: {}", tag);
        visitor.visit_u8(tag.number())
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        debug_log!("deserialize_ignored_any");

        // Skip tag
        self.reader.read_one()?;

        // Read len and copy payload into `self.buf`
        let len = Length::deserialized(&mut self.reader)?;
        self.buf.resize(len, 0);
        self.reader.read_exact(&mut self.buf)?;

        visitor.visit_unit()
    }
}
