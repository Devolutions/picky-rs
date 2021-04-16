mod boolean;
mod integer;
mod null;
mod sequence;
mod utf8_string;

use crate::misc::{Length, WriteExt};
use crate::ser::boolean::Boolean;
use crate::ser::integer::UnsignedInteger;
use crate::ser::null::Null;
use crate::ser::sequence::Sequence;
use crate::ser::utf8_string::Utf8String;
use crate::{Asn1DerError, Asn1RawDer, Result};
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::*;
use picky_asn1::Asn1Type;
use serde::Serialize;
use std::io::{Cursor, Write};

/// Serializes `value`
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    to_byte_buf(value, &mut buf)?;
    Ok(buf)
}

/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_bytes<T: ?Sized + Serialize>(value: &T, buf: &mut [u8]) -> Result<usize> {
    debug_log!("serialization using `to_bytes`");
    let mut serializer = Serializer::new_to_bytes(buf);
    value.serialize(&mut serializer)
}

/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_byte_buf<T: ?Sized + Serialize>(value: &T, buf: &mut Vec<u8>) -> Result<usize> {
    debug_log!("serialization using `to_byte_buf`");
    let mut serializer = Serializer::new_to_byte_buf(buf);
    value.serialize(&mut serializer)
}

/// Serializes `value` to `writer` and returns the amount of serialized bytes
pub fn to_writer<T: ?Sized + Serialize>(value: &T, writer: impl Write) -> Result<usize> {
    debug_log!("serialization using `to_writer`");
    let mut serializer = Serializer::new_to_writer(writer);
    value.serialize(&mut serializer)
}

/// An ASN.1-DER serializer for `serde`
pub struct Serializer<'se> {
    writer: Box<dyn Write + 'se>,
    tag_for_next_bytes: Tag,
    tag_for_next_seq: Tag,
    encapsulators: Vec<Tag>,
    no_header: bool,
}

impl<'se> Serializer<'se> {
    /// Creates a new serializer that writes to `buf`
    pub fn new_to_bytes(buf: &'se mut [u8]) -> Self {
        Self::new_to_writer(Cursor::new(buf))
    }

    /// Creates a new serializer that writes to `buf`
    pub fn new_to_byte_buf(buf: &'se mut Vec<u8>) -> Self {
        Self::new_to_writer(Cursor::new(buf))
    }

    /// Creates a new serializer that writes to `writer`
    pub fn new_to_writer(writer: impl Write + 'se) -> Self {
        Self {
            writer: Box::new(writer),
            tag_for_next_bytes: Tag::OCTET_STRING,
            tag_for_next_seq: Tag::SEQUENCE,
            encapsulators: Vec::with_capacity(3),
            no_header: false,
        }
    }

    fn h_encapsulate(&mut self, tag: Tag) {
        self.encapsulators.push(tag);
    }

    fn h_write_encapsulator(&mut self, payload_len: usize) -> Result<usize> {
        let mut written = 0;

        for (i, encapsulator_tag) in self.encapsulators.iter().copied().enumerate() {
            written += self.writer.write_one(encapsulator_tag.number())?;

            let encapsulated_len = {
                let mut encapsulated_len = payload_len;
                for sub_encapsulator_tag in self.encapsulators.iter().skip(i + 1).copied().rev() {
                    if sub_encapsulator_tag == BitStringAsn1Container::<()>::TAG {
                        encapsulated_len += Length::encoded_len(encapsulated_len + 1) + 1;
                    } else {
                        encapsulated_len += Length::encoded_len(encapsulated_len) + 1;
                    }
                }
                encapsulated_len
            };

            if encapsulator_tag == BitStringAsn1Container::<()>::TAG {
                written += Length::serialize(encapsulated_len + 1, &mut self.writer)?;
                written += self.writer.write_one(0x00)?; // no unused bits
            } else {
                written += Length::serialize(encapsulated_len, &mut self.writer)?;
            }
        }

        self.encapsulators.clear();

        Ok(written)
    }

    fn h_write_header(&mut self, tag: Tag, len: usize) -> Result<usize> {
        let mut written;
        match self.encapsulators.last() {
            Some(last_encapsulator_tag) if last_encapsulator_tag.is_context_specific() => {
                written = self.h_write_encapsulator(len)?;
            }
            _ => {
                if self.no_header {
                    written = self.h_write_encapsulator(len)?;
                } else {
                    written = self.h_write_encapsulator(Length::encoded_len(len) + len + 1)?;
                    written += self.writer.write_one(tag.number())?;
                    written += Length::serialize(len, &mut self.writer)?;
                }
            }
        }
        self.no_header = false; // reset state
        Ok(written)
    }

    fn h_serialize_bytes_with_tag(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut written = self.h_write_header(self.tag_for_next_bytes, bytes.len())?;
        written += self.writer.write_exact(bytes)?;

        self.tag_for_next_bytes = Tag::OCTET_STRING; // reset to octet string

        Ok(written)
    }
}

impl<'a, 'se> serde::ser::Serializer for &'a mut Serializer<'se> {
    type Ok = usize;
    type Error = Asn1DerError;

    type SerializeSeq = Sequence<'a, 'se>;
    type SerializeTuple = Sequence<'a, 'se>;
    type SerializeTupleStruct = Sequence<'a, 'se>;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Sequence<'a, 'se>;
    type SerializeStructVariant = Self;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        debug_log!("serialize_bool: {}", v);
        Boolean::serialize(v, self)
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok> {
        debug_log!("serialize_i8: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok> {
        debug_log!("serialize_i16: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok> {
        debug_log!("serialize_i32: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok> {
        debug_log!("serialize_i64: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_i128(self, _v: i128) -> Result<Self::Ok> {
        debug_log!("serialize_i128: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
        debug_log!("serialize_u8: {}", v);
        self.serialize_u128(v as u128)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
        debug_log!("serialize_u16: {}", v);
        self.serialize_u128(v as u128)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        debug_log!("serialize_u32: {}", v);
        self.serialize_u128(v as u128)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        debug_log!("serialize_u64: {}", v);
        self.serialize_u128(v as u128)
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok> {
        debug_log!("serialize_u128: {}", v);
        UnsignedInteger::serialize(v, self)
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
        debug_log!("serialize_f32: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
        debug_log!("serialize_f64: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok> {
        debug_log!("serialize_char: {}", v);
        let mut buf = [0; 4];
        self.serialize_str(v.encode_utf8(&mut buf))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        debug_log!("serialize_str: {}", v);
        Utf8String::serialize(v, self)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        debug_log!("serialize_bytes");
        self.h_serialize_bytes_with_tag(v)
    }

    fn serialize_none(self) -> Result<Self::Ok> {
        debug_log!("serialize_none");
        Ok(0)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok> {
        debug_log!("serialize_some");
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok> {
        debug_log!("serialize_unit");
        Null::serialize(self)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
        debug_log!("serialize_unit_struct: {}", _name);
        Null::serialize(self)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok> {
        debug_log!("serialize_unit_variant: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(mut self, name: &'static str, value: &T) -> Result<Self::Ok> {
        debug_log!("serialize_newtype_struct: {}", name);

        match name {
            ObjectIdentifierAsn1::NAME => self.tag_for_next_bytes = Tag::OID,
            BitStringAsn1::NAME => self.tag_for_next_bytes = Tag::BIT_STRING,
            IntegerAsn1::NAME => self.tag_for_next_bytes = Tag::INTEGER,
            UTCTimeAsn1::NAME => self.tag_for_next_bytes = Tag::UTC_TIME,
            GeneralizedTimeAsn1::NAME => self.tag_for_next_bytes = Tag::GENERALIZED_TIME,
            Utf8StringAsn1::NAME => self.tag_for_next_bytes = Tag::UTF8_STRING,
            PrintableStringAsn1::NAME => self.tag_for_next_bytes = Tag::PRINTABLE_STRING,
            NumericStringAsn1::NAME => self.tag_for_next_bytes = Tag::NUMERIC_STRING,
            IA5StringAsn1::NAME => self.tag_for_next_bytes = Tag::IA5_STRING,
            Asn1SetOf::<()>::NAME => self.tag_for_next_seq = Tag::SET,
            Asn1SequenceOf::<()>::NAME => self.tag_for_next_seq = Tag::SEQUENCE,
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
            HeaderOnly::<()>::NAME => self.no_header = true,
            Asn1RawDer::NAME => self.no_header = true,
            _ => {}
        }

        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok> {
        debug_log!("serialize_newtype_variant: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        debug_log!("serialize_seq");
        let mut tag = Tag::SEQUENCE;
        std::mem::swap(&mut tag, &mut self.tag_for_next_seq);
        Ok(Sequence::serialize_lazy(self, tag))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        debug_log!("serialize_tuple: {}", len);
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeTupleStruct> {
        debug_log!("serialize_tuple_struct: {}({})", _name, len);
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        debug_log!("serialize_tuple_variant: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        debug_log!("serialize_map: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        debug_log!("serialize_struct: {}", _name);
        self.serialize_seq(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        debug_log!("serialize_struct_variant: UNSUPPORTED");
        Err(Asn1DerError::UnsupportedType)
    }
}

impl<'a, 'se> serde::ser::SerializeTupleVariant for &'a mut Serializer<'se> {
    type Ok = usize;
    type Error = Asn1DerError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
        unimplemented!("The implementation does not support tuple variants")
    }

    fn end(self) -> Result<Self::Ok> {
        unimplemented!("The implementation does not support tuple variants")
    }
}

impl<'a, 'se> serde::ser::SerializeMap for &'a mut Serializer<'se> {
    type Ok = usize;
    type Error = Asn1DerError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, _key: &T) -> Result<()> {
        unimplemented!("The implementation does not support maps")
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
        unimplemented!("The implementation does not support maps")
    }

    fn end(self) -> Result<Self::Ok> {
        unimplemented!("The implementation does not support maps")
    }
}

impl<'a, 'se> serde::ser::SerializeStructVariant for &'a mut Serializer<'se> {
    type Ok = usize;
    type Error = Asn1DerError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, _value: &T) -> Result<()> {
        unimplemented!("The implementation does not support struct variants")
    }

    fn end(self) -> Result<Self::Ok> {
        unimplemented!("The implementation does not support struct variants")
    }
}
