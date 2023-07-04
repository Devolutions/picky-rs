use picky_asn1::restricted_string::{BMPString as Asn1BmpString, Utf8String as Asn1Utf8String};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum Asn1StringConversionError {
    #[error("UTF-8 string can't be encoded into UCS-2 encoding of BMPString. Input: {input}")]
    BmpEncode { input: String },

    #[error("UCS-2 encoded BMPString can't be decoded to UTF-8 string. Input: {input:?}")]
    BmpDecode { input: Asn1BmpString },

    #[error("Data inside ASN.1 UTF-8 string strucutre is not a valid UTF-8 string: {input:?}")]
    Utf8Decode { input: Asn1Utf8String },
}

pub fn utf8_to_bmpstring(value: &str) -> Result<Asn1BmpString, Asn1StringConversionError> {
    // Assume that the input chars are represented by 1 or 2 bytes per code point.
    // If assumption was wrong - extend the capacity of the vector on the go.
    let mut buffer = Vec::with_capacity(value.len());

    ucs2::encode_with(value, |encoded_char| {
        buffer.extend_from_slice(&encoded_char.to_be_bytes());
        Ok(())
    })
    .map_err(|_| Asn1StringConversionError::BmpEncode {
        input: value.to_string(),
    })?;

    Asn1BmpString::new(buffer).map_err(|_| Asn1StringConversionError::BmpEncode {
        input: value.to_string(),
    })
}

pub fn bmpstring_to_utf8(value: &Asn1BmpString) -> Result<String, Asn1StringConversionError> {
    let ucs2_bytes = value.as_bytes();
    // Asn1BmpString is guaranteed to have buffer size divisible by 2 (validated during
    // deserializzation or construction)
    let ucs2_chars = ucs2_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();

    // Buffer should be encough for most of the cases (1-2 bytes per code point)
    let mut str_buffer = Vec::with_capacity(ucs2_bytes.len());

    ucs2::decode_with(&ucs2_chars, |decoded_char| {
        str_buffer.extend_from_slice(decoded_char);
        Ok(())
    })
    .map_err(|_| Asn1StringConversionError::BmpDecode { input: value.clone() })?;

    String::from_utf8(str_buffer).map_err(|_| Asn1StringConversionError::BmpDecode { input: value.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::{expect, Expect};
    use rstest::rstest;

    const EXPECTED_ENCODED_1: Expect = expect![[r#"
        BMP("\0m\0y\0_\0c\0e\0r\0t")
    "#]];
    const EXPECTED_ENCODED_2: Expect = expect![[r#"
        BMP("\u{4}?\u{4}@\u{4}8\u{4}2\u{4}V\u{4}B\0!")
    "#]];
    const EXPECTED_ENCODED_3: Expect = expect![[r#"
        BMP("")
    "#]];

    #[rstest]
    #[case("my_cert", EXPECTED_ENCODED_1)]
    #[case("привіт!", EXPECTED_ENCODED_2)]
    #[case("", EXPECTED_ENCODED_3)]
    fn encoding_roundtrip(#[case] input: &str, #[case] encoded: Expect) {
        let bmp_string = utf8_to_bmpstring(input).unwrap();
        encoded.assert_debug_eq(&bmp_string);
        let decoded: String = bmpstring_to_utf8(&bmp_string).unwrap();
        assert_eq!(decoded, input);
    }
}
