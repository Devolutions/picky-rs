//! This module implements PKCS#12 specification defined in [RFC7292](https://tools.ietf.org/html/rfc7292).
//!
//! Direct ASN.1 type wrappers interaction is hidden inside serialiation/deserialization logic where
//! it is possible and makes sense. For example `SEQUENCE` is represented as `Vec<T>` in struct
//! definition. However, most basic types such as `OCETET STRING` or `BMPString` are represented by
//! their own distinctive types to avoid confusion.
//!
//! Structures defined in this module are were built in such way that allows maximum backwards and
//! forwards compatibility with other PKCS#12 implementations by wrapping unknown variants and
//! algorithms inside raw ASN1 types. For example, if the client code knows about specific
//! PKCS12 attribute, it always could be accessed via matching on attribute OID and raw ASN1
//! attribute value.
//!
//! `SafeBag` contents are presented as `OCTET STRING` or `Asb1RawDer` to allow more flexibility
//! when reading/writing PFX contents. For example, even if some specific `PrivateKeyInfo` or
//! `Certificate` is not supported by `picky` directly, they still could be read/written as raw
//! data. See tests in this file for full unencrypted PFX file contents parsing.
//!
//! Instead of using more general `AlgorithmIdentifier` and `ContentInfo` types defined in this
//! crate, this module defined pkcs12-specific wrappers with more usable interface, while providing
//! access to raw ASN1 types when needed (not supported structure variant).
//!
//! Parsing code is tested against PFX files generated by `OpenSSL` and `certmgr`
use core::fmt;
use serde::{de, ser};

mod attribute;
mod authenticated_safe;
mod digest;
pub(crate) mod encryption;
mod mac_data;
mod safe_bag;
mod safe_contents;

pub use attribute::*;
pub use authenticated_safe::*;
pub use digest::*;
pub use encryption::*;
pub use mac_data::*;
pub use safe_bag::*;
pub use safe_contents::*;

/// Top-level structure defined as `PFX` ASN.1 type in
/// [PKCS#12](https://tools.ietf.org/html/rfc7292#section-4.1)
///
/// This structure could be directly used to parse content of PFX files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfx {
    pub version: u8,
    pub auth_safe: AuthenticatedSafeContentInfo,
    pub mac_data: Option<MacData>,
}

impl ser::Serialize for Pfx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;

        let sequence_len = 2 + self.mac_data.is_some() as usize;

        let mut seq = serializer.serialize_seq(Some(sequence_len))?;

        seq.serialize_element(&self.version)?;
        seq.serialize_element(&self.auth_safe)?;

        if let Some(mac_data) = &self.mac_data {
            seq.serialize_element(mac_data)?;
        }

        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for Pfx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct PfxVisitor;

        impl<'de> de::Visitor<'de> for PfxVisitor {
            type Value = Pfx;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a valid DER-encoded AuthenticatedSafeContentInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let version: u8 = seq_next_element!(seq, Pfx, "PFX version");

                if version != 3 {
                    return Err(serde_invalid_value!(Pfx, "PFX version must be 3", "valid PFX version"));
                }

                let auth_safe: AuthenticatedSafeContentInfo = seq_next_element!(seq, Pfx, "PFX authSafe");

                let mac_data: Option<MacData> = seq.next_element()?;

                Ok(Pfx {
                    version,
                    auth_safe,
                    mac_data,
                })
            }
        }

        deserializer.deserialize_seq(PfxVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Certificate, PrivateKeyInfo};
    use expect_test::expect_file;

    #[test]
    fn pfx_openssl_nocrypt_roundtrip() {
        // This test validates PFX structure parsing and parsing of `Certificate`/`PrivateKeyInfo`
        // structures encapsulated inside PFX

        let encoded = include_bytes!("../../test_assets/pkcs12/openssl_nocrypt.pfx");
        let decoded: Pfx = picky_asn1_der::from_bytes(encoded).unwrap();

        // Validate parsed PFX structure via debug representation
        expect_file!["../../test_assets/pkcs12/openssl_nocrypt.parsed.bin"].assert_debug_eq(&decoded);

        // OpenSSL-generate PFXs will have exactly the same bytes when re-encoded
        let reencoded = picky_asn1_der::to_vec(&decoded).unwrap();
        assert_eq!(encoded, reencoded.as_slice());

        // Check that intenal X509 encapsulated structures could be parsed
        let (certs, key) = if let AuthenticatedSafeContentInfo::Data(safe_contents) = decoded.auth_safe {
            let mut it = safe_contents.into_iter();
            let certs = if let SafeContentsContentInfo::Data(certs) = it.next().unwrap() {
                certs
                    .0
                    .into_iter()
                    .map(|cert| match cert.kind {
                        SafeBagKind::Certificate(CertificateBag::X509(cert)) => cert.0,
                        SafeBagKind::Certificate(_) => {
                            panic!("Unexpected non-X509 certificate type")
                        }
                        _ => panic!("Not expected certificate bag type"),
                    })
                    .collect::<Vec<_>>()
            } else {
                panic!("Expected not encrypted certificates");
            };

            let key = if let SafeContentsContentInfo::Data(keys) = it.next().unwrap() {
                if keys.0.len() != 1 {
                    panic!("Expected only one private key");
                }

                let bag = keys.0.into_iter().next().unwrap();

                if let SafeBagKind::Key(key) = bag.kind {
                    key.0
                } else {
                    panic!("Not expected certificate bag type")
                }
            } else {
                panic!("Expected not encrypted private key safe contents")
            };

            assert!(it.next().is_none());

            (certs, key)
        } else {
            panic!("Expected raw AuthenticatedSafeContentInfo data");
        };

        if certs.len() != 3 {
            panic!("Expected 3 certificates");
        }

        for cert in certs {
            let _cert: Certificate =
                picky_asn1_der::from_bytes(&cert).expect("Failed to parse X509 certificate from PFX");
        }

        let _key: PrivateKeyInfo = picky_asn1_der::from_bytes(&key).expect("Failed to parse private key from PFX");
    }

    #[test]
    fn pfx_openssl_rc2_roundtrip() {
        let encoded = include_bytes!("../../test_assets/pkcs12/leaf_password_is_abc.pfx");
        let decoded: Pfx = picky_asn1_der::from_bytes(encoded).unwrap();
        // Validate parsed PFX structure via debug representation
        expect_file!["../../test_assets/pkcs12/leaf_password_is_abc.parsed.txt"].assert_debug_eq(&decoded);
        // OpenSSL-generate PFXs will have exactly the same bytes when re-encoded
        let reencoded = picky_asn1_der::to_vec(&decoded).unwrap();
        assert_eq!(encoded, reencoded.as_slice());
    }

    #[test]
    fn pfx_certmgr_aes256_roundtrip() {
        let encoded = include_bytes!("../../test_assets/pkcs12/certmgr_aes256.pfx");
        let decoded: Pfx = picky_asn1_der::from_bytes(encoded).unwrap();
        expect_file!["../../test_assets/pkcs12/certmgr_aes256.parsed.txt"].assert_debug_eq(&decoded);
        // For certmgr-generated PFXs, we can't compare the bytes directly because
        // certmgr omits serialization of NULL params of DigestAlgorithm, but we always serialize
        // them. (However certmgr will accept the PFX we generate as we serialize it the same way
        // as OpenSSL does.)
    }

    #[test]
    fn pfx_certmgr_3des_roundtrip() {
        let encoded = include_bytes!("../../test_assets/pkcs12/certmgr_3des.pfx");
        let decoded: Pfx = picky_asn1_der::from_bytes(encoded).unwrap();

        expect_file!["../../test_assets/pkcs12/certmgr_3des.parsed.txt"].assert_debug_eq(&decoded);
    }
}

#[cfg(test)]
pub(crate) mod test_data {
    use crate::{oids, RawAlgorithmIdentifier};
    use picky_asn1_der::Asn1RawDer;

    pub fn build_arbitrary_algorithm_identifier() -> RawAlgorithmIdentifier {
        RawAlgorithmIdentifier::from_parts(
            oids::unknown_reserved_prop_id_126(),           // Just some nonsense random OID
            Some(Asn1RawDer(vec![0x02, 0x02, 0x07, 0xD0])), // 2000 as IntegerAsn1
        )
    }
}
