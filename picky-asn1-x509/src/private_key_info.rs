use crate::{oids, AlgorithmIdentifier};
use picky_asn1::wrapper::{IntegerAsn1, OctetStringAsn1Container};
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

/// [Public-Key Cryptography Standards (PKCS) #8](https://tools.ietf.org/html/rfc5208#section-5)
///
/// # Section 5
///
/// Private-key information shall have ASN.1 type PrivateKeyInfo:
///
/// ```not_rust
/// PrivateKeyInfo ::= SEQUENCE {
///      version                   Version,
///      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///      privateKey                PrivateKey,
///      attributes           [0]  IMPLICIT Attributes OPTIONAL }
///
///   Version ::= INTEGER
///
///   PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
///
///   PrivateKey ::= OCTET STRING
///
///   Attributes ::= SET OF Attribute
/// ```
///
/// The fields of type PrivateKeyInfo have the following meanings:
///
/// `version` is the syntax version number, for compatibility with
/// future revisions of this document.  It shall be 0 for this version
/// of the document.
///
/// `privateKeyAlgorithm` identifies the private-key algorithm.  One
/// example of a private-key algorithm is PKCS #1's rsaEncryption.
///
/// `privateKey` is an octet string whose contents are the value of the
/// private key.  The interpretation of the contents is defined in the
/// registration of the private-key algorithm.  For an RSA private
/// key, for example, the contents are a BER encoding of a value of
/// type RSAPrivateKey.
///
/// `attributes` is a set of attributes.  These are the extended
/// information that is encrypted along with the private-key
/// information.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PrivateKeyInfo {
    pub version: u8,
    pub private_key_algorithm: AlgorithmIdentifier,
    pub private_key: PrivateKeyValue,
    //pub attributes
}

impl PrivateKeyInfo {
    pub fn new_rsa_encryption(
        modulus: IntegerAsn1,
        public_exponent: IntegerAsn1,
        private_exponent: IntegerAsn1,
        prime_1: IntegerAsn1,
        prime_2: IntegerAsn1,
        exponent_1: IntegerAsn1,
        exponent_2: IntegerAsn1,
        coefficient: IntegerAsn1,
    ) -> Self {
        let private_key = PrivateKeyValue::RSA(
            RSAPrivateKey {
                version: vec![0].into(),
                modulus: modulus,
                public_exponent: public_exponent,
                private_exponent: private_exponent,
                prime_1: prime_1,
                prime_2: prime_2,
                exponent_1: exponent_1,
                exponent_2: exponent_2,
                coefficient: coefficient,
            }
            .into(),
        );

        Self {
            version: 0,
            private_key_algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            private_key,
        }
    }
}

impl<'de> de::Deserialize<'de> for PrivateKeyInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PrivateKeyInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded PrivateKeyInfo (pkcs8)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let version = seq_next_element!(seq, PrivateKeyInfo, "version");
                if version != 0 {
                    return Err(serde_invalid_value!(
                        PrivateKeyInfo,
                        "unsupported version (valid version number: 0)",
                        "a supported PrivateKeyInfo"
                    ));
                }

                let private_key_algorithm: AlgorithmIdentifier =
                    seq_next_element!(seq, PrivateKeyInfo, "private key algorithm");
                let private_key = if private_key_algorithm.is_a(oids::rsa_encryption()) {
                    PrivateKeyValue::RSA(seq_next_element!(seq, PrivateKeyInfo, "rsa oid"))
                } else {
                    return Err(serde_invalid_value!(
                        PrivateKeyInfo,
                        "unsupported algorithm",
                        "a supported algorithm"
                    ));
                };

                Ok(PrivateKeyInfo {
                    version,
                    private_key_algorithm,
                    private_key,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PrivateKeyValue {
    RSA(OctetStringAsn1Container<RSAPrivateKey>),
}

impl ser::Serialize for PrivateKeyValue {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match self {
            PrivateKeyValue::RSA(rsa) => rsa.serialize(serializer),
        }
    }
}

/// [PKCS #1: RSA Cryptography Specifications Version 2.2](https://tools.ietf.org/html/rfc8017.html#appendix-A.1.2)
///
/// # Section A.1.2
///
/// An RSA private key should be represented with the ASN.1 type RSAPrivateKey:
///
/// ```not_rust
///      RSAPrivateKey ::= SEQUENCE {
///          version           Version,
///          modulus           INTEGER,  -- n
///          publicExponent    INTEGER,  -- e
///          privateExponent   INTEGER,  -- d
///          prime1            INTEGER,  -- p
///          prime2            INTEGER,  -- q
///          exponent1         INTEGER,  -- d mod (p-1)
///          exponent2         INTEGER,  -- d mod (q-1)
///          coefficient       INTEGER,  -- (inverse of q) mod p
///          otherPrimeInfos   OtherPrimeInfos OPTIONAL
///      }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RSAPrivateKey {
    pub version: IntegerAsn1,
    pub modulus: IntegerAsn1,
    pub public_exponent: IntegerAsn1,
    pub private_exponent: IntegerAsn1,
    pub prime_1: IntegerAsn1,
    pub prime_2: IntegerAsn1,
    pub exponent_1: IntegerAsn1,
    pub exponent_2: IntegerAsn1,
    pub coefficient: IntegerAsn1,
}

impl RSAPrivateKey {
    #[deprecated(note = "field is now public")]
    pub fn modulus(&self) -> &IntegerAsn1 {
        &self.modulus
    }

    #[deprecated(note = "field is now public")]
    pub fn public_exponent(&self) -> &IntegerAsn1 {
        &self.public_exponent
    }

    #[deprecated(note = "field is now public")]
    pub fn private_exponent(&self) -> &IntegerAsn1 {
        &self.private_exponent
    }

    #[deprecated(note = "field is now public")]
    pub fn prime_1(&self) -> &IntegerAsn1 {
        &self.prime_1
    }

    #[deprecated(note = "field is now public")]
    pub fn prime_2(&self) -> &IntegerAsn1 {
        &self.prime_2
    }

    #[deprecated(note = "field is now public")]
    pub fn primes(&self) -> (&IntegerAsn1, &IntegerAsn1) {
        (&self.prime_1, &self.prime_2)
    }

    #[deprecated(note = "field is now public")]
    pub fn exponent_1(&self) -> &IntegerAsn1 {
        &self.exponent_1
    }

    #[deprecated(note = "field is now public")]
    pub fn exponent_2(&self) -> &IntegerAsn1 {
        &self.exponent_2
    }

    #[deprecated(note = "field is now public")]
    pub fn exponents(&self) -> (&IntegerAsn1, &IntegerAsn1) {
        (&self.exponent_1, &self.exponent_2)
    }

    #[deprecated(note = "field is now public")]
    pub fn coefficient(&self) -> &IntegerAsn1 {
        &self.coefficient
    }

    #[deprecated(note = "field is now public")]
    pub fn into_public_components(self) -> (IntegerAsn1, IntegerAsn1) {
        (self.modulus, self.public_exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs_8_private_key() {
        let encoded = base64::decode(
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq7BFUpkGp3+LQmlQ\
             Yx2eqzDV+xeG8kx/sQFV18S5JhzGeIJNA72wSeukEPojtqUyX2J0CciPBh7eqclQ\
             2zpAswIDAQABAkAgisq4+zRdrzkwH1ITV1vpytnkO/NiHcnePQiOW0VUybPyHoGM\
             /jf75C5xET7ZQpBe5kx5VHsPZj0CBb3b+wSRAiEA2mPWCBytosIU/ODRfq6EiV04\
             lt6waE7I2uSPqIC20LcCIQDJQYIHQII+3YaPqyhGgqMexuuuGx+lDKD6/Fu/JwPb\
             5QIhAKthiYcYKlL9h8bjDsQhZDUACPasjzdsDEdq8inDyLOFAiEAmCr/tZwA3qeA\
             ZoBzI10DGPIuoKXBd3nk/eBxPkaxlEECIQCNymjsoI7GldtujVnr1qT+3yedLfHK\
             srDVjIT3LsvTqw==",
        )
        .expect("invalid base64");

        let modulus = IntegerAsn1::from(encoded[35..100].to_vec());
        let public_exponent = IntegerAsn1::from(encoded[102..105].to_vec());
        let private_exponent = IntegerAsn1::from(encoded[107..171].to_vec());
        let prime_1 = IntegerAsn1::from(encoded[173..206].to_vec());
        let prime_2 = IntegerAsn1::from(encoded[208..241].to_vec());
        let exponent_1 = IntegerAsn1::from(encoded[243..276].to_vec());
        let exponent_2 = IntegerAsn1::from(encoded[278..311].to_vec());
        let coefficient = IntegerAsn1::from(encoded[313..346].to_vec());

        let private_key = PrivateKeyInfo::new_rsa_encryption(
            modulus,
            public_exponent,
            private_exponent,
            prime_1,
            prime_2,
            exponent_1,
            exponent_2,
            coefficient,
        );
        check_serde!(private_key: PrivateKeyInfo in encoded);
    }
}
