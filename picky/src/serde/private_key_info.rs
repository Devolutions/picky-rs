use crate::{oids, serde::AlgorithmIdentifier};
use num_bigint_dig::BigInt;
use picky_asn1::wrapper::{Asn1SequenceOf, IntegerAsn1, OctetStringAsn1Container};
use serde::{de, ser};
use std::fmt;

// Public-Key Cryptography Standards (PKCS) #8:
// https://tools.ietf.org/html/rfc5208#section-5
//
// # Section 5
//
// Private-key information shall have ASN.1 type PrivateKeyInfo:
//
// PrivateKeyInfo ::= SEQUENCE {
//      version                   Version,
//      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//      privateKey                PrivateKey,
//      attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
//   Version ::= INTEGER
//
//   PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
//   PrivateKey ::= OCTET STRING
//
//   Attributes ::= SET OF Attribute
//
// The fields of type PrivateKeyInfo have the following meanings:
//
// version is the syntax version number, for compatibility with
// future revisions of this document.  It shall be 0 for this version
// of the document.
//
// privateKeyAlgorithm identifies the private-key algorithm.  One
// example of a private-key algorithm is PKCS #1's rsaEncryption
// [PKCS#1].
//
// privateKey is an octet string whose contents are the value of the
// private key.  The interpretation of the contents is defined in the
// registration of the private-key algorithm.  For an RSA private
// key, for example, the contents are a BER encoding of a value of
// type RSAPrivateKey.
//
// attributes is a set of attributes.  These are the extended
// information that is encrypted along with the private-key
// information.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PrivateKeyInfo {
    pub version: u8,
    pub private_key_algorithm: AlgorithmIdentifier,
    pub private_key: PrivateKeyValue,
    //pub attributes
}

impl PrivateKeyInfo {
    pub fn new_rsa_encryption(
        modulus: BigInt,
        public_exponent: BigInt,
        private_exponent: BigInt,
        primes: Vec<BigInt>,
    ) -> Self {
        let mut seq = Asn1SequenceOf(vec![
            BigInt::from(0).into(),
            modulus.into(),
            public_exponent.into(),
            private_exponent.into(),
        ]);
        seq.0.extend(primes.into_iter().map(|p| p.into()));
        let private_key = PrivateKeyValue::RSA(RSAPrivateKey(seq).into());

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
                let version = seq.next_element()?.unwrap();
                if version != 0 {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Other(
                            "[PrivateKeyInfo] unsupported version (valid version number: 0)",
                        ),
                        &"a supported PrivateKeyInfo",
                    ));
                }

                let private_key_algorithm: AlgorithmIdentifier = seq.next_element()?.unwrap();

                let private_key = if private_key_algorithm.is_a(oids::rsa_encryption()) {
                    PrivateKeyValue::RSA(seq.next_element()?.unwrap())
                } else {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Other("[PrivateKeyInfo] unsupported algorithm"),
                        &"a PrivateKeyInfo using a supported algorithm",
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
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match self {
            PrivateKeyValue::RSA(rsa) => rsa.serialize(serializer),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RSAPrivateKey(Asn1SequenceOf<IntegerAsn1>);

impl RSAPrivateKey {
    pub fn modulus(&self) -> &IntegerAsn1 {
        &(self.0).0[1]
    }

    pub fn public_exponent(&self) -> &IntegerAsn1 {
        &(self.0).0[2]
    }

    pub fn private_exponent(&self) -> &IntegerAsn1 {
        &(self.0).0[3]
    }

    pub fn primes(&self) -> &[IntegerAsn1] {
        &(self.0).0[4..]
    }

    pub fn into_public_components(self) -> (IntegerAsn1, IntegerAsn1) {
        let mut iter = (self.0).0.into_iter();
        iter.next().unwrap();
        (iter.next().unwrap(), iter.next().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::Sign;

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

        let modulus = BigInt::from_bytes_be(Sign::Plus, &encoded[35..100]);
        let public_exponent = BigInt::from_bytes_be(Sign::Plus, &encoded[102..105]);
        let private_exponent = BigInt::from_bytes_be(Sign::Plus, &encoded[107..171]);
        let primes = vec![
            BigInt::from_bytes_be(Sign::Plus, &encoded[173..206]),
            BigInt::from_bytes_be(Sign::Plus, &encoded[208..241]),
            BigInt::from_bytes_be(Sign::Plus, &encoded[243..276]),
            BigInt::from_bytes_be(Sign::Plus, &encoded[278..311]),
            BigInt::from_bytes_be(Sign::Plus, &encoded[313..346]),
        ];
        let private_key =
            PrivateKeyInfo::new_rsa_encryption(modulus, public_exponent, private_exponent, primes);
        check_serde!(private_key: PrivateKeyInfo in encoded);
    }
}
