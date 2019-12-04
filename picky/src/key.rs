use crate::private::{private_key_info::PrivateKeyValue, PrivateKeyInfo, SubjectPublicKeyInfo};
use picky_asn1::wrapper::{IntegerAsn1, OctetStringAsn1Container};
use picky_asn1_der::Asn1DerError;
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum KeyError {
    /// asn1 serialization error
    #[snafu(display("(asn1) couldn't serialize {}: {}", element, source))]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// asn1 deserialization error
    #[snafu(display("(asn1) couldn't deserialize {}: {}", element, source))]
    Asn1Deserialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// RSA error
    #[snafu(display("RSA error: {}", context))]
    Rsa { context: String },

    /// no secure randomness available
    NoSecureRandomness,
}

impl From<rsa::errors::Error> for KeyError {
    fn from(e: rsa::errors::Error) -> Self {
        KeyError::Rsa {
            context: e.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(PrivateKeyInfo);

impl From<PrivateKeyInfo> for PrivateKey {
    fn from(key: PrivateKeyInfo) -> Self {
        Self(key)
    }
}

impl From<PrivateKey> for PrivateKeyInfo {
    fn from(key: PrivateKey) -> Self {
        key.0
    }
}

impl From<PrivateKey> for SubjectPublicKeyInfo {
    fn from(key: PrivateKey) -> Self {
        match key.0.private_key {
            PrivateKeyValue::RSA(OctetStringAsn1Container(key)) => {
                let (modulus, public_exponent) = key.into_public_components();
                SubjectPublicKeyInfo::new_rsa_key(modulus, public_exponent)
            }
        }
    }
}

impl PrivateKey {
    pub fn from_pkcs8<T: ?Sized + AsRef<[u8]>>(pkcs8: &T) -> Result<Self, KeyError> {
        Ok(Self(picky_asn1_der::from_bytes(pkcs8.as_ref()).context(
            Asn1Deserialization {
                element: "private key info (pkcs8)",
            },
        )?))
    }

    pub fn from_rsa_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        use crate::{private::private_key_info::RSAPrivateKey, AlgorithmIdentifier};

        let private_key = picky_asn1_der::from_bytes::<RSAPrivateKey>(der.as_ref()).context(
            Asn1Deserialization {
                element: "rsa private key",
            },
        )?;

        Ok(Self(PrivateKeyInfo {
            version: 0,
            private_key_algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            private_key: PrivateKeyValue::RSA(private_key.into()),
        }))
    }

    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        picky_asn1_der::to_vec(&self.0).context(Asn1Serialization {
            element: "private key info (pkcs8)",
        })
    }

    pub fn to_public_key(&self) -> PublicKey {
        match &self.0.private_key {
            PrivateKeyValue::RSA(OctetStringAsn1Container(key)) => {
                SubjectPublicKeyInfo::new_rsa_key(
                    key.modulus().clone(),
                    key.public_exponent().clone(),
                )
                .into()
            }
        }
    }

    /// **Beware**: this is insanely slow in debug builds.
    pub fn generate_rsa(bits: usize) -> Result<Self, KeyError> {
        use rand::rngs::OsRng;
        use rsa::{PublicKey, RSAPrivateKey};

        let mut rng = OsRng::new().map_err(|_| KeyError::NoSecureRandomness)?;
        let key = RSAPrivateKey::new(&mut rng, bits)?;

        let modulus = IntegerAsn1::from_signed_bytes_be(key.n().to_bytes_be());
        let public_exponent = IntegerAsn1::from_signed_bytes_be(key.e().to_bytes_be());
        let private_exponent = IntegerAsn1::from_signed_bytes_be(key.d().to_bytes_be());

        Ok(Self(PrivateKeyInfo::new_rsa_encryption(
            modulus,
            public_exponent,
            private_exponent,
            key.primes()
                .iter()
                .map(|p| IntegerAsn1::from_signed_bytes_be(p.to_bytes_be()))
                .collect(),
        )))
    }

    pub(crate) fn as_inner(&self) -> &PrivateKeyInfo {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(SubjectPublicKeyInfo);

impl From<SubjectPublicKeyInfo> for PublicKey {
    fn from(key: SubjectPublicKeyInfo) -> Self {
        Self(key)
    }
}

impl From<PublicKey> for SubjectPublicKeyInfo {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(key: PrivateKey) -> Self {
        Self(key.into())
    }
}

impl PublicKey {
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, KeyError> {
        Ok(Self(picky_asn1_der::from_bytes(der.as_ref()).context(
            Asn1Deserialization {
                element: "subject public key info",
            },
        )?))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, KeyError> {
        picky_asn1_der::to_vec(&self.0).context(Asn1Serialization {
            element: "subject public key info",
        })
    }

    pub(crate) fn as_inner(&self) -> &SubjectPublicKeyInfo {
        &self.0
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
/// Generating RSA keys in debug is very slow. Therefore, these tests only run in release mode.
mod tests {
    use super::*;

    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        use crate::x509::{certificate::CertificateBuilder, date::UTCDate, name::DirectoryName};

        fn generate_certificate_from_pk(private_key: PrivateKey) {
            // validity
            let valid_from = UTCDate::ymd(2019, 10, 10).unwrap();
            let valid_to = UTCDate::ymd(2019, 10, 11).unwrap();

            CertificateBuilder::new()
                .valididy(valid_from, valid_to)
                .self_signed(DirectoryName::new_common_name("Test Root CA"), &private_key)
                .ca(true)
                .build()
                .expect("couldn't build root ca");
        }
    } else {
        fn generate_certificate_from_pk(_: PrivateKey) {}
    }}

    #[test]
    fn generate_rsa_keys() {
        let private_key = PrivateKey::generate_rsa(4096).expect("couldn't generate rsa key");
        generate_certificate_from_pk(private_key);
    }
}
