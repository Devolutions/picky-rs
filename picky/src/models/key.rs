use crate::{
    error::Result,
    serde::{private_key_info::PrivateKeyValue, PrivateKeyInfo, SubjectPublicKeyInfo},
};
use err_ctx::ResultExt;
use num_bigint_dig::{BigInt, Sign};
use serde_asn1_der::asn1_wrapper::OctetStringAsn1Container;

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
    pub fn from_pkcs8<T: ?Sized + AsRef<[u8]>>(pkcs8: &T) -> serde_asn1_der::Result<Self> {
        Ok(Self(serde_asn1_der::from_bytes(pkcs8.as_ref())?))
    }

    pub fn to_pkcs8(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(&self.0)
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

    pub fn as_inner(&self) -> &PrivateKeyInfo {
        &self.0
    }

    pub fn into_inner(self) -> PrivateKeyInfo {
        self.0
    }

    /// **Beware**: this is insanely slow in debug builds.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        use rand::rngs::OsRng;
        use rsa::{PublicKey, RSAPrivateKey};

        let mut rng = OsRng::new().ctx("no secure randomness available")?;
        let key = RSAPrivateKey::new(&mut rng, bits)
            .map_err(|_| crate::error::Error::Rsa)
            .ctx("failed to generate rsa key")?;

        let modulus = BigInt::from_bytes_be(Sign::Plus, &key.n().to_bytes_be());
        let public_exponent = BigInt::from_bytes_be(Sign::Plus, &key.e().to_bytes_be());
        let private_exponent = BigInt::from_bytes_be(Sign::Plus, &key.d().to_bytes_be());

        Ok(Self(PrivateKeyInfo::new_rsa_encryption(
            modulus,
            public_exponent,
            private_exponent,
            key.primes()
                .iter()
                .map(|p| BigInt::from_bytes_be(Sign::Plus, &p.to_bytes_be()))
                .collect(),
        )))
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
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> serde_asn1_der::Result<Self> {
        Ok(Self(serde_asn1_der::from_bytes(der.as_ref())?))
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(&self.0)
    }

    pub fn as_inner(&self) -> &SubjectPublicKeyInfo {
        &self.0
    }

    pub fn into_inner(self) -> SubjectPublicKeyInfo {
        self.0
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
// Generating RSA keys in debug is very slow. Therefore, these tests only run in release mode.
mod tests {
    use super::*;
    use crate::models::{certificate::CertificateBuilder, date::UTCDate, name::Name};

    #[test]
    fn generate_rsa_keys() {
        let private_key = PrivateKey::generate_rsa(4096).expect("couldn't generate rsa key");

        // validity
        let valid_from = UTCDate::ymd(2019, 10, 10).unwrap();
        let valid_to = UTCDate::ymd(2019, 10, 11).unwrap();

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(Name::new_common_name("Test Root CA"), &private_key)
            .ca(true)
            .build()
            .expect("couldn't build root ca");
    }
}
