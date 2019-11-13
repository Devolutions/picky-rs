use crate::{
    error::Result,
    serde::{private_key_info::PrivateKeyValue, PrivateKeyInfo, SubjectPublicKeyInfo},
};
use err_ctx::ResultExt;
use num_bigint_dig::{BigInt, Sign};
use serde_asn1_der::asn1_wrapper::OctetStringAsn1Container;

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey {
    inner: PrivateKeyInfo,
}

impl From<PrivateKeyInfo> for PrivateKey {
    fn from(key: PrivateKeyInfo) -> Self {
        Self { inner: key }
    }
}

impl From<PrivateKey> for PrivateKeyInfo {
    fn from(key: PrivateKey) -> Self {
        key.inner
    }
}

impl From<PrivateKey> for SubjectPublicKeyInfo {
    fn from(key: PrivateKey) -> Self {
        match key.inner.private_key {
            PrivateKeyValue::RSA(OctetStringAsn1Container(key)) => {
                let (modulus, public_exponent) = key.into_public_components();
                SubjectPublicKeyInfo::new_rsa_key(modulus, public_exponent)
            }
        }
    }
}

impl PrivateKey {
    pub fn from_pkcs8<T: ?Sized + AsRef<[u8]>>(pkcs8: &T) -> serde_asn1_der::Result<Self> {
        Ok(Self {
            inner: serde_asn1_der::from_bytes(pkcs8.as_ref())?,
        })
    }

    pub fn to_pkcs8(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(&self.inner)
    }

    pub fn to_subject_public_key_info(&self) -> SubjectPublicKeyInfo {
        match &self.inner.private_key {
            PrivateKeyValue::RSA(OctetStringAsn1Container(key)) => {
                SubjectPublicKeyInfo::new_rsa_key(
                    key.modulus().clone(),
                    key.public_exponent().clone(),
                )
            }
        }
    }

    pub fn as_inner(&self) -> &PrivateKeyInfo {
        &self.inner
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

        Ok(Self {
            inner: PrivateKeyInfo::new_rsa_encryption(
                modulus,
                public_exponent,
                private_exponent,
                key.primes()
                    .iter()
                    .map(|p| BigInt::from_bytes_be(Sign::Plus, &p.to_bytes_be()))
                    .collect(),
            ),
        })
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
// Generating RSA keys in debug is very slow. Therefore, these tests only run in release mode.
mod tests {
    use super::*;
    use crate::models::{certificate::Cert, signature::SignatureHashType};

    #[test]
    fn generate_rsa_keys() {
        let private_key = PrivateKey::generate_rsa(4096).expect("couldn't generate rsa key");

        // attempts to generate a full certificate using our newly generated private key
        Cert::generate_root("test", SignatureHashType::RsaSha256, &private_key)
            .expect("couldn't generate root ca");
    }
}
