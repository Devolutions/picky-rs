use crate::key::ec::{EcComponent, EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdKeypair, EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, PrivateKey};
use crate::putty::PuttyError;
use crate::putty::key_value::PpkKeyAlgorithmValue;
use crate::putty::public_key::PuttyBasePublicKey;
use crate::ssh::SshPrivateKey;
use crate::ssh::decode::SshReadExt;
use crate::ssh::encode::SshWriteExt;
use crate::ssh::private_key::SshBasePrivateKey;
use crate::ssh::public_key::SshBasePublicKey;
use crypto_bigint::BoxedUint;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// PuTTY private key wrapper
pub(crate) struct PuttyPrivateKey {
    pub(crate) base: PuttyBasePrivateKey,
    pub(crate) comment: String,
}

impl PuttyPrivateKey {
    pub fn from_openssh(key: &SshPrivateKey) -> Result<Self, PuttyError> {
        let base = PuttyBasePrivateKey::from_openssh(&key.base_key)?;
        let comment = key.comment.clone();

        Ok(Self { base, comment })
    }

    /// Converts the key to an OpenSSH key (with or without encryption)
    pub fn to_openssh(&self, passphrase: Option<&str>) -> Result<SshPrivateKey, PuttyError> {
        let base = self.base.to_openssh()?;
        let comment = if self.comment.is_empty() {
            None
        } else {
            Some(self.comment.clone())
        };

        let key = match base {
            SshBasePrivateKey::Rsa(key) => key,
            SshBasePrivateKey::Ec(key) => key,
            SshBasePrivateKey::Ed(key) => key,
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
        };

        Ok(SshPrivateKey::h_picky_private_key_to_ssh_private_key(
            key,
            passphrase.map(From::from),
            comment,
        )?)
    }
}

pub(crate) struct PuttyBasePrivateKey {
    pub(crate) algorithm: PpkKeyAlgorithmValue,
    pub(crate) public_key: PuttyBasePublicKey,
    pub(crate) data: Vec<u8>,
}

impl PuttyBasePrivateKey {
    pub fn from_openssh(key: &SshBasePrivateKey) -> Result<Self, PuttyError> {
        let mut data = Vec::new();
        let cursor = &mut data;

        match key {
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                // Putty does not support SK keys
                Err(PuttyError::NotSupported { feature: "SK keys" })
            }
            SshBasePrivateKey::Rsa(key) => {
                let mut rsa_key = RsaPrivateKey::try_from(key)?;

                cursor.write_ssh_mpint(rsa_key.d())?;
                if rsa_key.primes().len() != 2 {
                    return Err(PuttyError::RsaInvalidPrimesCount {
                        count: rsa_key.primes().len(),
                    });
                }
                cursor.write_ssh_mpint(&rsa_key.primes()[0])?;
                cursor.write_ssh_mpint(&rsa_key.primes()[1])?;

                rsa_key.precompute().map_err(|_| PuttyError::RsaPrecompute)?;
                let qinv = rsa_key
                    .qinv()
                    .expect("BUG: should be precomuted above")
                    .retrieve()
                    .to_be_bytes_trimmed_vartime();
                cursor.write_ssh_bytes(&qinv)?;

                let ssh_public_key = SshBasePublicKey::Rsa(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm: PpkKeyAlgorithmValue::Rsa,
                    data,
                    public_key,
                })
            }
            SshBasePrivateKey::Ec(key) => {
                let ec_key = EcdsaKeypair::try_from(key)?;

                let secret = BoxedUint::from_be_slice_vartime(ec_key.secret());
                cursor.write_ssh_mpint(&secret)?;

                let algorithm = match ec_key.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => PpkKeyAlgorithmValue::EcdsaSha2Nistp256,
                    NamedEcCurve::Known(EcCurve::NistP384) => PpkKeyAlgorithmValue::EcdsaSha2Nistp384,
                    NamedEcCurve::Known(EcCurve::NistP521) => PpkKeyAlgorithmValue::EcdsaSha2Nistp521,
                    _ => {
                        return Err(PuttyError::NotSupported {
                            feature: "unknown EC curve",
                        });
                    }
                };

                let ssh_public_key = SshBasePublicKey::Ec(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm,
                    data,
                    public_key,
                })
            }
            SshBasePrivateKey::Ed(key) => {
                let ed_key = EdKeypair::try_from(key)?;

                // PuTTY 0.75 and later write the little-endian Ed25519 secret at its full length.
                cursor.write_ssh_bytes(ed_key.secret())?;

                let algorithm = match ed_key.algorithm() {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => PpkKeyAlgorithmValue::Ed25519,
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                        return Err(PuttyError::NotSupported { feature: "X25519 keys" });
                    }
                    _ => {
                        return Err(PuttyError::NotSupported {
                            feature: "unknown EdDSA algorithm",
                        });
                    }
                };

                let ssh_public_key = SshBasePublicKey::Ed(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm,
                    data,
                    public_key,
                })
            }
        }
    }

    pub fn to_openssh(&self) -> Result<SshBasePrivateKey, PuttyError> {
        let ssh_public_key = self.public_key.to_openssh()?;
        let mut data = self.data.as_slice();

        match self.algorithm {
            PpkKeyAlgorithmValue::Rsa => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Rsa(rsa) => RsaPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let d = data.read_ssh_mpint()?;
                let p1 = data.read_ssh_mpint()?;
                let p2 = data.read_ssh_mpint()?;
                let _qinv = data.read_ssh_mpint()?;

                let private_key = PrivateKey::from_rsa_components(public.n(), public.e(), &d, &[p1, p2])?;

                Ok(SshBasePrivateKey::Rsa(private_key))
            }
            PpkKeyAlgorithmValue::EcdsaSha2Nistp256
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp384
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp521 => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Ec(rsa) => EcdsaPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let secret = data.read_ssh_bytes()?;

                let curve = match self.algorithm {
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp256 => EcCurve::NistP256,
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp384 => EcCurve::NistP384,
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp521 => EcCurve::NistP521,
                    _ => unreachable!("BUG: algorithm is checked above"),
                };

                // The secret is a minimal `mpint`, so it may be shorter than the field length.
                let secret = curve.pad_component(EcComponent::Secret(&secret))?;

                let private_key = PrivateKey::from_ec_encoded_components(
                    NamedEcCurve::Known(curve).into(),
                    &secret,
                    Some(public.encoded_point()),
                );

                Ok(SshBasePrivateKey::Ec(private_key))
            }
            PpkKeyAlgorithmValue::Ed25519 => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Ed(rsa) => EdPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let secret = decode_ed25519_secret(data.read_ssh_bytes()?, public.data())?;

                let private_key = PrivateKey::from_ed_encoded_components(
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(),
                    &secret,
                    Some(public.data()),
                );

                Ok(SshBasePrivateKey::Ed(private_key))
            }
            _ => Err(PuttyError::NotSupported {
                feature: "unsupported key algorithm",
            }),
        }
    }

    pub fn to_inner_key(&self) -> Result<PrivateKey, PuttyError> {
        let inner = match self.to_openssh()? {
            SshBasePrivateKey::Rsa(key) => key,
            SshBasePrivateKey::Ec(key) => key,
            SshBasePrivateKey::Ed(key) => key,
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
        };

        Ok(inner)
    }
}

/// Restores the 32-byte Ed25519 secret from a PPK private blob and checks it against the public key.
///
/// PuTTY stores the secret as a little-endian integer, and versions before 0.75 omit its trailing zero bytes.
/// Earlier picky versions wrote a big-endian `mpint` instead, which omits leading zero bytes and adds one before a first byte of 0x80 or more.
fn decode_ed25519_secret(mut secret: Vec<u8>, public_key: &[u8]) -> Result<Vec<u8>, PuttyError> {
    const SECRET_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;

    if secret.len() == SECRET_LENGTH + 1 && secret[0] == 0 {
        secret.remove(0);
    }

    let padding = SECRET_LENGTH
        .checked_sub(secret.len())
        .ok_or(PuttyError::InvalidPrivateKeyData)?;
    let mut little_endian = [0; SECRET_LENGTH];
    little_endian[..secret.len()].copy_from_slice(&secret);
    let mut big_endian = [0; SECRET_LENGTH];
    big_endian[padding..].copy_from_slice(&secret);

    [little_endian, big_endian]
        .into_iter()
        .find(|candidate| {
            ed25519_dalek::SigningKey::from_bytes(candidate)
                .verifying_key()
                .as_bytes()
                == public_key
        })
        .map(|candidate| candidate.to_vec())
        .ok_or(PuttyError::PublicAndPrivateKeyMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Earlier picky versions wrote the Ed25519 secret as a big-endian `mpint`.
    #[rstest]
    #[case(picky_test_data::SSH_PRIVATE_KEY_ED25519, 33)]
    #[case(picky_test_data::SSH_PRIVATE_KEY_ED25519_LEADING_ZERO, 31)]
    fn ed25519_secret_written_as_mpint(#[case] pem: &str, #[case] mpint_length: usize) {
        let ssh_key = SshPrivateKey::from_pem_str(pem, None).unwrap();
        let secret = EdKeypair::try_from(ssh_key.inner_key().unwrap())
            .unwrap()
            .secret()
            .to_vec();

        let mut key = PuttyBasePrivateKey::from_openssh(&ssh_key.base_key).unwrap();
        key.data.clear();
        key.data
            .write_ssh_mpint(&BoxedUint::from_be_slice_vartime(&secret))
            .unwrap();
        assert_eq!(key.data.len(), 4 + mpint_length);

        assert_eq!(&key.to_inner_key().unwrap(), ssh_key.inner_key().unwrap());
    }

    #[rstest]
    #[case(&[0x01; 32], "public and private key mismatch")]
    // Longer than any accepted encoding; must be rejected without panicking.
    #[case(&[0x01; 33], "invalid private key data")]
    fn ed25519_invalid_secret(#[case] secret: &[u8], #[case] error: &str) {
        let ssh_key = SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_ED25519, None).unwrap();

        let mut key = PuttyBasePrivateKey::from_openssh(&ssh_key.base_key).unwrap();
        key.data.clear();
        key.data.write_ssh_bytes(secret).unwrap();

        assert_eq!(key.to_inner_key().unwrap_err().to_string(), error);
    }
}
