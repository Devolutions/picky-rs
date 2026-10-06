use crate::hash::{HashAlgorithm, HashError};
use crate::key::ec::{EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, KeyError, PublicKey};
use base64::Engine as _;
use picky_asn1_x509::PublicKey as InnerPublicKey;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshPublicKeyError {
    #[error("invalid SSH public key encoding")]
    InvalidEncoding,
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error("unsupported SSH key type: {0}")]
    UnsupportedKeyType(String),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error(transparent)]
    HashError(#[from] HashError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshBasePublicKey {
    Rsa(PublicKey),
    Ec(PublicKey),
    Ed(PublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    pub inner_key: SshBasePublicKey,
    pub comment: String,
}

impl SshPublicKey {
    pub fn to_string(&self) -> Result<String, SshPublicKeyError> {
        let (key_type, blob) = self.encode_blob()?;
        Ok(format!(
            "{key_type} {} {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(blob),
            self.comment
        ))
    }

    pub fn inner_key(&self) -> &PublicKey {
        match &self.inner_key {
            SshBasePublicKey::Rsa(key) | SshBasePublicKey::Ec(key) | SshBasePublicKey::Ed(key) => key,
        }
    }

    pub fn fingerprint_sha256(&self) -> Result<[u8; 32], SshPublicKeyError> {
        let (_, blob) = self.encode_blob()?;
        let digest = HashAlgorithm::SHA2_256.digest(&blob)?;
        digest.try_into().map_err(|_| SshPublicKeyError::InvalidEncoding)
    }

    pub fn fingerprint_md5(&self) -> Result<[u8; 16], SshPublicKeyError> {
        let (_, blob) = self.encode_blob()?;
        HashAlgorithm::MD5
            .digest(&blob)?
            .try_into()
            .map_err(|_| SshPublicKeyError::InvalidEncoding)
    }

    pub fn fingerprint_sha1(&self) -> Result<[u8; 20], SshPublicKeyError> {
        let (_, blob) = self.encode_blob()?;
        HashAlgorithm::SHA1
            .digest(&blob)?
            .try_into()
            .map_err(|_| SshPublicKeyError::InvalidEncoding)
    }

    pub(crate) fn encode_blob(&self) -> Result<(&'static str, Vec<u8>), SshPublicKeyError> {
        let mut blob = Vec::new();
        let key_type = match &self.inner_key {
            SshBasePublicKey::Rsa(key) => {
                let InnerPublicKey::Rsa(key) = &key.as_inner().subject_public_key else {
                    return Err(SshPublicKeyError::InvalidEncoding);
                };
                write_string(&mut blob, b"ssh-rsa");
                write_mpint(&mut blob, key.public_exponent.as_unsigned_bytes_be());
                write_mpint(&mut blob, key.modulus.as_unsigned_bytes_be());
                "ssh-rsa"
            }
            SshBasePublicKey::Ec(key) => {
                let key = EcdsaPublicKey::try_from(key)?;
                let (key_type, identifier) = match key.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => ("ecdsa-sha2-nistp256", "nistp256"),
                    NamedEcCurve::Known(EcCurve::NistP384) => ("ecdsa-sha2-nistp384", "nistp384"),
                    NamedEcCurve::Known(EcCurve::NistP521) => ("ecdsa-sha2-nistp521", "nistp521"),
                    _ => {
                        return Err(SshPublicKeyError::UnsupportedKeyType(
                            "unsupported EC key type".to_string(),
                        ));
                    }
                };
                write_string(&mut blob, key_type.as_bytes());
                write_string(&mut blob, identifier.as_bytes());
                write_string(&mut blob, key.encoded_point());
                key_type
            }
            SshBasePublicKey::Ed(key) => {
                let key = EdPublicKey::try_from(key)?;
                if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) {
                    return Err(SshPublicKeyError::UnsupportedKeyType(key.algorithm().to_string()));
                }
                write_string(&mut blob, b"ssh-ed25519");
                write_string(&mut blob, key.data());
                "ssh-ed25519"
            }
        };
        Ok((key_type, blob))
    }
}

impl FromStr for SshPublicKey {
    type Err = SshPublicKeyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim_end_matches(['\r', '\n']);
        let mut fields = input.splitn(3, ' ');
        let outer_key_type = fields.next().ok_or(SshPublicKeyError::InvalidEncoding)?;
        let encoded = fields.next().ok_or(SshPublicKeyError::InvalidEncoding)?;
        let comment = fields.next().unwrap_or_default().to_string();
        let blob = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let mut cursor = blob.as_slice();
        let inner_key_type = read_string(&mut cursor)?;
        if inner_key_type != outer_key_type.as_bytes() {
            return Err(SshPublicKeyError::InvalidEncoding);
        }

        let inner_key = match outer_key_type {
            "ssh-rsa" => {
                let exponent = read_mpint(&mut cursor)?;
                let modulus = read_mpint(&mut cursor)?;
                SshBasePublicKey::Rsa(PublicKey::from_rsa_encoded_components(modulus, exponent))
            }
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                let identifier = read_string(&mut cursor)?;
                let (expected_identifier, curve) = match outer_key_type {
                    "ecdsa-sha2-nistp256" => (b"nistp256".as_slice(), EcCurve::NistP256),
                    "ecdsa-sha2-nistp384" => (b"nistp384".as_slice(), EcCurve::NistP384),
                    "ecdsa-sha2-nistp521" => (b"nistp521".as_slice(), EcCurve::NistP521),
                    _ => unreachable!("matched above"),
                };
                if identifier != expected_identifier {
                    return Err(SshPublicKeyError::InvalidEncoding);
                }
                let point = read_string(&mut cursor)?;
                SshBasePublicKey::Ec(PublicKey::from_ec_encoded_components(
                    &NamedEcCurve::Known(curve).into(),
                    point,
                ))
            }
            "ssh-ed25519" => {
                let public_key = read_string(&mut cursor)?;
                if public_key.len() != 32 {
                    return Err(SshPublicKeyError::InvalidEncoding);
                }
                SshBasePublicKey::Ed(PublicKey::from_ed_encoded_components(
                    &EdAlgorithm::Ed25519.into(),
                    public_key,
                ))
            }
            unsupported => return Err(SshPublicKeyError::UnsupportedKeyType(unsupported.to_string())),
        };

        if !cursor.is_empty() {
            return Err(SshPublicKeyError::InvalidEncoding);
        }
        Ok(Self { inner_key, comment })
    }
}

fn read_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], SshPublicKeyError> {
    if cursor.len() < 4 {
        return Err(SshPublicKeyError::InvalidEncoding);
    }
    let len = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
    *cursor = &cursor[4..];
    if cursor.len() < len {
        return Err(SshPublicKeyError::InvalidEncoding);
    }
    let value = &cursor[..len];
    *cursor = &cursor[len..];
    Ok(value)
}

fn read_mpint<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], SshPublicKeyError> {
    let value = read_string(cursor)?;
    if value.first() == Some(&0) {
        Ok(&value[1..])
    } else {
        Ok(value)
    }
}

fn write_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn write_mpint(output: &mut Vec<u8>, value: &[u8]) {
    let value = value.strip_prefix(&[0]).unwrap_or(value);
    let needs_zero = value.first().is_some_and(|byte| byte & 0x80 != 0);
    output.extend_from_slice(&((value.len() + usize::from(needs_zero)) as u32).to_be_bytes());
    if needs_zero {
        output.push(0);
    }
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_public_key_roundtrip_and_sha256_fingerprint() {
        let encoded = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test2@picky.com\r\n";

        let key = SshPublicKey::from_str(encoded).unwrap();

        assert_eq!(key.to_string().unwrap(), encoded);
        assert_ne!(key.fingerprint_sha256().unwrap(), [0u8; 32]);
    }

    #[test]
    fn approved_ec_public_keys_roundtrip() {
        let keys = [
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPHvQqIXgctGhw11YiThhgMojjk6yxFfToNwVOXMdp1hB/wPJvb/H9rH7Ln5EcdSJFngDtC86wtvoQEyaddBSNg= test@picky.com\r\n",
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLkc/NcBZLJsCDBAAigxImjtK5TaR19xS6bN8d78us71AHAD1Tx9ezze1vBtPvCxABKFh1BaB1MlZFlSqIzfo22TMeglSdARtnwz6Y7b4gzMoIDVpz1jb0/mOpPvI2qWYw== test@picky.com\r\n",
        ];

        for encoded in keys {
            let key = SshPublicKey::from_str(encoded).unwrap();
            assert_eq!(key.to_string().unwrap(), encoded);
        }

        let p521 = crate::key::PrivateKey::from_pem_str(picky_test_data::EC_NIST521_PK_1)
            .unwrap()
            .to_public_key()
            .unwrap();
        let key = SshPublicKey {
            inner_key: SshBasePublicKey::Ec(p521),
            comment: "p521@picky.com".to_string(),
        };
        let encoded = key.to_string().unwrap();
        assert_eq!(SshPublicKey::from_str(&encoded).unwrap(), key);
    }

    #[test]
    fn rejects_legacy_fingerprints() {
        let encoded = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7r test";
        let key = SshPublicKey::from_str(encoded).unwrap();

        assert!(key.fingerprint_md5().is_err());
        assert!(key.fingerprint_sha1().is_err());
    }

    #[test]
    fn ed25519_public_key_roundtrip() {
        let encoded = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDKeXB8air8kVbyipmcfbnqvW5iSiDXmefB9o2vpNINr test\r\n";
        let key = SshPublicKey::from_str(encoded).unwrap();

        assert_eq!(key.to_string().unwrap(), encoded);
        assert_ne!(key.fingerprint_sha256().unwrap(), [0u8; 32]);
    }
}
