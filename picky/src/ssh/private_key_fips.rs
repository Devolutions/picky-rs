use crate::key::ec::{EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdKeypair, EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, KeyError, PrivateKey, PrivateKeyKind, RsaPrivateKeyComponents};
use crate::pem::{Pem, PemError, parse_pem};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::wire_fips::{Reader, trim_unsigned, write_bytes, write_mpint, write_string, write_u32};
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair};
use picky_asn1_x509::PrivateKeyValue;
use std::io;
use thiserror::Error;

const LABEL: &str = "OPENSSH PRIVATE KEY";
const MAGIC: &[u8] = b"openssh-key-v1\0";
const NONE: &str = "none";

#[derive(Debug, Error)]
pub enum SshPrivateKeyError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
    #[error("Unsupported kdf: {0}")]
    UnsupportedKdf(String),
    #[error("Invalid auth magic header")]
    InvalidAuthMagicHeader,
    #[error("Invalid keys amount. Expected 1 but got {0}")]
    InvalidKeysAmount(u32),
    #[error("Check numbers are not equal: {0} {1}. Wrong passphrase or key is corrupted")]
    InvalidCheckNumbers(u32, u32),
    #[error("Invalid public key: {0:?}")]
    InvalidPublicKey(#[from] SshPublicKeyError),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error(transparent)]
    PemError(#[from] PemError),
}

#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct KdfOption {
    pub salt: Vec<u8>,
    pub rounds: u32,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Kdf {
    pub name: String,
    pub option: KdfOption,
}

impl Default for Kdf {
    fn default() -> Self {
        Self {
            name: NONE.to_owned(),
            option: KdfOption::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshBasePrivateKey {
    Rsa(PrivateKey),
    Ec(PrivateKey),
    Ed(PrivateKey),
}

impl SshBasePrivateKey {
    pub fn base_public_key(&self) -> Result<SshBasePublicKey, SshPrivateKeyError> {
        Ok(match self {
            Self::Rsa(key) => SshBasePublicKey::Rsa(key.to_public_key()?),
            Self::Ec(key) => SshBasePublicKey::Ec(key.to_public_key()?),
            Self::Ed(key) => SshBasePublicKey::Ed(key.to_public_key()?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPrivateKey {
    pub cipher_name: String,
    pub kdf: Kdf,
    pub base_key: SshBasePrivateKey,
    pub public_key: SshPublicKey,
    pub check: u32,
    pub comment: String,
    pub passphrase: Option<String>,
}

impl SshPrivateKey {
    pub fn generate_rsa(
        bits: usize,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<Self, SshPrivateKeyError> {
        Self::h_picky_private_key_to_ssh_private_key(PrivateKey::generate_rsa(bits)?, passphrase, comment)
    }

    pub fn generate_ec(
        curve: EcCurve,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<Self, SshPrivateKeyError> {
        Self::h_picky_private_key_to_ssh_private_key(PrivateKey::generate_ec(curve)?, passphrase, comment)
    }

    pub fn generate_ed25519(passphrase: Option<String>, comment: Option<String>) -> Result<Self, SshPrivateKeyError> {
        Self::h_picky_private_key_to_ssh_private_key(
            PrivateKey::generate_ed(EdAlgorithm::Ed25519, true)?,
            passphrase,
            comment,
        )
    }

    pub fn from_pem(pem: &Pem, passphrase: Option<String>) -> Result<Self, SshPrivateKeyError> {
        if pem.label() != LABEL {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        Self::decode(pem.data(), passphrase)
    }

    pub fn from_pem_str(pem: &str, passphrase: Option<String>) -> Result<Self, SshPrivateKeyError> {
        Self::from_pem(&parse_pem(pem)?, passphrase)
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, SshPrivateKeyError> {
        Ok(Pem::new(LABEL, self.encode()?))
    }

    pub fn to_string(&self) -> Result<String, SshPrivateKeyError> {
        let mut output = self.to_pem()?.to_string();
        output.push('\n');
        Ok(output)
    }

    pub fn public_key(&self) -> &SshPublicKey {
        &self.public_key
    }

    pub fn base_key(&self) -> &SshBasePrivateKey {
        &self.base_key
    }

    pub fn inner_key(&self) -> Option<&PrivateKey> {
        Some(match &self.base_key {
            SshBasePrivateKey::Rsa(key) | SshBasePrivateKey::Ec(key) | SshBasePrivateKey::Ed(key) => key,
        })
    }

    pub(crate) fn h_picky_private_key_to_ssh_private_key(
        private_key: PrivateKey,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<Self, SshPrivateKeyError> {
        if passphrase.is_some() {
            return Err(SshPrivateKeyError::UnsupportedCipher(
                "encrypted OpenSSH private keys are disabled by the active cryptographic policy".to_owned(),
            ));
        }
        let public_key = private_key.to_public_key()?;
        let (base_key, inner_key) = match private_key.as_kind() {
            PrivateKeyKind::Rsa => (SshBasePrivateKey::Rsa(private_key), SshBasePublicKey::Rsa(public_key)),
            PrivateKeyKind::Ec { .. } => (SshBasePrivateKey::Ec(private_key), SshBasePublicKey::Ec(public_key)),
            PrivateKeyKind::Ed { .. } => (SshBasePrivateKey::Ed(private_key), SshBasePublicKey::Ed(public_key)),
        };
        Ok(Self {
            cipher_name: NONE.to_owned(),
            kdf: Kdf::default(),
            base_key,
            public_key: SshPublicKey {
                inner_key,
                comment: String::new(),
            },
            check: 0,
            comment: comment.unwrap_or_default(),
            passphrase: None,
        })
    }

    fn decode(input: &[u8], _passphrase: Option<String>) -> Result<Self, SshPrivateKeyError> {
        let mut reader = Reader::new(input);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(SshPrivateKeyError::InvalidAuthMagicHeader);
        }
        let cipher_name = reader.read_string()?.to_owned();
        let kdf_name = reader.read_string()?.to_owned();
        let kdf_options = reader.read_bytes()?;
        if cipher_name != NONE {
            return Err(SshPrivateKeyError::UnsupportedCipher(cipher_name));
        }
        if kdf_name != NONE {
            return Err(SshPrivateKeyError::UnsupportedKdf(kdf_name));
        }
        if !kdf_options.is_empty() {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        let key_count = reader.read_u32()?;
        if key_count != 1 {
            return Err(SshPrivateKeyError::InvalidKeysAmount(key_count));
        }
        let public_blob = reader.read_bytes()?;
        let private_blob = reader.read_bytes()?;
        if !reader.is_empty() {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }

        let mut private = Reader::new(private_blob);
        let check = private.read_u32()?;
        let check2 = private.read_u32()?;
        if check != check2 {
            return Err(SshPrivateKeyError::InvalidCheckNumbers(check, check2));
        }
        let base_key = decode_private_key(&mut private)?;
        let comment = private.read_string()?.to_owned();
        validate_padding(private.remaining())?;
        let inner_key = base_key.base_public_key()?;
        let public_key = SshPublicKey {
            inner_key,
            comment: String::new(),
        };
        let (_, expected_public_blob) = public_key.encode_blob()?;
        if public_blob != expected_public_blob {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        Ok(Self {
            cipher_name,
            kdf: Kdf {
                name: kdf_name,
                option: KdfOption::default(),
            },
            base_key,
            public_key,
            check,
            comment,
            passphrase: None,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, SshPrivateKeyError> {
        if self.passphrase.is_some() || self.cipher_name != NONE || self.kdf != Kdf::default() {
            return Err(SshPrivateKeyError::UnsupportedCipher(self.cipher_name.clone()));
        }
        let mut output = MAGIC.to_vec();
        write_string(&mut output, NONE)?;
        write_string(&mut output, NONE)?;
        write_bytes(&mut output, &[])?;
        write_u32(&mut output, 1);
        let (_, public_blob) = self.public_key.encode_blob()?;
        write_bytes(&mut output, &public_blob)?;

        let mut private = Vec::new();
        write_u32(&mut private, self.check);
        write_u32(&mut private, self.check);
        encode_private_key(&self.base_key, &mut private)?;
        write_string(&mut private, &self.comment)?;
        let padding_len = 8 - (private.len() % 8);
        private.extend((1..=padding_len).map(|value| value as u8));
        write_bytes(&mut output, &private)?;
        Ok(output)
    }
}

impl TryFrom<PrivateKey> for SshPrivateKey {
    type Error = SshPrivateKeyError;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        Self::h_picky_private_key_to_ssh_private_key(value, None, None)
    }
}

fn decode_private_key(reader: &mut Reader<'_>) -> Result<SshBasePrivateKey, SshPrivateKeyError> {
    match reader.read_string()? {
        "ssh-rsa" => {
            let n = reader.read_mpint()?;
            let e = reader.read_mpint()?;
            let d = reader.read_mpint()?;
            let iqmp = reader.read_mpint()?;
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;
            validate_rsa_component_sizes(n, e, d, iqmp, p, q)?;
            let dp = modulo(d, &subtract_one(p)?)?;
            let dq = modulo(d, &subtract_one(q)?)?;
            let key = PrivateKey::from_rsa_encoded_components(RsaPrivateKeyComponents {
                modulus: n,
                public_exponent: e,
                private_exponent: d,
                prime_1: p,
                prime_2: q,
                exponent_1: &dp,
                exponent_2: &dq,
                coefficient: iqmp,
            });
            RsaKeyPair::from_der(&key.to_pkcs1()?).map_err(|_| SshPrivateKeyError::InvalidKeyFormat)?;
            Ok(SshBasePrivateKey::Rsa(key))
        }
        key_type @ ("ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521") => {
            let (identifier, curve) = match key_type {
                "ecdsa-sha2-nistp256" => ("nistp256", EcCurve::NistP256),
                "ecdsa-sha2-nistp384" => ("nistp384", EcCurve::NistP384),
                _ => ("nistp521", EcCurve::NistP521),
            };
            if reader.read_string()? != identifier {
                return Err(SshPrivateKeyError::InvalidKeyFormat);
            }
            let point = reader.read_bytes()?;
            let secret = reader.read_mpint()?;
            let signing_algorithm = match curve {
                EcCurve::NistP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                EcCurve::NistP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                EcCurve::NistP521 => &aws_lc_rs::signature::ECDSA_P521_SHA512_ASN1_SIGNING,
            };
            EcdsaKeyPair::from_private_key_and_public_key(signing_algorithm, secret, point)
                .map_err(|_| SshPrivateKeyError::InvalidKeyFormat)?;
            Ok(SshBasePrivateKey::Ec(PrivateKey::from_ec_encoded_components(
                NamedEcCurve::Known(curve).into(),
                secret,
                Some(point),
            )))
        }
        "ssh-ed25519" => {
            let public = reader.read_bytes()?;
            let combined = reader.read_bytes()?;
            if public.len() != 32 || combined.len() != 64 || &combined[32..] != public {
                return Err(SshPrivateKeyError::InvalidKeyFormat);
            }
            Ed25519KeyPair::from_seed_and_public_key(&combined[..32], public)
                .map_err(|_| SshPrivateKeyError::InvalidKeyFormat)?;
            Ok(SshBasePrivateKey::Ed(PrivateKey::from_ed_encoded_components(
                NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(),
                &combined[..32],
                Some(public),
            )))
        }

        unsupported => Err(SshPrivateKeyError::UnsupportedKeyType(unsupported.to_owned())),
    }
}

fn validate_rsa_component_sizes(
    modulus: &[u8],
    public_exponent: &[u8],
    private_exponent: &[u8],
    coefficient: &[u8],
    prime_1: &[u8],
    prime_2: &[u8],
) -> Result<(), SshPrivateKeyError> {
    let modulus_len = trim_unsigned(modulus).len();
    if !matches!(modulus_len, 256 | 384 | 512 | 1024)
        || public_exponent.is_empty()
        || public_exponent.len() > 5
        || private_exponent.is_empty()
        || private_exponent.len() > modulus_len
        || coefficient.is_empty()
        || coefficient.len() > modulus_len
        || prime_1.is_empty()
        || prime_1.len() > modulus_len / 2 + 1
        || prime_2.is_empty()
        || prime_2.len() > modulus_len / 2 + 1
    {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    Ok(())
}

fn encode_private_key(key: &SshBasePrivateKey, output: &mut Vec<u8>) -> Result<(), SshPrivateKeyError> {
    match key {
        SshBasePrivateKey::Rsa(key) => {
            let PrivateKeyValue::Rsa(key) = &key.as_inner().private_key else {
                return Err(SshPrivateKeyError::InvalidKeyFormat);
            };
            let key = &key.0;
            write_string(output, "ssh-rsa")?;
            write_mpint(output, key.modulus.as_unsigned_bytes_be())?;
            write_mpint(output, key.public_exponent.as_unsigned_bytes_be())?;
            write_mpint(output, key.private_exponent.as_unsigned_bytes_be())?;
            write_mpint(output, key.coefficient.as_unsigned_bytes_be())?;
            write_mpint(output, key.prime_1.as_unsigned_bytes_be())?;
            write_mpint(output, key.prime_2.as_unsigned_bytes_be())?;
        }
        SshBasePrivateKey::Ec(key) => {
            let key = EcdsaKeypair::try_from(key)?;
            let public = EcdsaPublicKey::try_from(&key)?;
            let (key_type, identifier) = match key.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => ("ecdsa-sha2-nistp256", "nistp256"),
                NamedEcCurve::Known(EcCurve::NistP384) => ("ecdsa-sha2-nistp384", "nistp384"),
                NamedEcCurve::Known(EcCurve::NistP521) => ("ecdsa-sha2-nistp521", "nistp521"),
                _ => return Err(SshPrivateKeyError::InvalidKeyFormat),
            };
            write_string(output, key_type)?;
            write_string(output, identifier)?;
            write_bytes(output, public.encoded_point())?;
            write_mpint(output, key.secret())?;
        }
        SshBasePrivateKey::Ed(key) => {
            let key = EdKeypair::try_from(key)?;
            let public = EdPublicKey::try_from(&key)?;
            if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) {
                return Err(SshPrivateKeyError::InvalidKeyFormat);
            }
            write_string(output, "ssh-ed25519")?;
            write_bytes(output, public.data())?;
            let mut combined = key.secret().to_vec();
            combined.extend_from_slice(public.data());
            write_bytes(output, &combined)?;
        }
    }
    Ok(())
}

fn validate_padding(padding: &[u8]) -> Result<(), SshPrivateKeyError> {
    if padding.is_empty() || padding.len() > 8 {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    if padding.iter().copied().eq((1..=padding.len()).map(|value| value as u8)) {
        Ok(())
    } else {
        Err(SshPrivateKeyError::InvalidKeyFormat)
    }
}

fn subtract_one(value: &[u8]) -> Result<Vec<u8>, SshPrivateKeyError> {
    let mut value = trim_unsigned(value).to_vec();
    if value.is_empty() {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    for byte in value.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            return Ok(trim_unsigned(&value).to_vec());
        }
        *byte = 0xff;
    }
    Err(SshPrivateKeyError::InvalidKeyFormat)
}

fn modulo(value: &[u8], divisor: &[u8]) -> Result<Vec<u8>, SshPrivateKeyError> {
    let divisor = trim_unsigned(divisor);
    if divisor.is_empty() {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    let mut remainder = Vec::new();
    for byte in trim_unsigned(value) {
        for bit in (0..8).rev() {
            shift_left_add(&mut remainder, (byte >> bit) & 1);
            if compare_unsigned(&remainder, divisor) != std::cmp::Ordering::Less {
                subtract_assign(&mut remainder, divisor);
            }
        }
    }
    Ok(remainder)
}

fn shift_left_add(value: &mut Vec<u8>, bit: u8) {
    let mut carry = bit;
    for byte in value.iter_mut().rev() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        value.insert(0, carry);
    } else if value.is_empty() && bit != 0 {
        value.push(bit);
    }
}

fn compare_unsigned(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    let left = trim_unsigned(left);
    let right = trim_unsigned(right);
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn subtract_assign(left: &mut Vec<u8>, right: &[u8]) {
    let mut borrow = 0i16;
    for offset in 0..left.len() {
        let li = left.len() - 1 - offset;
        let rhs = right
            .len()
            .checked_sub(offset + 1)
            .map(|index| right[index] as i16)
            .unwrap_or(0);
        let result = left[li] as i16 - rhs - borrow;
        if result < 0 {
            left[li] = (result + 256) as u8;
            borrow = 1;
        } else {
            left[li] = result as u8;
            borrow = 0;
        }
    }
    let first = left.iter().position(|byte| *byte != 0).unwrap_or(left.len());
    left.drain(..first);
}
