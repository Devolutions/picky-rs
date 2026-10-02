#[cfg(not(feature = "fips"))]
pub mod certificate;
#[cfg(not(feature = "fips"))]
pub mod decode;
#[cfg(not(feature = "fips"))]
pub mod encode;
#[cfg(not(feature = "fips"))]
pub mod private_key;
#[cfg(not(feature = "fips"))]
pub mod public_key;
#[cfg(feature = "fips")]
#[path = "public_key_fips.rs"]
pub mod public_key;

#[cfg(not(feature = "fips"))]
use crate::key::ec::NamedEcCurve;
#[cfg(not(feature = "fips"))]
use crate::key::ed::NamedEdAlgorithm;
#[cfg(not(feature = "fips"))]
use crate::key::{EcCurve, EdAlgorithm, KeyError};

#[cfg(not(feature = "fips"))]
use byteorder::ReadBytesExt;
#[cfg(not(feature = "fips"))]
use std::io::{self, Read};

#[cfg(not(feature = "fips"))]
pub use certificate::{SshCertKeyType, SshCertType, SshCertificate, SshCertificateBuilder};
#[cfg(not(feature = "fips"))]
pub use private_key::SshPrivateKey;
pub use public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};

#[cfg(not(feature = "fips"))]
pub(crate) type Base64Writer<'a, T, E> = base64::write::EncoderWriter<'a, T, E>;
#[cfg(not(feature = "fips"))]
pub(crate) type Base64Reader<'a, T, E> = base64::read::DecoderReader<'a, T, E>;

#[cfg(not(feature = "fips"))]
const SSH_COMBO_ED25519_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH;

#[cfg(not(feature = "fips"))]
mod key_type {
    pub const RSA: &str = "ssh-rsa";
    pub const ECDSA_SHA2_NIST_P256: &str = "ecdsa-sha2-nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "ecdsa-sha2-nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "ecdsa-sha2-nistp521";
    pub const ED25519: &str = "ssh-ed25519";
    pub const SK_ECDSA_SHA2_NIST_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
    pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
}

#[cfg(not(feature = "fips"))]
mod key_identifier {
    pub const ECDSA_SHA2_NIST_P256: &str = "nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "nistp521";
}

#[cfg(not(feature = "fips"))]
trait EcCurveSshExt {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError>;
    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError>;
}

#[cfg(not(feature = "fips"))]
impl EcCurveSshExt for NamedEcCurve {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_type::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_type::ECDSA_SHA2_NIST_P384),
            NamedEcCurve::Known(EcCurve::NistP521) => Ok(key_type::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key type serialization")),
        }
    }

    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_identifier::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_identifier::ECDSA_SHA2_NIST_P384),
            NamedEcCurve::Known(EcCurve::NistP521) => Ok(key_identifier::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key identifier serialization")),
        }
    }
}

#[cfg(not(feature = "fips"))]
trait EdAlgorithmSshExt {
    fn to_ed_ssh_key_type(&self) -> Result<&'static str, KeyError>;
}

#[cfg(not(feature = "fips"))]
impl EdAlgorithmSshExt for NamedEdAlgorithm {
    fn to_ed_ssh_key_type(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => Ok(key_type::ED25519),
            NamedEdAlgorithm::Known(EdAlgorithm::X25519) => Err(KeyError::UnsupportedAlgorithm {
                algorithm: "X25519 can't be use for SSH EdDSA keys",
            }),
            NamedEdAlgorithm::Unsupported(oid) => {
                Err(KeyError::unsupported_ed_algorithm(oid, "ssh key type serialization"))
            }
        }
    }
}

#[cfg(not(feature = "fips"))]
fn read_until_whitespace(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
    loop {
        match stream.read_u8() {
            Ok(symbol) => {
                if symbol as char == ' ' {
                    break;
                } else {
                    buffer.push(symbol);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        };
    }

    Ok(())
}

#[cfg(not(feature = "fips"))]
fn read_until_linebreak(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
    loop {
        match stream.read_u8() {
            Ok(b'\r') | Ok(b'\n') => break,
            Ok(c) => buffer.push(c),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}
