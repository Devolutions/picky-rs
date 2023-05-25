pub mod certificate;
pub mod decode;
pub mod encode;
pub mod private_key;
pub mod public_key;

pub use certificate::{SshCertKeyType, SshCertType, SshCertificate, SshCertificateBuilder};
pub use private_key::SshPrivateKey;
pub use public_key::SshPublicKey;

use crate::key::{ec::NamedEcCurve, EcCurve, KeyError};
use byteorder::ReadBytesExt;
use std::io::{self, Read};

pub(crate) type Base64Writer<'a, T, E> = base64::write::EncoderWriter<'a, T, E>;
pub(crate) type Base64Reader<'a, T, E> = base64::read::DecoderReader<'a, T, E>;

mod key_type {
    pub const SSH_RSA: &str = "ssh-rsa";
    pub const ECDSA_SHA2_NIST_P256: &str = "ecdsa-sha2-nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "ecdsa-sha2-nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "ecdsa-sha2-nistp521";
}

mod key_identifier {
    pub const ECDSA_SHA2_NIST_P256: &str = "nistp256";
    pub const ECDSA_SHA2_NIST_P384: &str = "nistp384";
    pub const ECDSA_SHA2_NIST_P521: &str = "nistp521";
}

trait EcCurveSshExt {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError>;
    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError>;
}

impl EcCurveSshExt for NamedEcCurve {
    fn to_ecdsa_ssh_key_type(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_type::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_type::ECDSA_SHA2_NIST_P384),
            // Special handling: we don't support any arithmetic on P521, but we at least
            // should be able to read and write it back correctly.
            NamedEcCurve::Unsupported(_) if self.is_nist_p521() => Ok(key_type::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key type serialization")),
        }
    }

    fn to_ecdsa_ssh_key_identifier(&self) -> Result<&'static str, KeyError> {
        match self {
            NamedEcCurve::Known(EcCurve::NistP256) => Ok(key_identifier::ECDSA_SHA2_NIST_P256),
            NamedEcCurve::Known(EcCurve::NistP384) => Ok(key_identifier::ECDSA_SHA2_NIST_P384),
            // See comment inside function above
            NamedEcCurve::Unsupported(_) if self.is_nist_p521() => Ok(key_identifier::ECDSA_SHA2_NIST_P521),
            NamedEcCurve::Unsupported(oid) => Err(KeyError::unsupported_curve(oid, "ssh key identifier serialization")),
        }
    }
}

fn read_to_buffer_until_whitespace(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
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
