use crate::{AsymmetricEncryptionAlgorithm, KeyAgreementAlgorithm, SignatureAlgorithm};
use std::fmt;

/// Contents of the SPKI subjectPublicKey BIT STRING in the algorithm's encoding.
/// See CONTRACT.md section 5.1.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey<'a>(
    /// Borrowed bytes in the algorithm's public-key encoding.
    /// See CONTRACT.md section 5.1.
    pub &'a [u8],
);

/// FFDH domain parameters, as unsigned big-endian integers.
/// See CONTRACT.md section 6.11.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct FfdhParameters<'a> {
    /// Group modulus.
    /// See CONTRACT.md section 6.11.
    pub p: &'a [u8],
    /// Subgroup generator.
    /// See CONTRACT.md section 6.11.
    pub g: &'a [u8],
    /// Subgroup order, when known.
    /// See CONTRACT.md section 6.11.
    pub q: Option<&'a [u8]>,
}
impl<'a> FfdhParameters<'a> {
    /// Packages domain parameters without validation.
    /// See CONTRACT.md section 6.11.
    pub fn new(p: &'a [u8], g: &'a [u8], q: Option<&'a [u8]>) -> Self {
        Self { p, g, q }
    }
}

/// Borrowed private material; the caller is responsible for wiping it.
/// Diagnostics disclose only the variant.
/// See CONTRACT.md sections 2 and 5.2.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum PrivateKeyMaterial<'a> {
    /// PKCS#8 DER for RSA, EC or Ed25519.
    /// See CONTRACT.md section 5.2.
    Pkcs8(&'a [u8]),
    /// Raw RFC 7748 scalar.
    /// See CONTRACT.md section 5.2.
    X25519(&'a [u8; 32]),
    /// FFDH parameters and private exponent.
    /// See CONTRACT.md section 6.11.
    Ffdh {
        /// Domain parameters.
        /// See CONTRACT.md section 6.11.
        parameters: FfdhParameters<'a>,
        /// Unsigned big-endian exponent.
        /// See CONTRACT.md section 6.11.
        private_value: &'a [u8],
    },
}
impl fmt::Debug for PrivateKeyMaterial<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Pkcs8(_) => "Pkcs8",
            Self::X25519(_) => "X25519",
            Self::Ffdh { .. } => "Ffdh",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}

/// Private-key availability query.
/// See CONTRACT.md section 7.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// Sign using this algorithm.
    /// See CONTRACT.md section 7.
    Sign(SignatureAlgorithm),
    /// Decrypt using this algorithm.
    /// See CONTRACT.md section 7.
    Decrypt(AsymmetricEncryptionAlgorithm),
    /// Static key agreement using this algorithm.
    /// See CONTRACT.md section 7.
    Agree(KeyAgreementAlgorithm),
    /// Export the public key.
    /// See CONTRACT.md section 7.
    PublicKey,
}
