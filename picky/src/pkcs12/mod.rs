//! This module provides types for parsing and building PKCS#12 files (PFX).
//!
//! # PFX file structure
//! PFX files are constructed from `safe contents` on the highest level, which are containers for
//! various types of `safe bags`. They could be encrypted or not and contain one or more `safe bags`.
//!
//! `Safe bags` are polymorphic containers for various types of data, such as private keys, certificates,
//! custom data (`secrets`), CRLs, etc. They could also be nested, which means that one `safe bag` could
//! contain multiple `safe bags` inside, making it possible to represent complex tree-like structures.
//!
//! Each `safe bag` could also contain `attributes`, which are key-value pairs of various types of data.
//! High-level API defines only `friendly name` and `local key id` attributes, but it is possible to
//! parse/build any custom attributes as well.
//!
//! There are also special `safe bags` called `shrouded key bags`, which are basically encrypted
//! PKCS8 private keys. Encryption on `safe bag` level is performed to allow PFX files that have
//! unencrypted certificates and encrypted private keys, to be preprocessed by the software without
//! knowing PFX password (e.g. check if PFX contains private key for the certificate or not). Usually
//! relations between contained certificates and private keys are marked with `local key id` attribute
//! which is set to the same value for both certificate and private key.
//!
//! # Parsing
//! Almost any kind of PKCS#12 object specified by [RFC](https://datatracker.ietf.org/doc/html/rfc7292)
//! could be parsed or constructed. However, only the most used PFX types are wrapped in high level
//! convenient API such as private keys, certificates, nested pfx nodes, etc. If parsed
//! data was in fact some rarely used PFX type, it is still possible to access it via low level API
//! via `.inner()` method usually returns ASN.1 DER encoded data (`picky-asn1-x509` crate types).
//!
//! Parsing process could be controlled even more with [`Pkcs12ParsingParams`], which allows to skip
//! some parsing errors (e.g. Skip failed mapping of private key ASN.1 structure to high-level picky
//! wrapper)
//!
//! Parsing of PFX file is simple as calling [`Pfx::from_der`] method with required params
//! (crypto context which holds PFX password, parsing params and data itself), after which its safe
//! bags could be inspected and data extracted from PFX.
//!
//! # Building
//! Building process of PFX files is down-to-top, in contrast to parsing. It starts with
//! building of required safe bags/attributes structures, wrapping them inside safe contents
//! (encrypted or unencrypted) and then wrapping them in PFX structure. This allows to keep API
//! flexible while representing Pfx file both after parsing and building as the same type ([`Pfx])
//!
//! # Encryption
//! - It is advised to always use Pbes2 AES-based encryption for PFX files. The only use case for new
//! PFX files with Pbes1 encryption is to support legacy software that does not support Pbes2.
//! - Usually PFX files without passwords are actually encrypted with empty-string passwords if
//! generated by modern software by default. (e.g. certmgr or OpenSSL). However, it is possible to
//! create PFX files without any encryption and MAC in picky if PFX will be used just as a plain
//! container for certificates and private keys and stored somewhere securely (e.g. wrapped in
//! another encryption layer).

mod attribute;
mod encryption;
mod mac;
mod pbkdf1;
mod safe_bag;
mod safe_contents;

use picky_asn1::restricted_string::CharSetError;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::pkcs12::{
    AuthenticatedSafeContentInfo as AuthenticatedSafeContentInfoAsn1,
    ParsedAuthenticatedSafeDataRepr as ParsedAuthenticatedSafeDataReprAsn1, Pbkdf2Prf as Pbkdf2PrfAsn1, Pfx as PfxAsn1,
    Pkcs12DigestAlgorithm as Pkcs12DigestAlgorithmAsn1,
    RawAuthenticatedSafeContentInfo as RawAuthenticatedSafeContentInfoAsn1, RawPfx as RawPfxAsn1,
    SafeContentsContentInfo as SafeContentsContentInfoAsn1,
};
use picky_asn1_x509::{oid::ObjectIdentifier, pkcs12::Pkcs12DigestAlgorithm};
use std::fmt::Display;
use thiserror::Error;

pub(crate) use pbkdf1::{pbkdf1, Pbkdf1Usage};

pub use attribute::{CustomPkcs12Attribute, Pkcs12Attribute};
pub use encryption::{
    Pbes1Cipher, Pbes1Encryption, Pbes2Cipher, Pbes2Encryption, Pkcs12CryptoContext, Pkcs12Encryption,
    Pkcs12EncryptionKind,
};
pub use mac::{Pkcs12MacAlgorithm, Pkcs12MacAlgorithmHmac, Pkcs12MacData, Pkcs12MacError};
pub use safe_bag::{SafeBag, SafeBagKind, SecretSafeBag};
pub use safe_contents::{SafeContents, SafeContentsKind};

const PFX_VERSION: u8 = 3;

/// Parsed PFX (PKCS12 archive). See module docs for more info on PFX file structure and API usage.
#[derive(Debug)]
pub struct Pfx {
    safe_contents: Vec<SafeContents>,
    mac_data: Option<Pkcs12MacData>,
    /// Pre-serialized auth safe data. Just an optimization to avoid re-serializing the auth safe
    /// data if it was already serialized for the MAC calculation.
    auth_safe_data: Option<Vec<u8>>,
}

impl Pfx {
    /// Create new PFX file with HMAC MAC algorithm. Usually this is the default in modern software
    pub fn new_with_hmac(
        safe_contents: Vec<SafeContents>,
        mac: Pkcs12MacAlgorithmHmac,
        crypto_context: &mut Pkcs12CryptoContext,
    ) -> Result<Self, Pkcs12Error> {
        let safe_contents_asn1 = safe_contents.iter().map(|sc| sc.inner().clone()).collect::<Vec<_>>();

        let serialized_auth_safe = picky_asn1_der::to_vec(&safe_contents_asn1)?;
        let mac_data = Pkcs12MacData::new_hmac(mac, crypto_context, &serialized_auth_safe)?;

        Ok(Self {
            safe_contents,
            mac_data: Some(mac_data),
            auth_safe_data: Some(serialized_auth_safe),
        })
    }

    /// Create new PFX file without MAC algorithm if needed for some reason (e.g. MAC is performed
    /// on the higher level)
    pub fn new_without_mac(safe_contents: Vec<SafeContents>) -> Self {
        Self {
            safe_contents,
            mac_data: None,
            auth_safe_data: None,
        }
    }

    /// Serialize PFX file to DER bytes
    pub fn to_der(&self) -> Result<Vec<u8>, Pkcs12Error> {
        match &self.auth_safe_data {
            Some(auth_safe) => {
                let pfx_asn1 = RawPfxAsn1 {
                    version: PFX_VERSION,
                    auth_safe: RawAuthenticatedSafeContentInfoAsn1::Data(Asn1RawDer(auth_safe.clone())),
                    mac_data: self.mac_data.as_ref().map(|mac_data| mac_data.inner().clone()),
                };

                picky_asn1_der::to_vec(&pfx_asn1).map_err(Into::into)
            }
            None => {
                let pfx_asn1 = PfxAsn1 {
                    version: PFX_VERSION,
                    auth_safe: AuthenticatedSafeContentInfoAsn1::<ParsedAuthenticatedSafeDataReprAsn1>::Data(
                        self.safe_contents
                            .iter()
                            .map(|sc| sc.inner().clone())
                            .collect::<Vec<_>>(),
                    ),
                    mac_data: self.mac_data.as_ref().map(|mac_data| mac_data.inner().clone()),
                };

                picky_asn1_der::to_vec(&pfx_asn1).map_err(Into::into)
            }
        }
    }

    /// Parses a PKCS12 archive (PFX) from its DER representation.
    pub fn from_der(
        data: &[u8],
        crypto_context: Pkcs12CryptoContext,
        parsing_params: Pkcs12ParsingParams,
    ) -> Result<Self, Pkcs12Error> {
        let (auth_safe, mac_data) = if parsing_params.skip_mac_validation {
            let pfx_asn1: PfxAsn1 = picky_asn1_der::from_bytes(data)?;
            if pfx_asn1.version != PFX_VERSION {
                return Err(Pkcs12Error::InvalidVersion(pfx_asn1.version));
            }
            let mac_data = pfx_asn1
                .mac_data
                .map(|asn1| Pkcs12MacData::from_asn1(asn1, true))
                .transpose()?;

            let auth_safe = match pfx_asn1.auth_safe {
                AuthenticatedSafeContentInfoAsn1::Data(data) => data,
                AuthenticatedSafeContentInfoAsn1::Unknown { content_type, .. } => {
                    return Err(Pkcs12Error::InvalidAuthenticatedSafeContentType(content_type.into()));
                }
            };

            (auth_safe, mac_data)
        } else {
            let pfx_asn1: RawPfxAsn1 = picky_asn1_der::from_bytes(data)?;
            if pfx_asn1.version != PFX_VERSION {
                return Err(Pkcs12Error::InvalidVersion(pfx_asn1.version));
            }

            let mac_data = pfx_asn1
                .mac_data
                .map(|asn1| Pkcs12MacData::from_asn1(asn1, false))
                .transpose()?;

            let auth_safe = match pfx_asn1.auth_safe {
                AuthenticatedSafeContentInfoAsn1::Data(data) => {
                    if let Some(mac_data) = &mac_data {
                        mac_data.validate(&crypto_context, data.0.as_slice())?;
                    }

                    let parsed: Vec<SafeContentsContentInfoAsn1> = picky_asn1_der::from_bytes(data.0.as_slice())?;
                    parsed
                }
                AuthenticatedSafeContentInfoAsn1::Unknown { content_type, .. } => {
                    return Err(Pkcs12Error::InvalidAuthenticatedSafeContentType(content_type.into()));
                }
            };

            (auth_safe, mac_data)
        };

        auth_safe
            .into_iter()
            .map(|safe_contents| SafeContents::from_asn1(safe_contents, &crypto_context, &parsing_params))
            .collect::<Result<Vec<_>, _>>()
            .map(|safe_contents| Self {
                safe_contents,
                mac_data,
                auth_safe_data: None,
            })
    }

    /// Inspect parsed PFX data
    pub fn safe_contents(&self) -> &[SafeContents] {
        &self.safe_contents
    }

    /// Inspect parsed MAC data
    pub fn mac_data(&self) -> Option<&Pkcs12MacData> {
        self.mac_data.as_ref()
    }
}

/// Parameters which control some aspects of PFX file parsing process
#[derive(Debug, Default)]
pub struct Pkcs12ParsingParams {
    /// Continue parsing if conversion to high level picky data structure fails (e.g. due to
    /// unsupported private key or certificate kind)
    pub skip_soft_parsing_errors: bool,
    /// Continue parsing if decryption fails and keep data in encrypted form
    pub skip_decryption_errors: bool,
    /// Continue parsing if MAC validation fails. Useful for parsing available unecrypted data from
    /// password-protected PFX files. Also could be useful if PFX integrity has been intentionally
    /// violated for testing purposes.
    pub skip_mac_validation: bool,
}

/// Hashing algorithm used for MAC or KDF in PFX file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs12HashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Pkcs12HashAlgorithm {
    pub(crate) fn pbkdf1_u_bits(self) -> usize {
        match self {
            Self::Sha1 => 160,
            Self::Sha224 => 224,
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    pub(crate) fn pbkdf1_v_bits(self) -> usize {
        match self {
            Self::Sha1 => 512,
            Self::Sha224 => 512,
            Self::Sha256 => 512,
            Self::Sha384 => 1024,
            Self::Sha512 => 1024,
        }
    }

    pub(crate) fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub(crate) fn from_asn1_pbkdf2_prf(value: &Pbkdf2PrfAsn1) -> Result<Self, Pkcs12Error> {
        let algorithm = match value {
            Pbkdf2PrfAsn1::HmacWithSha1 => Pkcs12HashAlgorithm::Sha1,
            Pbkdf2PrfAsn1::HmacWithSha224 => Pkcs12HashAlgorithm::Sha224,
            Pbkdf2PrfAsn1::HmacWithSha256 => Pkcs12HashAlgorithm::Sha256,
            Pbkdf2PrfAsn1::HmacWithSha384 => Pkcs12HashAlgorithm::Sha384,
            Pbkdf2PrfAsn1::HmacWithSha512 => Pkcs12HashAlgorithm::Sha512,
            Pbkdf2PrfAsn1::Unknown(raw) => {
                let oid = raw.algorithm().clone();
                return Err(Pkcs12Error::NotSupportedAlgorithm {
                    algorithm: UnsupportedPkcs12Algorithm::Oid(oid),
                    context: "Crypto operation (pbkdf2 prf algorithm)".to_string(),
                });
            }
        };

        Ok(algorithm)
    }

    pub(crate) fn from_asn1_digest_algorithm(value: &Pkcs12DigestAlgorithmAsn1) -> Result<Self, Pkcs12Error> {
        let algorithm = match value {
            Pkcs12DigestAlgorithm::Sha1 => Pkcs12HashAlgorithm::Sha1,
            Pkcs12DigestAlgorithm::Sha224 => Pkcs12HashAlgorithm::Sha224,
            Pkcs12DigestAlgorithm::Sha256 => Pkcs12HashAlgorithm::Sha256,
            Pkcs12DigestAlgorithm::Sha384 => Pkcs12HashAlgorithm::Sha384,
            Pkcs12DigestAlgorithm::Sha512 => Pkcs12HashAlgorithm::Sha512,
            Pkcs12DigestAlgorithm::Unknown(raw) => {
                let oid = raw.algorithm().clone();
                return Err(Pkcs12Error::NotSupportedAlgorithm {
                    algorithm: UnsupportedPkcs12Algorithm::Oid(oid),
                    context: "MAC calculation (pbkdf1 prf algorithm)".to_string(),
                });
            }
        };

        Ok(algorithm)
    }
}

impl From<Pkcs12HashAlgorithm> for Pkcs12DigestAlgorithm {
    fn from(value: Pkcs12HashAlgorithm) -> Self {
        match value {
            Pkcs12HashAlgorithm::Sha1 => Self::Sha1,
            Pkcs12HashAlgorithm::Sha224 => Self::Sha224,
            Pkcs12HashAlgorithm::Sha256 => Self::Sha256,
            Pkcs12HashAlgorithm::Sha384 => Self::Sha384,
            Pkcs12HashAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Debug, Error)]
pub enum Pkcs12Error {
    #[error("Not supported algorithm `{algorithm}` in context of {context}")]
    NotSupportedAlgorithm {
        algorithm: UnsupportedPkcs12Algorithm,
        context: String,
    },
    #[error("Failed to perform PBES1 crypto operation: {context}")]
    Pbes1 { context: String },
    #[error("Failed to perform PBES2 crypto operation: {context}")]
    Pbes2 { context: String },
    #[error(transparent)]
    CharSet(#[from] CharSetError),
    #[error(transparent)]
    Mac(#[from] mac::Pkcs12MacError),
    #[error("Invalid ASN.1 DER encoding")]
    Asn1Der(#[from] picky_asn1_der::Asn1DerError),
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
    #[error(transparent)]
    Certificate(#[from] crate::x509::certificate::CertError),
    #[error("Not supported or invalid PFX version: {0}")]
    InvalidVersion(u8),
    #[error("Invalid PFX AuthenticatedSafe content type: {0}")]
    InvalidAuthenticatedSafeContentType(UnsupportedPkcs12Algorithm),
    #[error("Unexpected attribute values count. Expected: `{expected}`, got: `{actual}`")]
    UnexpectedAttributeValuesCount { expected: usize, actual: usize },
}

#[derive(Debug, Clone)]
pub enum UnsupportedPkcs12Algorithm {
    Named(&'static str),
    Oid(ObjectIdentifier),
}

impl From<&'static str> for UnsupportedPkcs12Algorithm {
    fn from(name: &'static str) -> Self {
        Self::Named(name)
    }
}

impl From<ObjectIdentifier> for UnsupportedPkcs12Algorithm {
    fn from(oid: ObjectIdentifier) -> Self {
        Self::Oid(oid)
    }
}

impl Display for UnsupportedPkcs12Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnsupportedPkcs12Algorithm::Named(name) => f.write_str(name),
            UnsupportedPkcs12Algorithm::Oid(oid) => {
                write!(f, "OID({})", format_oid(oid))
            }
        }
    }
}

impl Pkcs12Error {
    pub fn unsupported_algorithm(algorithm: impl Into<UnsupportedPkcs12Algorithm>, context: impl Into<String>) -> Self {
        Self::NotSupportedAlgorithm {
            algorithm: algorithm.into(),
            context: context.into(),
        }
    }
}

fn format_oid(oid: &ObjectIdentifier) -> String {
    let oid_str: String = oid.clone().into();
    format!("OID({})", oid_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key::PrivateKey, pem::Pem};
    use rstest::rstest;

    #[test]
    fn pfx_certmgr_aes256() {
        let encoded = include_bytes!("../../../test_assets/pkcs12/certmgr_aes256.pfx");
        let crypto_context = Pkcs12CryptoContext::new_with_password("test");
        let _decoded = Pfx::from_der(encoded, crypto_context, Pkcs12ParsingParams::default()).unwrap();
    }

    #[test]
    fn pfx_certmgr_3des() {
        let encoded = include_bytes!("../../../test_assets/pkcs12/certmgr_3des.pfx");
        let crypto_context = Pkcs12CryptoContext::new_with_password("test");
        let _decoded = Pfx::from_der(encoded, crypto_context, Pkcs12ParsingParams::default()).unwrap();
    }

    #[test]
    fn pfx_certmgr_rc2() {
        let encoded = include_bytes!("../../../test_assets/pkcs12/leaf_password_is_abc.pfx");
        let crypto_context = Pkcs12CryptoContext::new_with_password("abc");
        let _decoded = Pfx::from_der(encoded, crypto_context, Pkcs12ParsingParams::default()).unwrap();
    }

    #[test]
    fn pfx_certmgr_rc2_empty_pass() {
        let encoded = include_bytes!("../../../test_assets/pkcs12/leaf_empty_password.pfx");
        let crypto_context = Pkcs12CryptoContext::new_without_password();
        let _decoded = Pfx::from_der(encoded, crypto_context, Pkcs12ParsingParams::default()).unwrap();
    }

    #[test]
    fn pfx_openssl_aes_empty_pass() {
        let encoded = include_bytes!("../../../test_assets/pkcs12/openssl_nocrypt.pfx");
        let crypto_context = Pkcs12CryptoContext::new_without_password();
        let _decoded = Pfx::from_der(encoded, crypto_context, Pkcs12ParsingParams::default()).unwrap();
    }

    fn stable_rand() -> impl rand::RngCore + rand::CryptoRng {
        use rand::SeedableRng;
        rand_chacha::ChaChaRng::seed_from_u64(42)
    }

    fn build_cert_bags() -> [SafeBag; 3] {
        let leaf = crate::x509::Cert::from_der(include_bytes!("../../../test_assets/pkcs12/asset_leaf.crt")).unwrap();
        let intermediate =
            crate::x509::Cert::from_der(include_bytes!("../../../test_assets/pkcs12/asset_intermediate.crt")).unwrap();
        let root = crate::x509::Cert::from_der(include_bytes!("../../../test_assets/pkcs12/asset_root.crt")).unwrap();

        let leaf_cert_bag = SafeBag::new_certificate(leaf, build_leaf_attributes()).unwrap();

        let intermediate_cert_bag = SafeBag::new_certificate(
            intermediate,
            vec![Pkcs12Attribute::new_friendly_name(
                "PICKY_INTERMEDIATE".parse().unwrap(),
            )],
        )
        .unwrap();

        let root_cert_bag = SafeBag::new_certificate(
            root,
            vec![Pkcs12Attribute::new_friendly_name("PICKY_ROOT".parse().unwrap())],
        )
        .unwrap();

        [leaf_cert_bag, intermediate_cert_bag, root_cert_bag]
    }

    fn build_leaf_attributes() -> Vec<Pkcs12Attribute> {
        vec![
            Pkcs12Attribute::new_local_key_id([0x01, 0x00, 0x00, 0x00]),
            Pkcs12Attribute::new_friendly_name("PICKY_LEAF".parse().unwrap()),
        ]
    }

    fn make_crypto_context(password: Option<&str>) -> Pkcs12CryptoContext {
        if let Some(password) = password {
            Pkcs12CryptoContext::new_with_password(password).with_rng(stable_rand())
        } else {
            Pkcs12CryptoContext::new_without_password().with_rng(stable_rand())
        }
    }

    fn validate_pfx(der_data: &[u8], password: Option<&str>) {
        let crypto_context = make_crypto_context(password);

        // Check that we can decode PFX encoded by picky itself
        let _decoded = Pfx::from_der(der_data, crypto_context, Pkcs12ParsingParams::default()).unwrap();

        #[cfg(windows)]
        {
            let temp_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();

            std::fs::write(&temp_path, der_data).unwrap();

            let certutil_args = vec![
                "-dump".to_string(),
                "-p".to_string(),
                password.unwrap_or("").to_string(),
                temp_path.to_str().unwrap().to_string(),
            ];

            let certutil_output = std::process::Command::new("certutil")
                .args(certutil_args)
                .output()
                .unwrap();

            assert!(
                certutil_output.status.success(),
                "certutil failed: {}",
                String::from_utf8_lossy(&certutil_output.stdout)
            );
        }
    }

    fn encryption_3des(crypto_context: &mut Pkcs12CryptoContext) -> Pkcs12Encryption {
        Pkcs12Encryption::new_pbes1(Pbes1Encryption::new(Pbes1Cipher::ShaAnd3Key3DesCbc), crypto_context)
    }

    fn encryption_rc2(crypto_context: &mut Pkcs12CryptoContext) -> Pkcs12Encryption {
        Pkcs12Encryption::new_pbes1(Pbes1Encryption::new(Pbes1Cipher::ShaAnd40BitRc2Cbc), crypto_context)
    }

    fn encryption_aes256(crypto_context: &mut Pkcs12CryptoContext) -> Pkcs12Encryption {
        Pkcs12Encryption::new_pbes2(
            Pbes2Encryption::new(Pbes2Cipher::Aes256Cbc, Pkcs12HashAlgorithm::Sha256),
            crypto_context,
        )
    }

    pub fn leaf_private_key_rsa() -> PrivateKey {
        let pem = crate::test_files::RSA_2048_PK_3.parse::<Pem>().unwrap();
        PrivateKey::from_pkcs8(pem.data()).unwrap()
    }

    type EncryptionFn = fn(&mut Pkcs12CryptoContext) -> Pkcs12Encryption;

    #[rstest]
    #[case(encryption_3des, Some("test"), Pkcs12HashAlgorithm::Sha1)]
    #[case(encryption_rc2, Some("test"), Pkcs12HashAlgorithm::Sha1)]
    #[case(encryption_aes256, Some("test"), Pkcs12HashAlgorithm::Sha256)]
    #[case(encryption_3des, None, Pkcs12HashAlgorithm::Sha1)]
    // RC2 uses same KDF as 3DES so we could skip case of RC2 without password
    #[case(encryption_aes256, None, Pkcs12HashAlgorithm::Sha256)]
    fn build_pfx_encrypted(
        #[case] encryption_fn: EncryptionFn,
        #[case] password: Option<&'static str>,
        #[case] hmac_algorithm: Pkcs12HashAlgorithm,
    ) {
        let leaf_key = leaf_private_key_rsa();

        let [leaf_cert_bag, intermediate_cert_bag, root_cert_bag] = build_cert_bags();

        let mut crypto_context = make_crypto_context(password);

        let key_encryption = encryption_fn(&mut crypto_context);

        let leaf_key_bag =
            SafeBag::new_encrypted_key(leaf_key, build_leaf_attributes(), key_encryption, &crypto_context).unwrap();

        let cert_encryption = encryption_fn(&mut crypto_context);

        let cert_safe_contents = SafeContents::new_encrypted(
            vec![leaf_cert_bag, intermediate_cert_bag, root_cert_bag],
            cert_encryption,
            &crypto_context,
        )
        .unwrap();

        let key_safe_contents = SafeContents::new(vec![leaf_key_bag]);

        let secret_safe_bag = SafeBag::new_secret(
            SecretSafeBag::new(picky_asn1_x509::oids::content_info_type_data(), &42u8).unwrap(),
            vec![Pkcs12Attribute::new_custom(
                CustomPkcs12Attribute::new_single_value(picky_asn1_x509::oids::content_info_type_data(), &256u64)
                    .unwrap(),
            )],
        );

        let secret_safe_contents = SafeContents::new(vec![secret_safe_bag]);

        let pfx = Pfx::new_with_hmac(
            vec![cert_safe_contents, key_safe_contents, secret_safe_contents],
            Pkcs12MacAlgorithmHmac::new(hmac_algorithm),
            &mut crypto_context,
        )
        .unwrap();

        let der_data = pfx.to_der().unwrap();

        validate_pfx(&der_data, password);
    }
}
