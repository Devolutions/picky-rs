//! JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
//!
//! See [RFC7516](https://tools.ietf.org/html/rfc7516).

use crate::{
    jose::jwk::Jwk,
    key::{PrivateKey, PublicKey},
};
use aes_gcm::{aead::generic_array::typenum::Unsigned, AeadInPlace, Aes128Gcm, Aes256Gcm, NewAead};
use base64::DecodeError;
use digest::generic_array::GenericArray;
use rand::RngCore;
use rsa::{PaddingScheme, PublicKey as RsaPublicKeyInterface, RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, convert::TryFrom};
use thiserror::Error;

type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::generic_array::typenum::U12>;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JweError {
    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// AES-GCM error (opaque)
    #[error("AES-GCM error (opaque)")]
    AesGcm,

    /// Json error
    #[error("JSON error: {source}")]
    Json { source: serde_json::Error },

    /// Key error
    #[error("Key error: {source}")]
    Key { source: crate::key::KeyError },

    /// Invalid token encoding
    #[error("input isn't a valid token string: {input}")]
    InvalidEncoding { input: String },

    /// Couldn't decode base64
    #[error("couldn't decode base64: {source}")]
    Base64Decoding { source: DecodeError },

    /// Input isn't valid utf8
    #[error("input isn't valid utf8: {source}, input: {input:?}")]
    InvalidUtf8 {
        source: std::string::FromUtf8Error,
        input: Vec<u8>,
    },

    /// Unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    /// Invalid size
    #[error("invalid size for {ty}: expected {expected}, got {got}")]
    InvalidSize {
        ty: &'static str,
        expected: usize,
        got: usize,
    },
}

impl From<rsa::errors::Error> for JweError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<aes_gcm::Error> for JweError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::AesGcm
    }
}

impl From<serde_json::Error> for JweError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

impl From<crate::key::KeyError> for JweError {
    fn from(e: crate::key::KeyError) -> Self {
        Self::Key { source: e }
    }
}

impl From<DecodeError> for JweError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

// === JWE algorithms === //

/// `alg` header parameter values for JWE used to determine the Content Encryption Key (CEK)
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #4](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweAlg {
    /// RSAES-PKCS1-V1_5
    ///
    /// Recommended- by RFC
    #[serde(rename = "RSA1_5")]
    RsaPkcs1v15,

    /// RSAES OAEP using default parameters
    ///
    /// Recommended+ by RFC
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with default initial value using 128 bit key (unsupported)
    ///
    /// Recommended by RFC
    #[serde(rename = "A128KW")]
    AesKeyWrap128,

    /// AES Key Wrap with default initial value using 192 bit key (unsupported)
    #[serde(rename = "A192KW")]
    AesKeyWrap192,

    /// AES Key Wrap with default initial value using 256 bit key (unsupported)
    ///
    /// Recommended by RFC
    #[serde(rename = "A256KW")]
    AesKeyWrap256,

    /// Direct use of a shared symmetric key as the CEK
    #[serde(rename = "dir")]
    Direct,

    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF (unsupported)
    ///
    /// Recommended+ by RFC
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" (unsupported)
    ///
    /// Recommended by RFC
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsAesKeyWrap128,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" (unsupported)
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsAesKeyWrap192,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" (unsupported)
    ///
    /// Recommended by RFC
    ///
    /// Additional header used: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsAesKeyWrap256,
}

// === JWE header === //

/// `enc` header parameter values for JWE to encrypt content
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #5](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweEnc {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm. (unsupported)
    ///
    /// Required by RFC
    #[serde(rename = "A128CBC-HS256")]
    Aes128CbcHmacSha256,

    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm. (unsupported)
    #[serde(rename = "A192CBC-HS384")]
    Aes192CbcHmacSha384,

    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm. (unsupported)
    ///
    /// Required by RFC
    #[serde(rename = "A256CBC-HS512")]
    Aes256CbcHmacSha512,

    /// AES GCM using 128-bit key.
    ///
    /// Recommended by RFC
    #[serde(rename = "A128GCM")]
    Aes128Gcm,

    /// AES GCM using 192-bit key.
    #[serde(rename = "A192GCM")]
    Aes192Gcm,

    /// AES GCM using 256-bit key.
    ///
    /// Recommended by RFC
    #[serde(rename = "A256GCM")]
    Aes256Gcm,
}

impl JweEnc {
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128CbcHmacSha256 | Self::Aes128Gcm => <Aes128Gcm as NewAead>::KeySize::to_usize(),
            Self::Aes192CbcHmacSha384 | Self::Aes192Gcm => <Aes192Gcm as NewAead>::KeySize::to_usize(),
            Self::Aes256CbcHmacSha512 | Self::Aes256Gcm => <Aes256Gcm as NewAead>::KeySize::to_usize(),
        }
    }

    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes128CbcHmacSha256 | Self::Aes128Gcm => <Aes128Gcm as AeadInPlace>::NonceSize::to_usize(),
            Self::Aes192CbcHmacSha384 | Self::Aes192Gcm => <Aes192Gcm as AeadInPlace>::NonceSize::to_usize(),
            Self::Aes256CbcHmacSha512 | Self::Aes256Gcm => <Aes256Gcm as AeadInPlace>::NonceSize::to_usize(),
        }
    }

    pub fn tag_size(self) -> usize {
        match self {
            Self::Aes128CbcHmacSha256 | Self::Aes128Gcm => <Aes128Gcm as AeadInPlace>::TagSize::to_usize(),
            Self::Aes192CbcHmacSha384 | Self::Aes192Gcm => <Aes192Gcm as AeadInPlace>::TagSize::to_usize(),
            Self::Aes256CbcHmacSha512 | Self::Aes256Gcm => <Aes256Gcm as AeadInPlace>::TagSize::to_usize(),
        }
    }
}

// === JWE header === //

/// JWE specific part of JOSE header
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JweHeader {
    // -- specific to JWE -- //
    /// Algorithm used to encrypt or determine the Content Encryption Key (CEK) (key wrapping...)
    pub alg: JweAlg,

    /// Content encryption algorithm to use
    ///
    /// This must be a *symmetric* Authenticated Encryption with Associated Data (AEAD) algorithm.
    pub enc: JweEnc,

    // -- common with JWS -- //
    /// JWK Set URL
    ///
    /// URI that refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to digitally sign the JWK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key
    ///
    /// The public key that corresponds to the key used to digitally sign the JWS.
    /// This key is represented as a JSON Web Key (JWK).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// Type header
    ///
    /// Used by JWE applications to declare the media type [IANA.MediaTypes] of this complete JWE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type header
    ///
    /// Used by JWE applications to declare the media type [IANA.MediaTypes] of the secured content (the payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    // -- common with all -- //
    /// Key ID Header
    ///
    /// A hint indicating which key was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL Header
    ///
    /// URI that refers to a resource for an X.509 public key certificate or certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain
    ///
    /// Chain of one or more PKIX certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint
    ///
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint
    ///
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t#S256", alias = "x5t#s256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

impl JweHeader {
    pub fn new(alg: JweAlg, enc: JweEnc) -> Self {
        Self {
            alg,
            enc,
            jku: None,
            jwk: None,
            typ: None,
            cty: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }
}

// === json web encryption === //

/// Provides an API to encrypt any kind of data (binary). JSON claims are part of `Jwt` only.
#[derive(Debug, Clone)]
pub struct Jwe {
    pub header: JweHeader,
    pub payload: Vec<u8>,
}

impl Jwe {
    pub fn new(alg: JweAlg, enc: JweEnc, payload: Vec<u8>) -> Self {
        Self {
            header: JweHeader::new(alg, enc),
            payload,
        }
    }

    /// Encode with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn encode(self, asymmetric_key: &PublicKey) -> Result<String, JweError> {
        encode_impl(self, EncoderMode::Normal(asymmetric_key))
    }

    /// Encode with provided CEK (a symmetric key). This will ignore `alg` value and override it with "dir".
    pub fn encode_direct(self, cek: &[u8]) -> Result<String, JweError> {
        encode_impl(self, EncoderMode::Direct(cek))
    }

    /// Encode with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn decode(encoded_token: &str, key: &PrivateKey) -> Result<Jwe, JweError> {
        decode_impl(encoded_token, DecoderMode::Normal(key))
    }

    /// Decode with provided CEK (a symmetric key).
    pub fn decode_direct(encoded_token: &str, cek: &[u8]) -> Result<Jwe, JweError> {
        decode_impl(encoded_token, DecoderMode::Direct(cek))
    }
}

// encoder

#[derive(Debug, Clone)]
enum EncoderMode<'a> {
    Normal(&'a PublicKey),
    Direct(&'a [u8]),
}

fn encode_impl(jwe: Jwe, mode: EncoderMode) -> Result<String, JweError> {
    let mut header = jwe.header;

    let (encrypted_key_base64, jwe_cek) = match mode {
        EncoderMode::Direct(symmetric_key) => {
            if symmetric_key.len() != header.enc.key_size() {
                return Err(JweError::InvalidSize {
                    ty: "symmetric key",
                    expected: header.enc.key_size(),
                    got: symmetric_key.len(),
                });
            }

            // Override `alg` header with "dir"
            header.alg = JweAlg::Direct;

            (
                base64::encode_config(&[], base64::URL_SAFE_NO_PAD),
                Cow::Borrowed(symmetric_key),
            )
        }
        EncoderMode::Normal(public_key) => {
            // Currently, only rsa is supported
            let rsa_public_key = RSAPublicKey::try_from(public_key)?;

            let mut rng = rand::rngs::OsRng;

            let mut symmetric_key = vec![0u8; header.enc.key_size()];
            rng.fill_bytes(&mut symmetric_key);

            let padding = match header.alg {
                JweAlg::RsaPkcs1v15 => PaddingScheme::new_pkcs1v15_encrypt(),
                JweAlg::RsaOaep => PaddingScheme::new_oaep::<sha1::Sha1>(),
                JweAlg::RsaOaep256 => PaddingScheme::new_oaep::<sha2::Sha256>(),
                unsupported => {
                    return Err(JweError::UnsupportedAlgorithm {
                        algorithm: format!("{:?}", unsupported),
                    })
                }
            };

            let encrypted_key = rsa_public_key.encrypt(&mut rng, padding, &symmetric_key)?;

            (
                base64::encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD),
                Cow::Owned(symmetric_key),
            )
        }
    };

    let mut buffer = jwe.payload;
    let nonce = <aes_gcm::aead::Nonce<_> as From<[u8; 12]>>::from(rand::random()); // 96-bits nonce for AES-GCM
    let aad = b""; // The Additional Authenticated Data value used is the empty octet string for AES-GCM.
    let authentication_tag = match header.enc {
        JweEnc::Aes128Gcm => {
            Aes128Gcm::new(GenericArray::from_slice(&jwe_cek)).encrypt_in_place_detached(&nonce, aad, &mut buffer)?
        }
        JweEnc::Aes192Gcm => {
            Aes192Gcm::new(GenericArray::from_slice(&jwe_cek)).encrypt_in_place_detached(&nonce, aad, &mut buffer)?
        }
        JweEnc::Aes256Gcm => {
            Aes256Gcm::new(GenericArray::from_slice(&jwe_cek)).encrypt_in_place_detached(&nonce, aad, &mut buffer)?
        }
        unsupported => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("{:?}", unsupported),
            })
        }
    };

    let protected_header_base64 = base64::encode_config(&serde_json::to_vec(&header)?, base64::URL_SAFE_NO_PAD);
    let initialization_vector_base64 = base64::encode_config(nonce.as_slice(), base64::URL_SAFE_NO_PAD);
    let ciphertext_base64 = base64::encode_config(&buffer, base64::URL_SAFE_NO_PAD);
    let authentication_tag_base64 = base64::encode_config(&authentication_tag, base64::URL_SAFE_NO_PAD);

    Ok([
        protected_header_base64,
        encrypted_key_base64,
        initialization_vector_base64,
        ciphertext_base64,
        authentication_tag_base64,
    ]
    .join("."))
}

// decoder

#[derive(Debug, Clone)]
enum DecoderMode<'a> {
    Normal(&'a PrivateKey),
    Direct(&'a [u8]),
}

struct Parts {
    protected_header: Vec<u8>,
    encrypted_key: Vec<u8>,
    initialization_vector: Vec<u8>,
    ciphertext: Vec<u8>,
    authentication_tag: Vec<u8>,
}

impl Parts {
    fn break_down(encoded_token: &str) -> Option<Self> {
        let mut split = encoded_token.splitn(5, '.');
        Some(Parts {
            protected_header: base64::decode_config(split.next()?, base64::URL_SAFE_NO_PAD).ok()?,
            encrypted_key: base64::decode_config(split.next()?, base64::URL_SAFE_NO_PAD).ok()?,
            initialization_vector: base64::decode_config(split.next()?, base64::URL_SAFE_NO_PAD).ok()?,
            ciphertext: base64::decode_config(split.next()?, base64::URL_SAFE_NO_PAD).ok()?,
            authentication_tag: base64::decode_config(split.next()?, base64::URL_SAFE_NO_PAD).ok()?,
        })
    }
}

fn decode_impl<'a>(encoded_token: &str, mode: DecoderMode<'a>) -> Result<Jwe, JweError> {
    let parts = Parts::break_down(encoded_token).ok_or_else(|| JweError::InvalidEncoding {
        input: encoded_token.to_owned(),
    })?;

    let header = serde_json::from_slice::<JweHeader>(&parts.protected_header)?;

    let jwe_cek = match mode {
        DecoderMode::Direct(symmetric_key) => Cow::Borrowed(symmetric_key),
        DecoderMode::Normal(private_key) => {
            let rsa_private_key = RSAPrivateKey::try_from(private_key)?;

            let padding = match header.alg {
                JweAlg::RsaPkcs1v15 => PaddingScheme::new_pkcs1v15_encrypt(),
                JweAlg::RsaOaep => PaddingScheme::new_oaep::<sha1::Sha1>(),
                JweAlg::RsaOaep256 => PaddingScheme::new_oaep::<sha2::Sha256>(),
                unsupported => {
                    return Err(JweError::UnsupportedAlgorithm {
                        algorithm: format!("{:?}", unsupported),
                    })
                }
            };

            let decrypted_key = rsa_private_key.decrypt(padding, &parts.encrypted_key)?;

            Cow::Owned(decrypted_key)
        }
    };

    if jwe_cek.len() != header.enc.key_size() {
        return Err(JweError::InvalidSize {
            ty: "symmetric key",
            expected: header.enc.key_size(),
            got: jwe_cek.len(),
        });
    }

    if parts.initialization_vector.len() != header.enc.nonce_size() {
        return Err(JweError::InvalidSize {
            ty: "initialization vector (nonce)",
            expected: header.enc.nonce_size(),
            got: parts.initialization_vector.len(),
        });
    }

    if parts.authentication_tag.len() != header.enc.tag_size() {
        return Err(JweError::InvalidSize {
            ty: "authentication tag",
            expected: header.enc.tag_size(),
            got: parts.authentication_tag.len(),
        });
    }

    let mut buffer = parts.ciphertext;
    let nonce = GenericArray::from_slice(&parts.initialization_vector);
    let aad = b""; // The Additional Authenticated Data value used is the empty octet string for AES-GCM.
    match header.enc {
        JweEnc::Aes128Gcm => Aes128Gcm::new(GenericArray::from_slice(&jwe_cek)).decrypt_in_place_detached(
            &nonce,
            aad,
            &mut buffer,
            GenericArray::from_slice(&parts.authentication_tag),
        )?,
        JweEnc::Aes192Gcm => Aes192Gcm::new(GenericArray::from_slice(&jwe_cek)).decrypt_in_place_detached(
            &nonce,
            aad,
            &mut buffer,
            GenericArray::from_slice(&parts.authentication_tag),
        )?,
        JweEnc::Aes256Gcm => Aes256Gcm::new(GenericArray::from_slice(&jwe_cek)).decrypt_in_place_detached(
            &nonce,
            aad,
            &mut buffer,
            GenericArray::from_slice(&parts.authentication_tag),
        )?,
        unsupported => {
            return Err(JweError::UnsupportedAlgorithm {
                algorithm: format!("{:?}", unsupported),
            })
        }
    };

    Ok(Jwe {
        header,
        payload: buffer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key::PrivateKey, pem::Pem};

    fn get_private_key_1() -> PrivateKey {
        let pk_pem = crate::test_files::RSA_2048_PK_1.parse::<Pem>().unwrap();
        PrivateKey::from_pem(&pk_pem).unwrap()
    }

    fn get_private_key_2() -> PrivateKey {
        let pk_pem = crate::test_files::RSA_2048_PK_7
            .parse::<Pem>()
            .expect("private key pem");
        PrivateKey::from_pem(&pk_pem).expect("private_key")
    }

    #[test]
    fn rsa_oaep_aes_128_gcm() {
        let payload = "何だと？……無駄な努力だ？……百も承知だ！だがな、勝つ望みがある時ばかり、戦うのとは訳が違うぞ！"
            .as_bytes()
            .to_vec();

        let private_key = get_private_key_1();
        let public_key = private_key.to_public_key();

        let jwe = Jwe::new(JweAlg::RsaOaep, JweEnc::Aes128Gcm, payload);
        let encoded = jwe.clone().encode(&public_key).unwrap();

        let decoded = Jwe::decode(&encoded, &private_key).unwrap();

        assert_eq!(jwe.payload, decoded.payload);
        assert_eq!(jwe.header, decoded.header);
    }

    #[test]
    fn rsa_pkcs1v15_aes_128_gcm_bad_key() {
        let payload = "そうとも！ 負けると知って戦うのが、遙かに美しいのだ！"
            .as_bytes()
            .to_vec();

        let private_key = get_private_key_1();
        let public_key = get_private_key_2().to_public_key();

        let jwe = Jwe::new(JweAlg::RsaPkcs1v15, JweEnc::Aes128Gcm, payload);
        let encoded = jwe.clone().encode(&public_key).unwrap();

        let err = Jwe::decode(&encoded, &private_key).err().unwrap();
        assert_eq!(err.to_string(), "RSA error: decryption error");
    }

    #[test]
    fn direct_aes_256_gcm() {
        let payload = "さあ、取れ、取るがいい！だがな、貴様たちがいくら騒いでも、あの世へ、俺が持って行くものが一つある！それはな…".as_bytes().to_vec();

        let key = "わたしの……心意気だ!!";

        let jwe = Jwe::new(JweAlg::Direct, JweEnc::Aes256Gcm, payload);
        let encoded = jwe.clone().encode_direct(key.as_bytes()).unwrap();

        let decoded = Jwe::decode_direct(&encoded, key.as_bytes()).unwrap();

        assert_eq!(jwe.payload, decoded.payload);
        assert_eq!(jwe.header, decoded.header);
    }

    #[test]
    fn direct_aes_192_gcm_bad_key() {
        let payload = "和解をしよう？ 俺が？ 真っ平だ！ 真っ平御免だ！".as_bytes().to_vec();

        let jwe = Jwe::new(JweAlg::Direct, JweEnc::Aes192Gcm, payload);
        let encoded = jwe.clone().encode_direct(b"abcdefghabcdefghabcdefgh").unwrap();

        let err = Jwe::decode_direct(&encoded, b"zzzzzzzzabcdefghzzzzzzzz").err().unwrap();
        assert_eq!(err.to_string(), "AES-GCM error (opaque)");
    }
}
