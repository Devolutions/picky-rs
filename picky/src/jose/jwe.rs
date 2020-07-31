//! JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
//!
//! See [RFC7516](https://tools.ietf.org/html/rfc7516).

use crate::jose::jwk::Jwk;
use serde::{Deserialize, Serialize};

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

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256 (unsupported)
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

    /// Direct use of a shared symmetric key as the CEK (unsupported)
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

/// `enc` header parameter values for JWE to encrypt content
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #5](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JweEnc {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm.
    ///
    /// Required by RFC
    #[serde(rename = "A128CBC-HS256")]
    Aes128CbcHmacSha256,

    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm.
    #[serde(rename = "A192CBC-HS384")]
    Aes192CbcHmacSha384,

    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm.
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

// === JWE header === //

/// JWE specific part of JOSE header
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JweHeader {
    // -- specific to JWE -- //
    /// Algorithm used to encrypt or determine the Content Encryption Key (CEK) (key wrapping...)
    pub alg: JweAlg,

    /// Content encryption algorithm to use
    ///
    /// This must be a *symmetric* Authenticated Encryption with Associated Data (AEAD) algorimth.
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
