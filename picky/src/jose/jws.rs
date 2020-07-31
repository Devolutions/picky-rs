//! JSON Web Signature (JWS) represents content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based data structures.
//!
//! See [RFC7515](https://tools.ietf.org/html/rfc7515).

use crate::{
    hash::HashAlgorithm,
    jose::jwk::Jwk,
    key::{PrivateKey, PublicKey},
    signature::{SignatureAlgorithm, SignatureError},
};
use base64::DecodeError;
use core::convert::TryFrom;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwsError {
    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// Json error
    #[error("JSON error: {source}")]
    Json { source: serde_json::Error },

    /// signature error
    #[error("signature error: {source}")]
    Signature { source: SignatureError },

    /// invalid token encoding
    #[error("input isn't a valid token string: {input}")]
    InvalidEncoding { input: String },

    /// couldn't decode base64
    #[error("couldn't decode base64: {source}")]
    Base64Decoding { source: DecodeError },

    /// input isn't valid utf8
    #[error("input isn't valid utf8: {source}, input: {input:?}")]
    InvalidUtf8 {
        source: std::string::FromUtf8Error,
        input: Vec<u8>,
    },

    /// expected JWS but got an unexpected type
    #[error("header says input is not a JWS: expected JWS, found {typ}")]
    UnexpectedType { typ: String },

    /// registered claim type is invalid
    #[error("registered claim `{claim}` has invalid type")]
    InvalidRegisteredClaimType { claim: &'static str },

    /// a required claim is missing
    #[error("required claim `{claim}` is missing")]
    RequiredClaimMissing { claim: &'static str },

    /// token not yet valid
    #[error("token not yet valid (not before: {}, now: {} [leeway: {}])", not_before, now.numeric_date, now.leeway)]
    NotYetValid { not_before: i64, now: JwsDate },

    /// token expired
    #[error("token expired (not after: {}, now: {} [leeway: {}])", not_after, now.numeric_date, now.leeway)]
    Expired { not_after: i64, now: JwsDate },

    /// validator is invalid
    #[error("invalid validator: {description}")]
    InvalidValidator { description: &'static str },
}

impl From<rsa::errors::Error> for JwsError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<serde_json::Error> for JwsError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

impl From<SignatureError> for JwsError {
    fn from(e: SignatureError) -> Self {
        Self::Signature { source: e }
    }
}

impl From<DecodeError> for JwsError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

// === JWS date === //

/// Represent date as defined by [RFC7519](https://tools.ietf.org/html/rfc7519#section-2).
///
/// A leeway can be configured to account clock skew when comparing with another date.
/// Should be small (less than 120).
#[derive(Clone, Debug)]
pub struct JwsDate {
    pub numeric_date: i64,
    pub leeway: u16,
}

impl JwsDate {
    pub const fn new(numeric_date: i64) -> Self {
        Self {
            numeric_date,
            leeway: 0,
        }
    }

    pub const fn new_with_leeway(numeric_date: i64, leeway: u16) -> Self {
        Self { numeric_date, leeway }
    }

    pub const fn is_before(&self, other_numeric_date: i64) -> bool {
        self.numeric_date <= other_numeric_date + self.leeway as i64
    }

    pub const fn is_before_strict(&self, other_numeric_date: i64) -> bool {
        self.numeric_date < other_numeric_date + self.leeway as i64
    }

    pub const fn is_after(&self, other_numeric_date: i64) -> bool {
        self.numeric_date >= other_numeric_date - self.leeway as i64
    }

    pub const fn is_after_strict(&self, other_numeric_date: i64) -> bool {
        self.numeric_date > other_numeric_date - self.leeway as i64
    }
}

// === JWS algorithms === //

/// `alg` header parameter values for JWS
///
/// [JSON Web Algorithms (JWA) draft-ietf-jose-json-web-algorithms-40 #3](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwsAlg {
    /// HMAC using SHA-256 (unsupported)
    ///
    /// Required by RFC
    HS256,

    /// HMAC using SHA-384 (unsupported)
    HS384,

    /// HMAC using SHA-512 (unsupported)
    HS512,

    /// RSASSA-PKCS-v1_5 using SHA-256
    ///
    /// Recommended by RFC
    RS256,

    /// RSASSA-PKCS-v1_5 using SHA-384
    RS384,

    /// RSASSA-PKCS-v1_5 using SHA-512
    RS512,

    /// ECDSA using P-256 and SHA-256 (unsupported)
    ///
    /// Recommended+ by RFC
    ES256,

    /// ECDSA using P-384 and SHA-384 (unsupported)
    ES384,

    /// ECDSA using P-521 and SHA-512 (unsupported)
    ES512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (unsupported)
    PS256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (unsupported)
    PS384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (unsupported)
    PS512,
}

impl TryFrom<SignatureAlgorithm> for JwsAlg {
    type Error = SignatureError;

    fn try_from(v: SignatureAlgorithm) -> Result<Self, Self::Error> {
        match v {
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256) => Ok(Self::RS256),
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_384) => Ok(Self::RS384),
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512) => Ok(Self::RS512),
            unsupported => Err(SignatureError::UnsupportedAlgorithm {
                algorithm: format!("{:?}", unsupported),
            }),
        }
    }
}

impl TryFrom<JwsAlg> for SignatureAlgorithm {
    type Error = SignatureError;

    fn try_from(v: JwsAlg) -> Result<Self, Self::Error> {
        match v {
            JwsAlg::RS256 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256)),
            JwsAlg::RS384 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_384)),
            JwsAlg::RS512 => Ok(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512)),
            unsupported => Err(SignatureError::UnsupportedAlgorithm {
                algorithm: format!("{:?}", unsupported),
            }),
        }
    }
}

// === validator === //

#[derive(Debug, Clone, Copy)]
enum CheckStrictness {
    Ignored,
    Optional,
    Required,
}

#[derive(Debug, Clone)]
pub struct JwsValidator<'a> {
    public_key: Option<&'a PublicKey>,
    current_date: Option<&'a JwsDate>,
    expiration_claim: CheckStrictness,
    not_before_claim: CheckStrictness,
}

pub const DANGEROUS_VALIDATOR: JwsValidator<'static> = JwsValidator::dangerous();

impl<'a> JwsValidator<'a> {
    /// Check signature and the registered exp and nbf claims. If a claim is missing token is rejected.
    pub const fn strict(public_key: &'a PublicKey, current_date: &'a JwsDate) -> Self {
        Self {
            public_key: Some(public_key),
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Required,
            not_before_claim: CheckStrictness::Required,
        }
    }

    /// Check signature and the registered exp and nbf claims. Token isn't rejected if a claim is missing.
    pub const fn lenient(public_key: &'a PublicKey, current_date: &'a JwsDate) -> Self {
        Self {
            public_key: Some(public_key),
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Optional,
            not_before_claim: CheckStrictness::Optional,
        }
    }

    /// Check signature only. No registered claim is checked.
    pub const fn signature_only(public_key: &'a PublicKey) -> Self {
        Self {
            public_key: Some(public_key),
            current_date: None,
            expiration_claim: CheckStrictness::Ignored,
            not_before_claim: CheckStrictness::Ignored,
        }
    }

    /// No check.
    pub const fn dangerous() -> Self {
        Self {
            public_key: None,
            current_date: None,
            expiration_claim: CheckStrictness::Ignored,
            not_before_claim: CheckStrictness::Ignored,
        }
    }

    pub fn public_key(self, public_key: &'a PublicKey) -> Self {
        Self {
            public_key: Some(public_key),
            ..self
        }
    }

    pub fn current_date(self, current_date: &'a JwsDate) -> Self {
        Self {
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Required,
            not_before_claim: CheckStrictness::Required,
            ..self
        }
    }

    pub fn expiration_check_required(self) -> Self {
        Self {
            expiration_claim: CheckStrictness::Required,
            ..self
        }
    }

    pub fn expiration_check_optional(self) -> Self {
        Self {
            expiration_claim: CheckStrictness::Optional,
            ..self
        }
    }

    pub fn expiration_check_ignored(self) -> Self {
        Self {
            expiration_claim: CheckStrictness::Ignored,
            ..self
        }
    }

    pub fn not_before_check_required(self) -> Self {
        Self {
            not_before_claim: CheckStrictness::Required,
            ..self
        }
    }

    pub fn not_before_check_optional(self) -> Self {
        Self {
            not_before_claim: CheckStrictness::Optional,
            ..self
        }
    }

    pub fn not_before_check_ignored(self) -> Self {
        Self {
            not_before_claim: CheckStrictness::Ignored,
            ..self
        }
    }
}

// === JWS header === //

/// JOSE header of a JWS
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwsHeader {
    // -- specific to JWK -- //
    /// Algorithm Header
    ///
    /// identifies the cryptographic algorithm used to secure the JWS.
    pub alg: JwsAlg,

    // -- common with JWE -- //
    /// JWK Set URL
    ///
    /// URI that refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to digitally sign the JWS.
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
    /// Used by JWS applications to declare the media type [IANA.MediaTypes] of this complete JWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type header
    ///
    /// Used by JWS applications to declare the media type [IANA.MediaTypes] of the secured content (the payload).
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

impl JwsHeader {
    fn new(alg: JwsAlg) -> Self {
        Self {
            alg,
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

// === json web token === //

const JWT_TYPE: &str = "JWT";
const EXPIRATION_TIME_CLAIM: &str = "exp";
const NOT_BEFORE_CLAIM: &str = "nbf";

pub struct Jws<C> {
    pub header: JwsHeader,
    pub claims: C,
}

impl<C: Clone> Clone for Jws<C> {
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            claims: self.claims.clone(),
        }
    }
}

impl<C: fmt::Debug> fmt::Debug for Jws<C> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Jws")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .finish()
    }
}

impl<C> Jws<C> {
    pub fn new(alg: JwsAlg, claims: C) -> Self {
        Jws {
            header: JwsHeader {
                typ: Some(JWT_TYPE.to_owned()),
                ..JwsHeader::new(alg)
            },
            claims,
        }
    }

    pub fn new_with_header(header: JwsHeader, claims: C) -> Self {
        Jws { header, claims }
    }

    pub fn check_signature(&self, encoded_token: &str, public_key: &PublicKey) -> Result<(), JwsError> {
        let last_dot_idx = encoded_token.rfind('.').ok_or_else(|| JwsError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        if encoded_token.ends_with('.') {
            return Err(JwsError::InvalidEncoding {
                input: encoded_token.to_owned(),
            });
        }

        let signature = base64::decode_config(&encoded_token[last_dot_idx + 1..], base64::URL_SAFE_NO_PAD)?;
        let signature_algo = SignatureAlgorithm::try_from(self.header.alg)?;
        signature_algo.verify(public_key, &encoded_token[..last_dot_idx].as_bytes(), &signature)?;

        Ok(())
    }
}

impl<C: Serialize> Jws<C> {
    pub fn encode(&self, private_key: &PrivateKey) -> Result<String, JwsError> {
        let header_base64 = base64::encode_config(&serde_json::to_vec(&self.header)?, base64::URL_SAFE_NO_PAD);
        let claims_base64 = base64::encode_config(&serde_json::to_vec(&self.claims)?, base64::URL_SAFE_NO_PAD);
        let header_claims = [header_base64, claims_base64].join(".");
        let signature_algo = SignatureAlgorithm::try_from(self.header.alg)?;
        let signature = signature_algo.sign(header_claims.as_bytes(), private_key)?;
        let signature_base64 = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
        Ok([header_claims, signature_base64].join("."))
    }
}

impl<C: DeserializeOwned> Jws<C> {
    /// Validate using validator and returns decoded JWS.
    pub fn decode(encoded_token: &str, validator: &JwsValidator) -> Result<Self, JwsError> {
        let first_dot_idx = encoded_token.find('.').ok_or_else(|| JwsError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        let last_dot_idx = encoded_token.rfind('.').ok_or_else(|| JwsError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        if first_dot_idx == last_dot_idx || encoded_token.starts_with('.') || encoded_token.ends_with('.') {
            return Err(JwsError::InvalidEncoding {
                input: encoded_token.to_owned(),
            });
        }

        let header_json = base64::decode_config(&encoded_token[..first_dot_idx], base64::URL_SAFE_NO_PAD)?;
        let header = serde_json::from_slice::<JwsHeader>(&header_json)?;

        if let Some(public_key) = &validator.public_key {
            let signature = base64::decode_config(&encoded_token[last_dot_idx + 1..], base64::URL_SAFE_NO_PAD)?;
            let signature_algo = SignatureAlgorithm::try_from(header.alg)?;
            signature_algo.verify(public_key, &encoded_token[..last_dot_idx].as_bytes(), &signature)?;
        }

        let claims_json =
            base64::decode_config(&encoded_token[first_dot_idx + 1..last_dot_idx], base64::URL_SAFE_NO_PAD)?;

        let claims = match (
            validator.current_date,
            validator.not_before_claim,
            validator.expiration_claim,
        ) {
            (None, CheckStrictness::Required, _) | (None, _, CheckStrictness::Required) => {
                return Err(JwsError::InvalidValidator {
                    description: "current date is missing",
                })
            }
            (Some(current_date), nbf_strictness, exp_strictness) => {
                let claims = serde_json::from_slice::<serde_json::Value>(&claims_json)?;

                let nbf_opt = claims.get(NOT_BEFORE_CLAIM);
                match (nbf_strictness, nbf_opt) {
                    (CheckStrictness::Ignored, _) | (CheckStrictness::Optional, None) => {}
                    (CheckStrictness::Required, None) => {
                        return Err(JwsError::RequiredClaimMissing {
                            claim: NOT_BEFORE_CLAIM,
                        })
                    }
                    (_, Some(nbf)) => {
                        let nbf_i64 = nbf.as_i64().ok_or_else(|| JwsError::InvalidRegisteredClaimType {
                            claim: NOT_BEFORE_CLAIM,
                        })?;
                        if !current_date.is_after(nbf_i64) {
                            return Err(JwsError::NotYetValid {
                                not_before: nbf_i64,
                                now: current_date.clone(),
                            });
                        }
                    }
                }

                let exp_opt = claims.get(EXPIRATION_TIME_CLAIM);
                match (exp_strictness, exp_opt) {
                    (CheckStrictness::Ignored, _) | (CheckStrictness::Optional, None) => {}
                    (CheckStrictness::Required, None) => {
                        return Err(JwsError::RequiredClaimMissing {
                            claim: EXPIRATION_TIME_CLAIM,
                        })
                    }
                    (_, Some(exp)) => {
                        let exp_i64 = exp.as_i64().ok_or_else(|| JwsError::InvalidRegisteredClaimType {
                            claim: EXPIRATION_TIME_CLAIM,
                        })?;
                        if !current_date.is_before_strict(exp_i64) {
                            return Err(JwsError::Expired {
                                not_after: exp_i64,
                                now: current_date.clone(),
                            });
                        }
                    }
                }

                serde_json::value::from_value(claims)?
            }
            (None, _, _) => serde_json::from_slice(&claims_json)?,
        };

        Ok(Jws { header, claims })
    }

    /// Unsafe JWS decoding method. Signature isn't checked at all.
    pub fn decode_without_validation(encoded_token: &str) -> Result<Self, JwsError> {
        Self::decode(encoded_token, &DANGEROUS_VALIDATOR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::Pem;
    use serde::Deserialize;
    use std::borrow::Cow;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MyClaims {
        sub: Cow<'static, str>,
        name: Cow<'static, str>,
        admin: bool,
        iat: i32,
    }

    fn get_private_key_1() -> PrivateKey {
        let pk_pem = crate::test_files::RSA_2048_PK_1.parse::<Pem>().unwrap();
        PrivateKey::from_pkcs8(pk_pem.data()).unwrap()
    }

    fn get_private_key_2() -> PrivateKey {
        let pk_pem = crate::test_files::RSA_2048_PK_2.parse::<Pem>().unwrap();
        PrivateKey::from_pkcs8(pk_pem.data()).unwrap()
    }

    const fn get_strongly_typed_claims() -> MyClaims {
        MyClaims {
            sub: Cow::Borrowed("1234567890"),
            name: Cow::Borrowed("John Doe"),
            admin: true,
            iat: 1516239022,
        }
    }

    #[test]
    fn encode_rsa_sha256() {
        let claims = get_strongly_typed_claims();
        let jws = Jws::new(JwsAlg::RS256, claims);
        let encoded = jws.encode(&get_private_key_1()).unwrap();
        assert_eq!(encoded, crate::test_files::JOSE_JWS_EXAMPLE);
    }

    #[test]
    fn decode_rsa_sha256() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwsValidator::signature_only(&public_key);
        let jws = Jws::<MyClaims>::decode(crate::test_files::JOSE_JWS_EXAMPLE, &validator).unwrap();
        assert_eq!(jws.claims, get_strongly_typed_claims());

        // exp and nbf claims aren't present but this should pass with lenient validator
        let now = JwsDate::new(0);
        let validator = validator
            .current_date(&now)
            .expiration_check_optional()
            .not_before_check_optional();
        Jws::<MyClaims>::decode(crate::test_files::JOSE_JWS_EXAMPLE, &validator).unwrap();
    }

    #[test]
    fn decode_invalid_validator_err() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwsValidator::signature_only(&public_key)
            .expiration_check_required()
            .not_before_check_optional();
        let err = Jws::<MyClaims>::decode(crate::test_files::JOSE_JWS_EXAMPLE, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "invalid validator: current date is missing");
    }

    #[test]
    fn decode_required_claim_missing_err() {
        let public_key = get_private_key_1().to_public_key();
        let now = JwsDate::new(0);
        let validator = JwsValidator::strict(&public_key, &now);
        let err = Jws::<MyClaims>::decode(crate::test_files::JOSE_JWS_EXAMPLE, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "required claim `nbf` is missing");
    }

    #[test]
    fn decode_rsa_sha256_using_json_value_claims() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwsValidator::signature_only(&public_key);
        let jws = Jws::<serde_json::Value>::decode(crate::test_files::JOSE_JWS_EXAMPLE, &validator).unwrap();
        assert_eq!(jws.claims["sub"].as_str().expect("sub"), "1234567890");
        assert_eq!(jws.claims["name"].as_str().expect("name"), "John Doe");
        assert_eq!(jws.claims["admin"].as_bool().expect("sub"), true);
        assert_eq!(jws.claims["iat"].as_i64().expect("iat"), 1516239022);
    }

    #[test]
    fn decode_rsa_sha256_delayed_signature_check() {
        let jws = Jws::<MyClaims>::decode_without_validation(crate::test_files::JOSE_JWS_EXAMPLE).unwrap();
        assert_eq!(jws.claims, get_strongly_typed_claims());

        let public_key = get_private_key_2().to_public_key();
        let err = jws
            .check_signature(crate::test_files::JOSE_JWS_EXAMPLE, &public_key)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "signature error: invalid signature");
    }

    #[test]
    fn decode_rsa_sha256_invalid_signature_err() {
        let public_key = get_private_key_2().to_public_key();
        let err = Jws::<MyClaims>::decode(
            crate::test_files::JOSE_JWS_EXAMPLE,
            &JwsValidator::signature_only(&public_key),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "signature error: invalid signature");
    }

    #[test]
    fn decode_invalid_base64_err() {
        let public_key = get_private_key_1().to_public_key();
        let err = Jws::<MyClaims>::decode("aieoè~†.tésp.à", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "couldn\'t decode base64: Invalid byte 195, offset 4.");
    }

    #[test]
    fn decode_invalid_json_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jws::<MyClaims>::decode("abc.abc.abc", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "JSON error: expected value at line 1 column 1");

        let err = Jws::<MyClaims>::decode(
            "eyAiYWxnIjogIkhTMjU2IH0K.abc.abc",
            &JwsValidator::signature_only(&public_key),
        )
        .err()
        .unwrap();
        assert_eq!(
            err.to_string(),
            "JSON error: control character (\\u0000-\\u001F) \
             found while parsing a string at line 2 column 0"
        );
    }

    #[test]
    fn decode_invalid_encoding_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jws::<MyClaims>::decode(".abc.abc", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: .abc.abc");

        let err = Jws::<MyClaims>::decode("abc.abc.", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc.abc.");

        let err = Jws::<MyClaims>::decode("abc.abc", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc.abc");

        let err = Jws::<MyClaims>::decode("abc", &JwsValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc");
    }

    #[derive(Serialize, Deserialize)]
    struct MyExpirableClaims {
        exp: i64,
        nbf: i64,
        msg: String,
    }

    #[test]
    fn decode_jws_not_expired() {
        let public_key = get_private_key_1().to_public_key();

        let jws = Jws::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWS_WITH_EXP,
            &JwsValidator::strict(&public_key, &JwsDate::new(1545263999)),
        )
        .expect("couldn't decode jws without leeway");

        assert_eq!(jws.claims.exp, 1545264000);
        assert_eq!(jws.claims.nbf, 1545263000);
        assert_eq!(jws.claims.msg, "THIS IS TIME SENSITIVE DATA");

        // alternatively, a leeway can account for small clock skew
        Jws::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWS_WITH_EXP,
            &JwsValidator::strict(&public_key, &JwsDate::new_with_leeway(1545264001, 10)),
        )
        .expect("couldn't decode jws with leeway for exp");

        Jws::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWS_WITH_EXP,
            &JwsValidator::strict(&public_key, &JwsDate::new_with_leeway(1545262999, 10)),
        )
        .expect("couldn't decode jws with leeway for nbf");
    }

    #[test]
    fn decode_jws_invalid_date_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jws::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWS_WITH_EXP,
            &JwsValidator::strict(&public_key, &JwsDate::new(1545264001)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token expired (not after: 1545264000, now: 1545264001 [leeway: 0])"
        );

        let err = Jws::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWS_WITH_EXP,
            &JwsValidator::strict(&public_key, &JwsDate::new_with_leeway(1545262998, 1)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token not yet valid (not before: 1545263000, now: 1545262998 [leeway: 1])"
        );
    }
}
