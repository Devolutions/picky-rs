use crate::{
    key::{PrivateKey, PublicKey},
    signature::{SignatureError, SignatureHashType},
};
use base64::DecodeError;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_value, Value};
use std::fmt;
use thiserror::Error;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtError {
    /// RSA error
    #[error("RSA error: {}", context)]
    Rsa { context: String },

    /// Json error
    #[error("JSON error: {}", source)]
    Json { source: serde_json::Error },

    /// signature error
    #[error("signature error: {}", source)]
    Signature { source: SignatureError },

    /// invalid token encoding
    #[error("input isn't a valid token string: {}", input)]
    InvalidEncoding { input: String },

    /// couldn't decode base64
    #[error("couldn't decode base64: {}", source)]
    Base64Decoding { source: DecodeError },

    /// input isn't valid utf8
    #[error("input isn't valid utf8: {}, input: {:?}", source, input)]
    InvalidUtf8 {
        source: std::string::FromUtf8Error,
        input: Vec<u8>,
    },

    /// expected JWT but got an unexpected type
    #[error("header says input is not a JWT: expected JWT, found {}", typ)]
    UnexpectedType { typ: String },

    /// registered claim type is invalid
    #[error("registered claim `{}` has invalid type", claim)]
    InvalidRegisteredClaimType { claim: &'static str },

    /// a required claim is missing
    #[error("required claim `{}` is missing", claim)]
    RequiredClaimMissing { claim: &'static str },

    /// token not yet valid
    #[error("token not yet valid (not before: {}, now: {} [leeway: {}])", not_before, now.numeric_date, now.leeway)]
    NotYetValid { not_before: i64, now: JwtDate },

    /// token expired
    #[error("token expired (not after: {}, now: {} [leeway: {}])", not_after, now.numeric_date, now.leeway)]
    Expired { not_after: i64, now: JwtDate },

    /// validator is invalid
    #[error("invalid validator: {}", description)]
    InvalidValidator { description: &'static str },
}

impl From<rsa::errors::Error> for JwtError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Rsa { context: e.to_string() }
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

impl From<SignatureError> for JwtError {
    fn from(e: SignatureError) -> Self {
        Self::Signature { source: e }
    }
}

impl From<DecodeError> for JwtError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

// === JWT date === //

/// Represent date as defined by [RFC7519](https://tools.ietf.org/html/rfc7519#section-2).
///
/// A leeway can be configured to account clock skew when comparing with another date.
/// Should be small (less than 120).
#[derive(Clone, Debug)]
pub struct JwtDate {
    pub numeric_date: i64,
    pub leeway: u16,
}

impl JwtDate {
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

// === validator === //

#[derive(Debug, Clone, Copy)]
enum CheckStrictness {
    Ignored,
    Optional,
    Required,
}

#[derive(Debug, Clone)]
pub struct JwtValidator<'a> {
    public_key: Option<&'a PublicKey>,
    current_date: Option<&'a JwtDate>,
    expiration_claim: CheckStrictness,
    not_before_claim: CheckStrictness,
}

pub const DANGEROUS_VALIDATOR: JwtValidator<'static> = JwtValidator::dangerous();

impl<'a> JwtValidator<'a> {
    /// Check signature and the registered exp and nbf claims. If a claim is missing token is rejected.
    pub const fn strict(public_key: &'a PublicKey, current_date: &'a JwtDate) -> Self {
        Self {
            public_key: Some(public_key),
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Required,
            not_before_claim: CheckStrictness::Required,
        }
    }

    /// Check signature and the registered exp and nbf claims. Token isn't rejected if a claim is missing.
    pub const fn lenient(public_key: &'a PublicKey, current_date: &'a JwtDate) -> Self {
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

    pub fn current_date(self, current_date: &'a JwtDate) -> Self {
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

// === json web token === //

const JWT_TYPE: &str = "JWT";
const EXPIRATION_TIME_CLAIM: &str = "exp";
const NOT_BEFORE_CLAIM: &str = "nbf";

#[derive(Serialize, Debug, Clone)]
struct Header {
    alg: SignatureHashType,
    typ: &'static str,
}

pub struct Jwt<C> {
    header: Header,
    claims: C,
}

impl<C: Clone> Clone for Jwt<C> {
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            claims: self.claims.clone(),
        }
    }
}

impl<C: fmt::Debug> fmt::Debug for Jwt<C> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Jwt")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .finish()
    }
}

impl<C> Jwt<C> {
    pub fn new(hashtype: SignatureHashType, claims: C) -> Self {
        Jwt {
            header: Header {
                alg: hashtype,
                typ: JWT_TYPE,
            },
            claims,
        }
    }

    pub fn view_claims(&self) -> &C {
        &self.claims
    }

    pub fn into_claims(self) -> C {
        self.claims
    }

    pub fn check_signature(&self, encoded_token: &str, public_key: &PublicKey) -> Result<(), JwtError> {
        let last_dot_idx = encoded_token.rfind('.').ok_or_else(|| JwtError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        if encoded_token.ends_with('.') {
            return Err(JwtError::InvalidEncoding {
                input: encoded_token.to_owned(),
            });
        }

        let signature = base64::decode_config(&encoded_token[last_dot_idx + 1..], base64::URL_SAFE_NO_PAD)?;

        self.header
            .alg
            .verify(public_key, &encoded_token[..last_dot_idx].as_bytes(), &signature)?;

        Ok(())
    }
}

impl<C: Serialize> Jwt<C> {
    pub fn encode(&self, private_key: &PrivateKey) -> Result<String, JwtError> {
        let header_base64 = base64::encode_config(&serde_json::to_vec(&self.header)?, base64::URL_SAFE_NO_PAD);
        let claims_base64 = base64::encode_config(&serde_json::to_vec(&self.claims)?, base64::URL_SAFE_NO_PAD);
        let header_claims = [header_base64, claims_base64].join(".");
        let signature = self.header.alg.sign(header_claims.as_bytes(), private_key)?;
        let signature_base64 = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
        Ok([header_claims, signature_base64].join("."))
    }
}

impl<C: DeserializeOwned> Jwt<C> {
    /// Validate using validator and returns decoded JWT.
    pub fn decode(encoded_token: &str, validator: &JwtValidator) -> Result<Self, JwtError> {
        let first_dot_idx = encoded_token.find('.').ok_or_else(|| JwtError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        let last_dot_idx = encoded_token.rfind('.').ok_or_else(|| JwtError::InvalidEncoding {
            input: encoded_token.to_owned(),
        })?;

        if first_dot_idx == last_dot_idx || encoded_token.starts_with('.') || encoded_token.ends_with('.') {
            return Err(JwtError::InvalidEncoding {
                input: encoded_token.to_owned(),
            });
        }

        let header = {
            let header_json = base64::decode_config(&encoded_token[..first_dot_idx], base64::URL_SAFE_NO_PAD)?;
            let mut header_val = serde_json::from_slice::<Value>(&header_json)?;
            let typ = header_val["typ"].as_str().ok_or_else(|| JwtError::UnexpectedType {
                typ: header_val["typ"].to_string(),
            })?;
            if typ != JWT_TYPE {
                return Err(JwtError::UnexpectedType { typ: typ.to_owned() });
            }
            Header {
                alg: from_value(header_val["alg"].take())?,
                typ: JWT_TYPE,
            }
        };

        if let Some(public_key) = &validator.public_key {
            let signature = base64::decode_config(&encoded_token[last_dot_idx + 1..], base64::URL_SAFE_NO_PAD)?;

            header
                .alg
                .verify(public_key, &encoded_token[..last_dot_idx].as_bytes(), &signature)?;
        }

        let claims_json =
            base64::decode_config(&encoded_token[first_dot_idx + 1..last_dot_idx], base64::URL_SAFE_NO_PAD)?;

        let claims = match (
            validator.current_date,
            validator.not_before_claim,
            validator.expiration_claim,
        ) {
            (None, CheckStrictness::Required, _) | (None, _, CheckStrictness::Required) => {
                return Err(JwtError::InvalidValidator {
                    description: "current date is missing",
                })
            }
            (Some(current_date), nbf_strictness, exp_strictness) => {
                let claims = serde_json::from_slice::<serde_json::Value>(&claims_json)?;

                let nbf_opt = claims.get(NOT_BEFORE_CLAIM);
                match (nbf_strictness, nbf_opt) {
                    (CheckStrictness::Ignored, _) | (CheckStrictness::Optional, None) => {}
                    (CheckStrictness::Required, None) => {
                        return Err(JwtError::RequiredClaimMissing {
                            claim: NOT_BEFORE_CLAIM,
                        })
                    }
                    (_, Some(nbf)) => {
                        let nbf_i64 = nbf.as_i64().ok_or_else(|| JwtError::InvalidRegisteredClaimType {
                            claim: NOT_BEFORE_CLAIM,
                        })?;
                        if !current_date.is_after(nbf_i64) {
                            return Err(JwtError::NotYetValid {
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
                        return Err(JwtError::RequiredClaimMissing {
                            claim: EXPIRATION_TIME_CLAIM,
                        })
                    }
                    (_, Some(exp)) => {
                        let exp_i64 = exp.as_i64().ok_or_else(|| JwtError::InvalidRegisteredClaimType {
                            claim: EXPIRATION_TIME_CLAIM,
                        })?;
                        if !current_date.is_before_strict(exp_i64) {
                            return Err(JwtError::Expired {
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

        Ok(Jwt { header, claims })
    }

    /// Unsafe JWT decoding method. Signature isn't checked at all.
    pub fn decode_without_validation(encoded_token: &str) -> Result<Self, JwtError> {
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
        let jwt = Jwt::new(SignatureHashType::RsaSha256, claims);
        let encoded = jwt.encode(&get_private_key_1()).unwrap();
        assert_eq!(encoded, crate::test_files::JOSE_JWT_EXAMPLE);
    }

    #[test]
    fn decode_rsa_sha256() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwtValidator::signature_only(&public_key);
        let jwt = Jwt::<MyClaims>::decode(crate::test_files::JOSE_JWT_EXAMPLE, &validator).unwrap();
        let claims = jwt.into_claims();
        assert_eq!(claims, get_strongly_typed_claims());

        // exp and nbf claims aren't present but this should pass with lenient validator
        let now = JwtDate::new(0);
        let validator = validator
            .current_date(&now)
            .expiration_check_optional()
            .not_before_check_optional();
        Jwt::<MyClaims>::decode(crate::test_files::JOSE_JWT_EXAMPLE, &validator).unwrap();
    }

    #[test]
    fn decode_invalid_validator_err() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwtValidator::signature_only(&public_key)
            .expiration_check_required()
            .not_before_check_optional();
        let err = Jwt::<MyClaims>::decode(crate::test_files::JOSE_JWT_EXAMPLE, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "invalid validator: current date is missing");
    }

    #[test]
    fn decode_required_claim_missing_err() {
        let public_key = get_private_key_1().to_public_key();
        let now = JwtDate::new(0);
        let validator = JwtValidator::strict(&public_key, &now);
        let err = Jwt::<MyClaims>::decode(crate::test_files::JOSE_JWT_EXAMPLE, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "required claim `nbf` is missing");
    }

    #[test]
    fn decode_rsa_sha256_using_json_value_claims() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwtValidator::signature_only(&public_key);
        let jwt = Jwt::<serde_json::Value>::decode(crate::test_files::JOSE_JWT_EXAMPLE, &validator).unwrap();
        let claims = jwt.into_claims();
        assert_eq!(claims["sub"].as_str().expect("sub"), "1234567890");
        assert_eq!(claims["name"].as_str().expect("name"), "John Doe");
        assert_eq!(claims["admin"].as_bool().expect("sub"), true);
        assert_eq!(claims["iat"].as_i64().expect("iat"), 1516239022);
    }

    #[test]
    fn decode_rsa_sha256_delayed_signature_check() {
        let jwt = Jwt::<MyClaims>::decode_without_validation(crate::test_files::JOSE_JWT_EXAMPLE).unwrap();
        let claims = jwt.view_claims();
        assert_eq!(claims, &get_strongly_typed_claims());

        let public_key = get_private_key_2().to_public_key();
        let err = jwt
            .check_signature(crate::test_files::JOSE_JWT_EXAMPLE, &public_key)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "signature error: invalid signature");
    }

    #[test]
    fn decode_rsa_sha256_invalid_signature_err() {
        let public_key = get_private_key_2().to_public_key();
        let err = Jwt::<MyClaims>::decode(
            crate::test_files::JOSE_JWT_EXAMPLE,
            &JwtValidator::signature_only(&public_key),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "signature error: invalid signature");
    }

    #[test]
    fn decode_invalid_base64_err() {
        let public_key = get_private_key_1().to_public_key();
        let err = Jwt::<MyClaims>::decode("aieoè~†.tésp.à", &JwtValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "couldn\'t decode base64: Invalid byte 195, offset 4.");
    }

    #[test]
    fn decode_invalid_json_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jwt::<MyClaims>::decode("abc.abc.abc", &JwtValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "JSON error: expected value at line 1 column 1");

        let err = Jwt::<MyClaims>::decode(
            "eyAiYWxnIjogIkhTMjU2IH0K.abc.abc",
            &JwtValidator::signature_only(&public_key),
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

        let err = Jwt::<MyClaims>::decode(".abc.abc", &JwtValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: .abc.abc");

        let err = Jwt::<MyClaims>::decode("abc.abc.", &JwtValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc.abc.");

        let err = Jwt::<MyClaims>::decode("abc.abc", &JwtValidator::signature_only(&public_key))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc.abc");

        let err = Jwt::<MyClaims>::decode("abc", &JwtValidator::signature_only(&public_key))
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
    fn decode_jwt_not_expired() {
        let public_key = get_private_key_1().to_public_key();

        let jwt = Jwt::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_WITH_EXP,
            &JwtValidator::strict(&public_key, &JwtDate::new(1545263999)),
        )
        .expect("couldn't decode jwt without leeway");

        let claims = jwt.into_claims();
        assert_eq!(claims.exp, 1545264000);
        assert_eq!(claims.nbf, 1545263000);
        assert_eq!(claims.msg, "THIS IS TIME SENSITIVE DATA");

        // alternatively, a leeway can account for small clock skew
        Jwt::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_WITH_EXP,
            &JwtValidator::strict(&public_key, &JwtDate::new_with_leeway(1545264001, 10)),
        )
        .expect("couldn't decode jwt with leeway for exp");

        Jwt::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_WITH_EXP,
            &JwtValidator::strict(&public_key, &JwtDate::new_with_leeway(1545262999, 10)),
        )
        .expect("couldn't decode jwt with leeway for nbf");
    }

    #[test]
    fn decode_jwt_invalid_date_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jwt::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_WITH_EXP,
            &JwtValidator::strict(&public_key, &JwtDate::new(1545264001)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token expired (not after: 1545264000, now: 1545264001 [leeway: 0])"
        );

        let err = Jwt::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_WITH_EXP,
            &JwtValidator::strict(&public_key, &JwtDate::new_with_leeway(1545262998, 1)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token not yet valid (not before: 1545263000, now: 1545262998 [leeway: 1])"
        );
    }
}
