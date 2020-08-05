use crate::{
    jose::{
        jwe::{JweAlg, JweEnc, JweHeader},
        jws::{Jws, JwsAlg, JwsError, JwsHeader},
    },
    key::{PrivateKey, PublicKey},
};
use core::fmt;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtError {
    /// JWS error
    #[error("JWS error: {source}")]
    Jws { source: JwsError },

    /// JWE error
    //#[error("JWE error: {source}")]
    //Jwe { source: JweError },

    /// Json error
    #[error("JSON error: {source}")]
    Json { source: serde_json::Error },

    /// registered claim type is invalid
    #[error("registered claim `{claim}` has invalid type")]
    InvalidRegisteredClaimType { claim: &'static str },

    /// a required claim is missing
    #[error("required claim `{claim}` is missing")]
    RequiredClaimMissing { claim: &'static str },

    /// token not yet valid
    #[error("token not yet valid (not before: {}, now: {} [leeway: {}])", not_before, now.numeric_date, now.leeway)]
    NotYetValid { not_before: i64, now: JwtDate },

    /// token expired
    #[error("token expired (not after: {}, now: {} [leeway: {}])", not_after, now.numeric_date, now.leeway)]
    Expired { not_after: i64, now: JwtDate },

    /// validator is invalid
    #[error("invalid validator: {description}")]
    InvalidValidator { description: &'static str },
}

impl From<JwsError> for JwtError {
    fn from(s: JwsError) -> Self {
        Self::Jws { source: s }
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json { source: e }
    }
}

/*impl From<JweError> for JwtError {
    fn from(s: JweError) -> Self {
        Self::Jwe { source: s }
    }
}*/

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
    current_date: Option<&'a JwtDate>,
    expiration_claim: CheckStrictness,
    not_before_claim: CheckStrictness,
}

pub const DANGEROUS_VALIDATOR: JwtValidator<'static> = JwtValidator::dangerous();

impl<'a> JwtValidator<'a> {
    /// Check signature and the registered exp and nbf claims. If a claim is missing token is rejected.
    pub const fn strict(current_date: &'a JwtDate) -> Self {
        Self {
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Required,
            not_before_claim: CheckStrictness::Required,
        }
    }

    /// Check signature and the registered exp and nbf claims. Token isn't rejected if a claim is missing.
    pub const fn lenient(current_date: &'a JwtDate) -> Self {
        Self {
            current_date: Some(current_date),
            expiration_claim: CheckStrictness::Optional,
            not_before_claim: CheckStrictness::Optional,
        }
    }

    /// No check.
    pub const fn dangerous() -> Self {
        Self {
            current_date: None,
            expiration_claim: CheckStrictness::Ignored,
            not_before_claim: CheckStrictness::Ignored,
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

// === JWT === //

const JWT_TYPE: &str = "JWT";
const EXPIRATION_TIME_CLAIM: &str = "exp";
const NOT_BEFORE_CLAIM: &str = "nbf";

pub struct Jwt<H, C> {
    pub header: H,
    pub claims: C,
}

pub type JwtSig<C> = Jwt<JwsHeader, C>;
pub type JwtEnc<C> = Jwt<JweHeader, C>;

impl<H, C> Clone for Jwt<H, C>
where
    H: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            claims: self.claims.clone(),
        }
    }
}

impl<H, C> fmt::Debug for Jwt<H, C>
where
    H: fmt::Debug,
    C: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Jwt")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .finish()
    }
}

impl<C> Jwt<JwsHeader, C> {
    pub fn new(alg: JwsAlg, claims: C) -> Self {
        Jwt {
            header: JwsHeader {
                typ: Some(JWT_TYPE.to_owned()),
                ..JwsHeader::new(alg)
            },
            claims,
        }
    }
}

impl<C> Jwt<JweHeader, C> {
    pub fn new(alg: JweAlg, enc: JweEnc, claims: C) -> Self {
        Jwt {
            header: JweHeader {
                typ: Some(JWT_TYPE.to_owned()),
                ..JweHeader::new(alg, enc)
            },
            claims,
        }
    }
}

impl<H, C> Jwt<H, C> {
    pub fn new_with_header(header: H, claims: C) -> Self {
        Jwt { header, claims }
    }
}

impl<C> Jwt<JwsHeader, C>
where
    C: Serialize,
{
    pub fn encode(self, private_key: &PrivateKey) -> Result<String, JwsError> {
        let jws = Jws {
            header: self.header,
            payload: serde_json::to_vec(&self.claims)?,
        };
        jws.encode(private_key)
    }
}

impl<C> Jwt<JwsHeader, C>
where
    C: DeserializeOwned,
{
    /// Validate using validator and public key.
    pub fn decode(encoded_token: &str, public_key: &PublicKey, validator: &JwtValidator) -> Result<Self, JwtError> {
        let jws = Jws::decode(encoded_token, public_key)?;
        Ok(Jwt {
            header: jws.header,
            claims: h_decode_check_claims(&jws.payload, validator)?,
        })
    }

    /// Unsafe JWT decoding method. Signature isn't checked at all.
    pub fn decode_dangerous(encoded_token: &str, validator: &JwtValidator) -> Result<Self, JwtError> {
        let jws = Jws::decode_without_validation(encoded_token)?;
        Ok(Jwt {
            header: jws.header,
            claims: h_decode_check_claims(&jws.payload, validator)?,
        })
    }
}

fn h_decode_check_claims<C: DeserializeOwned>(claims_json: &[u8], validator: &JwtValidator) -> Result<C, JwtError> {
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
            let claims = serde_json::from_slice::<serde_json::Value>(claims_json)?;

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
        (None, _, _) => serde_json::from_slice(claims_json)?,
    };

    Ok(claims)
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

    const fn get_strongly_typed_claims() -> MyClaims {
        MyClaims {
            sub: Cow::Borrowed("1234567890"),
            name: Cow::Borrowed("John Doe"),
            admin: true,
            iat: 1516239022,
        }
    }

    fn get_private_key_1() -> PrivateKey {
        let pk_pem = crate::test_files::RSA_2048_PK_1.parse::<Pem>().unwrap();
        PrivateKey::from_pkcs8(pk_pem.data()).unwrap()
    }

    #[test]
    fn encode_jws_rsa_sha256() {
        let claims = get_strongly_typed_claims();
        let jwt = JwtSig::new(JwsAlg::RS256, claims);
        let encoded = jwt.encode(&get_private_key_1()).unwrap();
        assert_eq!(encoded, crate::test_files::JOSE_JWT_SIG_EXAMPLE);
    }

    #[test]
    fn decode_jws_rsa_sha256() {
        let public_key = get_private_key_1().to_public_key();
        let jwt = JwtSig::<MyClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_EXAMPLE,
            &public_key,
            &JwtValidator::dangerous(),
        )
        .unwrap();
        assert_eq!(jwt.claims, get_strongly_typed_claims());

        // exp and nbf claims aren't present but this should pass with lenient validator
        let now = JwtDate::new(0);
        JwtSig::<MyClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_EXAMPLE,
            &public_key,
            &JwtValidator::lenient(&now),
        )
        .unwrap();
    }

    #[test]
    fn decode_jws_invalid_validator_err() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwtValidator::dangerous()
            .expiration_check_required()
            .not_before_check_optional();
        let err = JwtSig::<MyClaims>::decode(crate::test_files::JOSE_JWT_SIG_EXAMPLE, &public_key, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "invalid validator: current date is missing");
    }

    #[test]
    fn decode_jws_required_claim_missing_err() {
        let public_key = get_private_key_1().to_public_key();
        let now = JwtDate::new(0);
        let validator = JwtValidator::strict(&now);
        let err = JwtSig::<MyClaims>::decode(crate::test_files::JOSE_JWT_SIG_EXAMPLE, &public_key, &validator)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "required claim `nbf` is missing");
    }

    #[test]
    fn decode_jws_rsa_sha256_using_json_value_claims() {
        let public_key = get_private_key_1().to_public_key();
        let validator = JwtValidator::dangerous();
        let jwt = JwtSig::<serde_json::Value>::decode(crate::test_files::JOSE_JWT_SIG_EXAMPLE, &public_key, &validator)
            .unwrap();
        assert_eq!(jwt.claims["sub"].as_str().expect("sub"), "1234567890");
        assert_eq!(jwt.claims["name"].as_str().expect("name"), "John Doe");
        assert_eq!(jwt.claims["admin"].as_bool().expect("sub"), true);
        assert_eq!(jwt.claims["iat"].as_i64().expect("iat"), 1516239022);
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

        let jwt = JwtSig::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_WITH_EXP,
            &public_key,
            &JwtValidator::strict(&JwtDate::new(1545263999)),
        )
        .expect("couldn't decode jwt without leeway");

        assert_eq!(jwt.claims.exp, 1545264000);
        assert_eq!(jwt.claims.nbf, 1545263000);
        assert_eq!(jwt.claims.msg, "THIS IS TIME SENSITIVE DATA");

        // alternatively, a leeway can account for small clock skew
        JwtSig::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_WITH_EXP,
            &public_key,
            &JwtValidator::strict(&JwtDate::new_with_leeway(1545264001, 10)),
        )
        .expect("couldn't decode jwt with leeway for exp");

        JwtSig::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_WITH_EXP,
            &public_key,
            &JwtValidator::strict(&JwtDate::new_with_leeway(1545262999, 10)),
        )
        .expect("couldn't decode jwt with leeway for nbf");
    }

    #[test]
    fn decode_jws_invalid_date_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = JwtSig::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_WITH_EXP,
            &public_key,
            &JwtValidator::strict(&JwtDate::new(1545264001)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token expired (not after: 1545264000, now: 1545264001 [leeway: 0])"
        );

        let err = JwtSig::<MyExpirableClaims>::decode(
            crate::test_files::JOSE_JWT_SIG_WITH_EXP,
            &public_key,
            &JwtValidator::strict(&JwtDate::new_with_leeway(1545262998, 1)),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "token not yet valid (not before: 1545263000, now: 1545262998 [leeway: 1])"
        );
    }
}
