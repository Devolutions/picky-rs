use super::jwe::Jwe;
use crate::jose::jwe::{JweAlg, JweEnc, JweError, JweHeader};
use crate::jose::jws::{Jws, JwsAlg, JwsError, JwsHeader};
use crate::key::{PrivateKey, PublicKey};
use core::fmt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

// === error type === //

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtError {
    /// JWS error
    #[error("JWS error: {source}")]
    Jws { source: JwsError },

    /// JWE error
    #[error("JWE error: {source}")]
    Jwe { source: JweError },

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

impl From<JweError> for JwtError {
    fn from(s: JweError) -> Self {
        Self::Jwe { source: s }
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
    current_date: Option<&'a JwtDate>,
    expiration_claim: CheckStrictness,
    not_before_claim: CheckStrictness,
}

pub const NO_CHECK_VALIDATOR: JwtValidator<'static> = JwtValidator::no_check();

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
    pub const fn no_check() -> Self {
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

    pub fn new_signed(alg: JwsAlg, claims: C) -> Self {
        Self::new(alg, claims)
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

    pub fn new_encrypted(alg: JweAlg, enc: JweEnc, claims: C) -> Self {
        Self::new(alg, enc, claims)
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
    pub fn encode(self, private_key: &PrivateKey) -> Result<String, JwtError> {
        let jws = Jws {
            header: self.header,
            payload: serde_json::to_vec(&self.claims)?,
        };
        let encoded = jws.encode(private_key)?;
        Ok(encoded)
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
            claims: h_decode_and_validate_claims(&jws.payload, validator)?,
        })
    }

    /// Unsafe JWT decoding method. Signature isn't checked at all.
    pub fn decode_dangerous(encoded_token: &str, validator: &JwtValidator) -> Result<Self, JwtError> {
        let jws = Jws::decode_without_validation(encoded_token)?;
        Ok(Jwt {
            header: jws.header,
            claims: h_decode_and_validate_claims(&jws.payload, validator)?,
        })
    }
}

impl<C> Jwt<JweHeader, C>
where
    C: Serialize,
{
    /// Encode with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn encode(self, asymmetric_key: &PublicKey) -> Result<String, JwtError> {
        let jwe = Jwe {
            header: self.header,
            payload: serde_json::to_vec(&self.claims)?,
        };
        let encoded = jwe.encode(asymmetric_key)?;
        Ok(encoded)
    }

    /// Encode with provided CEK (a symmetric key). This will ignore `alg` value and override it with "dir".
    pub fn encode_direct(self, cek: &[u8]) -> Result<String, JweError> {
        let jwe = Jwe {
            header: self.header,
            payload: serde_json::to_vec(&self.claims)?,
        };
        let encoded = jwe.encode_direct(cek)?;
        Ok(encoded)
    }
}

impl<C> Jwt<JweHeader, C>
where
    C: DeserializeOwned,
{
    /// Encode with CEK encrypted and included in the token using asymmetric cryptography.
    pub fn decode(encoded_token: &str, key: &PrivateKey, validator: &JwtValidator) -> Result<Self, JwtError> {
        let jwe = Jwe::decode(encoded_token, key)?;
        Ok(Jwt {
            header: jwe.header,
            claims: h_decode_and_validate_claims(&jwe.payload, validator)?,
        })
    }

    /// Decode with provided CEK (a symmetric key).
    pub fn decode_direct(encoded_token: &str, cek: &[u8], validator: &JwtValidator) -> Result<Self, JwtError> {
        let jwe = Jwe::decode_direct(encoded_token, cek)?;
        Ok(Jwt {
            header: jwe.header,
            claims: h_decode_and_validate_claims(&jwe.payload, validator)?,
        })
    }
}

fn h_decode_and_validate_claims<C: DeserializeOwned>(
    claims_json: &[u8],
    validator: &JwtValidator,
) -> Result<C, JwtError> {
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
                    let nbf_i64 = nbf.as_i64().ok_or(JwtError::InvalidRegisteredClaimType {
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
                    let exp_i64 = exp.as_i64().ok_or(JwtError::InvalidRegisteredClaimType {
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
            &JwtValidator::no_check(),
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
        let validator = JwtValidator::no_check()
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
        let validator = JwtValidator::no_check();
        let jwt = JwtSig::<serde_json::Value>::decode(crate::test_files::JOSE_JWT_SIG_EXAMPLE, &public_key, &validator)
            .unwrap();
        assert_eq!(jwt.claims["sub"].as_str().expect("sub"), "1234567890");
        assert_eq!(jwt.claims["name"].as_str().expect("name"), "John Doe");
        assert_eq!(jwt.claims["admin"].as_bool().expect("sub"), true);
        assert_eq!(jwt.claims["iat"].as_i64().expect("iat"), 1516239022);
    }

    #[test]
    fn jwe_direct_aes_256_gcm() {
        let claims = get_strongly_typed_claims();
        let key = crate::hash::HashAlgorithm::SHA2_256.digest(b"magic_password");
        let jwt = Jwt::new_encrypted(JweAlg::Direct, JweEnc::Aes256Gcm, claims);
        let encoded = jwt.encode_direct(&key).unwrap();
        let decoded = Jwt::<_, MyClaims>::decode_direct(&encoded, &key, &NO_CHECK_VALIDATOR).unwrap();
        assert_eq!(decoded.claims, get_strongly_typed_claims());
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

    #[test]
    fn decode_step_cli_generated_token() {
        let pk_pem = crate::test_files::RSA_2048_PK_7.parse::<Pem>().unwrap();
        let pk = PrivateKey::from_pem(&pk_pem).expect("private_key 7");

        let token: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiekZIVnNNOWRjNE9sSEl3dkVuVnFmS3pSajF1anFZR3NablhBY2duX0NxSSJ9.nYfNbetIs-ot-lc2_kWdDATEduiY-uEjF6FWUwYgsKHCrrqwbgKnx0qu7gdhghqJ3-WwgOywlwyQL8EUSxhYFJqkBuISTpyUEdBmcEAjKgdG9wDiajzsHF32awTmVQCVKbS45knI4rnNQj6o37h7JX1IU9p0ZLl5s8SQ4HhwwD6yRRdFgrCk811LIfSWhBOadQNX2AqODGAKU9Dz30BqZMlmrrh0yoGltandsYsNcsQTCgP6a6kFW9tSIx2PN7ox7PpPL2DIos6VS-7qpGgxHwvhxGmsBYLWqE9D3Q0oqx-oiAdxEgknU355Ld6PiJm_Q2K8SnS0Fk83laRDU2FRuQ.OP91ilVez0ErRRXt._Q2yVghXSubt44LbhS4iIF5A8vohaVasnsa_Xnx3cH6LU5kPr_gtSVNT5ZXV67mBz9xY2QNTlArtmR7z1yJrx2yftePxxDOBqz9Bdo189h1iQ_QrzLaGQogkuCFf2BuOAv4wYh6kJ4S835MXM6afNmItQcLV45LX_Bu02GuUa7syx9n4UU0KMKKpyEt79Fx-WN9BDrrQ-P-6eJTuiGi4x7d5O1Dp7ocV4CxgIA4faZznMi05fZsY4ebEP2O9VZ2zfMyv_KT7WeGyB2pcBfpupMGmKybqXweT8QdoFSMnfmE_vqnIxQzFHHVOYrrrUKu9T-294TicUdmgohqIAWzBq0_dm9HFrdD_BnHfOtfnFJn_uHdtsTPPA7L54Mb_81ijLrooZvbrIPXZsJc_YLq65vkYWtdbfA5JDZIK8jDZr-79YyBIrqsYgn3w2LwgNHuKU0Ro-zheV208xCsKYbOooX4E86YAgeltwt_W-VyD-06fKpADUyN2p8ck3AG5k2FV2LUJ7ZSkesixprcOmzDDIjmMrKFyqsbEj0Fwm4kk-RNO3M8T2b00IEdcrP3EUoDm6CG-Ur7NNOosR-7xuK4wnH9KN8x9ePRJeil3G0zWNpIsV9dQhDQaP42HdYfyJ28LLn1tBn9aG_L8Erp7_Yv0Y21VrpoNLLnsptms4N82le3iYXN6Rlk-R6Mv04SupNEOoOFG3NpPa7NF-phcoR65BIFgjonTLPabEanAxu3vBhqGiX9N9A57N1av10cjVhqiOY-FxUTlubIDaw00F1974AuDGhx5bWllVr-68qXEpmatyee8j7tJd1XlEvHy6CpDrOFh-fEFKuwy_e0iMKPEF_Jj2vdX5sb8DAriAkoUY_m9zL29RNZzhdsbWamUMlIFlObkj09f_Db1P-FdolZga3xfdteUOB5Ig9vecEm7B9iE4hBJ4HcJY8yMGT1XS1_b9MSmWkUz4wf_3DHbgK6EUlDjqrLfHWBWZr7--stcFlVmxChu5wL5zAqIDoIcoAT_yIU8DgeRknZImbRAhXBtGoGvcCoRktLTNwoul4I.5SToM5GtHWm-beaADd1uhg";
        let jwe = Jwe::decode(token, &pk).unwrap();

        #[derive(Deserialize)]
        struct SomeJetClaims {
            jet_ap: String,
            prx_usr: String,
            nbf: i64,
        };

        let payload = core::str::from_utf8(&jwe.payload).unwrap();
        let jwk = JwtSig::<SomeJetClaims>::decode_dangerous(payload, &JwtValidator::no_check()).unwrap();

        assert_eq!(jwk.claims.jet_ap, "rdp");
        assert_eq!(jwk.claims.prx_usr, "username");
        assert_eq!(jwk.claims.nbf, 1600373587);
    }
}
