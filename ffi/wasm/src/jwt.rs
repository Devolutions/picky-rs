use crate::key::{PrivateKey, PublicKey};
use picky::jose::jws;
use picky::jose::jwt;
use wasm_bindgen::prelude::*;

define_error!(JwtError, picky::jose::jwt::JwtError);

/// `alg` header parameter values for JWS
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum JwsAlg {
    /// RSASSA-PKCS-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS-v1_5 using SHA-512
    RS512,
    /// HMAC using SHA-256 (unsupported)
    HS256,
    /// HMAC using SHA-384 (unsupported)
    HS384,
    /// HMAC using SHA-512 (unsupported)
    HS512,
    /// ECDSA using P-256 and SHA-256 (unsupported)
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

impl From<jws::JwsAlg> for JwsAlg {
    fn from(alg: jws::JwsAlg) -> Self {
        match alg {
            jws::JwsAlg::HS256 => JwsAlg::HS256,
            jws::JwsAlg::HS384 => JwsAlg::HS384,
            jws::JwsAlg::HS512 => JwsAlg::HS512,
            jws::JwsAlg::RS256 => JwsAlg::RS256,
            jws::JwsAlg::RS384 => JwsAlg::RS384,
            jws::JwsAlg::RS512 => JwsAlg::RS512,
            jws::JwsAlg::ES256 => JwsAlg::ES256,
            jws::JwsAlg::ES384 => JwsAlg::ES384,
            jws::JwsAlg::ES512 => JwsAlg::ES512,
            jws::JwsAlg::PS256 => JwsAlg::PS256,
            jws::JwsAlg::PS384 => JwsAlg::PS384,
            jws::JwsAlg::PS512 => JwsAlg::PS512,
        }
    }
}

impl From<JwsAlg> for jws::JwsAlg {
    fn from(alg: JwsAlg) -> Self {
        match alg {
            JwsAlg::RS256 => jws::JwsAlg::RS256,
            JwsAlg::RS384 => jws::JwsAlg::RS384,
            JwsAlg::RS512 => jws::JwsAlg::RS512,
            JwsAlg::HS256 => jws::JwsAlg::HS256,
            JwsAlg::HS384 => jws::JwsAlg::HS384,
            JwsAlg::HS512 => jws::JwsAlg::HS512,
            JwsAlg::ES256 => jws::JwsAlg::ES256,
            JwsAlg::ES384 => jws::JwsAlg::ES384,
            JwsAlg::ES512 => jws::JwsAlg::ES512,
            JwsAlg::PS256 => jws::JwsAlg::PS256,
            JwsAlg::PS384 => jws::JwsAlg::PS384,
            JwsAlg::PS512 => jws::JwsAlg::PS512,
        }
    }
}

///  Signed JSON Web Token object.
///
/// This is a JWS (JSON Web Signature) structure with JWT claims contained in a JSON payload.
#[wasm_bindgen]
pub struct JwtSig(pub(crate) jwt::CheckedJwtSig<serde_json::Value>);

#[wasm_bindgen]
impl JwtSig {
    pub fn builder() -> JwtSigBuilder {
        JwtSigBuilder::init()
    }

    /// Returns the content type.
    pub fn get_content_type(&self) -> Result<String, JwtError> {
        Ok(self.0.header.cty.as_deref().unwrap_or("").into())
    }

    /// Returns the claims as a JSON encoded payload.
    pub fn get_claims(&self) -> Result<String, JwtError> {
        serde_json::to_string_pretty(&self.0.state.claims).map_err(|e| JwtError(e.into()))
    }

    /// Decode JWT and check signature using provided public key.
    pub fn decode(encoded_token: &str, public_key: &PublicKey, validator: &JwtValidator) -> Result<JwtSig, JwtError> {
        let jwt = picky::jose::jwt::JwtSig::decode(encoded_token, &public_key.0)
            .and_then(|jwt| jwt.validate::<serde_json::Value>(&validator.0))?;
        Ok(JwtSig(jwt))
    }

    /// Dangerous JWT decoding method. Signature isn't checked at all.
    pub fn decode_dangerous(encoded_token: &str, validator: &JwtValidator) -> Result<JwtSig, JwtError> {
        let jwt = picky::jose::jwt::JwtSig::decode_dangerous(encoded_token)
            .and_then(|jwt| jwt.validate::<serde_json::Value>(&validator.0))?;
        Ok(JwtSig(jwt))
    }

    /// Encode using the given private key and returns the compact representation of this token.
    pub fn encode(&self, key: &PrivateKey) -> Result<String, JwtError> {
        self.0.clone().encode(&key.0).map_err(JwtError)
    }
}

pub(crate) struct SigBuilderInner {
    pub(crate) alg: JwsAlg,
    pub(crate) cty: Option<String>,
    pub(crate) claims: String,
}

#[wasm_bindgen]
pub struct JwtSigBuilder(pub(crate) SigBuilderInner);

#[wasm_bindgen]
impl JwtSigBuilder {
    pub fn init() -> JwtSigBuilder {
        Self(SigBuilderInner {
            alg: JwsAlg::RS256,
            cty: None,
            claims: String::from("{}"),
        })
    }

    pub fn set_algorithm(&mut self, alg: JwsAlg) {
        self.0.alg = alg;
    }

    pub fn set_content_type(&mut self, cty: &str) {
        self.0.cty = Some(cty.to_owned());
    }

    /// Claims should be a valid JSON payload.
    pub fn set_claims(&mut self, claims: &str) {
        self.0.claims = claims.to_owned();
    }

    pub fn build(&self) -> Result<JwtSig, JwtError> {
        let claims = serde_json::from_str(&self.0.claims).map_err(|e| JwtError(e.into()))?;
        let mut jwt = jwt::CheckedJwtSig::new(self.0.alg.into(), claims);
        jwt.header.cty = self.0.cty.clone();
        Ok(JwtSig(jwt))
    }
}

#[wasm_bindgen]
pub struct JwtValidator(jwt::JwtValidator);

#[wasm_bindgen]
impl JwtValidator {
    /// Check signature and the registered exp and nbf claims. If a claim is missing token is rejected.
    pub fn strict(numeric_date: i64, leeway: u16) -> JwtValidator {
        Self(jwt::JwtValidator::strict(jwt::JwtDate::new_with_leeway(
            numeric_date,
            leeway,
        )))
    }

    /// Check signature and the registered exp and nbf claims. Token isn't rejected if a claim is missing.
    pub fn lenient(numeric_date: i64, leeway: u16) -> JwtValidator {
        Self(jwt::JwtValidator::lenient(jwt::JwtDate::new_with_leeway(
            numeric_date,
            leeway,
        )))
    }

    /// No check.
    pub fn no_check() -> JwtValidator {
        Self(jwt::JwtValidator::no_check())
    }
}
