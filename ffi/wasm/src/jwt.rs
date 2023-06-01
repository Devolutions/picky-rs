// Deprecation attribute on `JwsAlg::ED25519` causes rustc to emit a warning even if this enum
// variant is not used. This is because #[wasm_bindgen] generates `impl` block without
// #[allow(deprecated)] attribute. This is a workaround to suppress the warning.
#![allow(deprecated)]

use crate::key::{PrivateKey, PublicKey};
use picky::jose::{jws, jwt};
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
    /// EdDSA using Ed25519/Ed448
    EdDSA,
    /// [DO NOT USE] EdDSA using Ed25519
    ///
    /// This value is used by some popular libraries (e.g. `golang-jwt) instead of `EdDSA` due to
    /// mistake in the implementation. This value is deprecated and should not be used.
    #[deprecated(note = "You should not use this value, but it may appear in the wild")]
    ED25519,
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
            jws::JwsAlg::EdDSA => JwsAlg::EdDSA,
            jws::JwsAlg::ED25519 => JwsAlg::ED25519,
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
            JwsAlg::EdDSA => jws::JwsAlg::EdDSA,
            JwsAlg::ED25519 => jws::JwsAlg::ED25519,
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

    /// Returns the key ID.
    pub fn get_kid(&self) -> Result<String, JwtError> {
        Ok(self.0.header.kid.as_deref().unwrap_or("").into())
    }

    /// Returns the header as a JSON encoded payload.
    pub fn get_header(&self) -> Result<String, JwtError> {
        serde_json::to_string(&self.0.header).map_err(|e| JwtError(e.into()))
    }

    /// Returns the claims as a JSON encoded payload.
    pub fn get_claims(&self) -> Result<String, JwtError> {
        serde_json::to_string(&self.0.state.claims).map_err(|e| JwtError(e.into()))
    }

    /// Decode JWT and check signature using provided public key.
    pub fn decode(compact_repr: &str, public_key: &PublicKey, validator: &JwtValidator) -> Result<JwtSig, JwtError> {
        let jwt = picky::jose::jwt::JwtSig::decode(compact_repr, &public_key.0)
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
    pub(crate) kid: Option<String>,
    pub(crate) claims: serde_json::Value,
    pub(crate) additional_headers: std::collections::HashMap<String, serde_json::Value>,
}

#[wasm_bindgen]
pub struct JwtSigBuilder(pub(crate) SigBuilderInner);

#[wasm_bindgen]
impl JwtSigBuilder {
    pub fn init() -> JwtSigBuilder {
        Self(SigBuilderInner {
            alg: JwsAlg::RS256,
            cty: None,
            kid: None,
            claims: serde_json::Value::Null,
            additional_headers: std::collections::HashMap::new(),
        })
    }

    pub fn set_algorithm(&mut self, alg: JwsAlg) {
        self.0.alg = alg;
    }

    pub fn set_content_type(&mut self, cty: &str) {
        self.0.cty = Some(cty.to_owned());
    }

    pub fn set_kid(&mut self, kid: &str) {
        self.0.kid = Some(kid.to_owned());
    }

    /// Adds a JSON object as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_object(&mut self, name: &str, obj: &str) -> Result<(), JwtError> {
        let parameter = serde_json::from_str(obj).map_err(|e| JwtError(e.into()))?;
        self.0.additional_headers.insert(name.to_owned(), parameter);
        Ok(())
    }

    /// Adds a boolean as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_bool(&mut self, name: &str, value: bool) {
        let parameter = serde_json::Value::Bool(value);
        self.0.additional_headers.insert(name.to_owned(), parameter);
    }

    /// Adds a positive number as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_pos_int(&mut self, name: &str, value: u64) {
        let parameter = serde_json::Value::from(value);
        self.0.additional_headers.insert(name.to_owned(), parameter);
    }

    /// Adds a possibly negative number as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_neg_int(&mut self, name: &str, value: i64) {
        let parameter = serde_json::Value::from(value);
        self.0.additional_headers.insert(name.to_owned(), parameter);
    }

    /// Adds a float as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_float(&mut self, name: &str, value: i64) {
        let parameter = serde_json::Value::from(value);
        self.0.additional_headers.insert(name.to_owned(), parameter);
    }

    /// Adds a float as additional header parameter.
    ///
    /// This additional header parameter may be either public or private.
    pub fn add_additional_parameter_string(&mut self, name: &str, value: &str) {
        let parameter = serde_json::Value::String(value.to_owned());
        self.0.additional_headers.insert(name.to_owned(), parameter);
    }

    /// Claims should be a valid JSON payload.
    pub fn set_claims(&mut self, claims: &str) -> Result<(), JwtError> {
        self.0.claims = serde_json::from_str(claims).map_err(|e| JwtError(e.into()))?;
        Ok(())
    }

    pub fn build(&self) -> Result<JwtSig, JwtError> {
        let claims = self.0.claims.clone();
        let mut jwt = jwt::CheckedJwtSig::new(self.0.alg.into(), claims);
        jwt.header.cty = self.0.cty.clone();
        jwt.header.kid = self.0.kid.clone();
        jwt.header.additional = self.0.additional_headers.clone();
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
