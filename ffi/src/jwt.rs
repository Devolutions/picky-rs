use self::ffi::JwsAlg;
use picky::jose::jws;

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

pub(crate) struct SigBuilderInner {
    pub(crate) alg: JwsAlg,
    pub(crate) cty: Option<String>,
    pub(crate) kid: Option<String>,
    pub(crate) claims: serde_json::Value,
    pub(crate) additional_headers: std::collections::HashMap<String, serde_json::Value>,
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::key::ffi::{PrivateKey, PublicKey};
    use diplomat_runtime::{DiplomatResult, DiplomatWriteable};
    use picky::jose::jwt;
    use std::fmt::Write as _;

    /// `alg` header parameter values for JWS
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

    ///  Signed JSON Web Token object.
    ///
    /// This is a JWS (JSON Web Signature) structure with JWT claims contained in a JSON payload.
    #[diplomat::opaque]
    pub struct JwtSig(pub(crate) jwt::CheckedJwtSig<serde_json::Value>);

    impl JwtSig {
        pub fn builder() -> Box<JwtSigBuilder> {
            JwtSigBuilder::init()
        }

        /// Returns the content type.
        // TODO: support for optional string in return position
        pub fn get_content_type(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(write!(writeable, "{}", self.0.header.cty.as_deref().unwrap_or("")));
            writeable.flush();
            Ok(()).into()
        }

        /// Returns the key ID.
        // TODO: support for optional string in return position
        pub fn get_kid(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(write!(writeable, "{}", self.0.header.kid.as_deref().unwrap_or("")));
            writeable.flush();
            Ok(()).into()
        }

        /// Returns the header as a JSON encoded payload.
        pub fn get_header(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            let header = err_check!(serde_json::to_string(&self.0.header));
            err_check!(write!(writeable, "{header}"));
            writeable.flush();
            Ok(()).into()
        }

        /// Returns the claims as a JSON encoded payload.
        pub fn get_claims(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            let claims = err_check!(serde_json::to_string(&self.0.state.claims));
            err_check!(write!(writeable, "{claims}"));
            writeable.flush();
            Ok(()).into()
        }

        /// Decode JWT and check signature using provided public key.
        pub fn decode(
            compact_repr: &str,
            public_key: &PublicKey,
            validator: &JwtValidator,
        ) -> DiplomatResult<Box<JwtSig>, Box<PickyError>> {
            let jwt = err_check_from!(picky::jose::jwt::JwtSig::decode(compact_repr, &public_key.0)
                .and_then(|jwt| jwt.validate::<serde_json::Value>(&validator.0)));
            Ok(Box::new(JwtSig(jwt))).into()
        }

        /// Encode using the given private key and returns the compact representation of this token.
        pub fn encode(
            &self,
            key: &PrivateKey,
            writeable: &mut DiplomatWriteable,
        ) -> DiplomatResult<(), Box<PickyError>> {
            let encoded = err_check!(self.0.clone().encode(&key.0));
            err_check!(write!(writeable, "{encoded}"));
            writeable.flush();
            Ok(()).into()
        }
    }

    #[diplomat::opaque]
    pub struct JwtSigBuilder(pub(crate) super::SigBuilderInner);

    impl JwtSigBuilder {
        pub fn init() -> Box<JwtSigBuilder> {
            Box::new(Self(super::SigBuilderInner {
                alg: JwsAlg::RS256,
                cty: None,
                kid: None,
                claims: serde_json::Value::Null,
                additional_headers: std::collections::HashMap::new(),
            }))
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
        pub fn add_additional_parameter_object(
            &mut self,
            name: &str,
            obj: &str,
        ) -> DiplomatResult<(), Box<PickyError>> {
            let parameter = err_check!(serde_json::from_str(obj));
            self.0.additional_headers.insert(name.to_owned(), parameter);
            Ok(()).into()
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

        /// Sets the given JSON payload.
        ///
        /// Claims should be a valid JSON payload.
        pub fn set_claims(&mut self, claims: &str) -> DiplomatResult<(), Box<PickyError>> {
            let claims = err_check!(serde_json::from_str(claims));
            self.0.claims = claims;
            Ok(()).into()
        }

        pub fn build(&self) -> Box<JwtSig> {
            let claims = self.0.claims.clone();
            let mut jwt = jwt::CheckedJwtSig::new(self.0.alg.into(), claims);
            jwt.header.cty = self.0.cty.clone();
            jwt.header.kid = self.0.kid.clone();
            jwt.header.additional = self.0.additional_headers.clone();
            Box::new(JwtSig(jwt))
        }
    }

    #[diplomat::opaque]
    pub struct JwtValidator(jwt::JwtValidator);

    impl JwtValidator {
        /// Check signature and the registered exp and nbf claims. If a claim is missing token is rejected.
        pub fn strict(numeric_date: i64, leeway: u16) -> Box<JwtValidator> {
            Box::new(Self(jwt::JwtValidator::strict(jwt::JwtDate::new_with_leeway(
                numeric_date,
                leeway,
            ))))
        }

        /// Check signature and the registered exp and nbf claims. Token isn't rejected if a claim is missing.
        pub fn lenient(numeric_date: i64, leeway: u16) -> Box<JwtValidator> {
            Box::new(Self(jwt::JwtValidator::lenient(jwt::JwtDate::new_with_leeway(
                numeric_date,
                leeway,
            ))))
        }

        /// No check.
        pub fn no_check() -> Box<JwtValidator> {
            Box::new(Self(jwt::JwtValidator::no_check()))
        }
    }
}
