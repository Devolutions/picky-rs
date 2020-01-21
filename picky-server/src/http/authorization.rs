use crate::configuration::ServerConfig;
use picky::jose::jwt::{Jwt, JwtDate, JwtValidator};
use saphir::{header, SyncRequest};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CsrClaims {
    pub sub: String,
    pub nbf: u64,
    pub exp: u64,
}

#[derive(Copy, Clone, Debug)]
pub enum AuthorizationMethod {
    Bearer,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum Authorized {
    ApiKey,
    Token(Jwt<'static, serde_json::Value>),
}

impl From<&str> for AuthorizationMethod {
    fn from(method_str: &str) -> Self {
        if unicase::eq_ascii(method_str, "bearer") {
            Self::Bearer
        } else {
            Self::Unknown
        }
    }
}

pub fn check_authorization(config: &ServerConfig, req: &SyncRequest) -> Result<Authorized, String> {
    let header = match req.headers_map().get(header::AUTHORIZATION) {
        Some(h) => h,
        None => return Err("Authorization header is missing".to_owned()),
    };

    let auth_str = match header.to_str() {
        Ok(s) => s,
        Err(_e) => return Err("Authorization header can't be converted in string".to_owned()),
    };

    let auth_vec = auth_str.split(' ').collect::<Vec<&str>>();
    if auth_vec.len() < 2 {
        return Err(format!("Authorization header wrong format: {}", auth_str));
    }
    let method = AuthorizationMethod::from(auth_vec[0]);
    match method {
        AuthorizationMethod::Bearer => {
            let token = auth_vec[1];
            if token == config.api_key {
                return Ok(Authorized::ApiKey);
            }

            // try JWT
            let public_key = config
                .provisioner_public_key
                .as_ref()
                .ok_or_else(|| "provisioner public key is missing".to_owned())?;
            Ok(Authorized::Token(
                Jwt::decode(
                    auth_vec[1],
                    &JwtValidator::strict(public_key, &JwtDate::new_with_leeway(epoch_until!(0) as i64, 10)),
                )
                .map_err(|e| format!("couldn't validate json web token: {}", e))?,
            ))
        }
        AuthorizationMethod::Unknown => Err(format!("Unknown authorization method: {}", auth_vec[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::BackendType;
    use http::{request, Method};
    use picky::{
        key::{PrivateKey, PublicKey},
        pem::Pem,
        signature::SignatureHashType,
    };

    fn get_private_key_1() -> PrivateKey {
        let pem = include_str!("../../../test_assets/private_keys/rsa-2048-pk_4.key")
            .parse::<Pem>()
            .expect("pem 1");
        PrivateKey::from_pem(&pem).expect("key 1")
    }

    fn get_private_key_2() -> PrivateKey {
        let pem = include_str!("../../../test_assets/private_keys/rsa-2048-pk_7.key")
            .parse::<Pem>()
            .expect("pem 2");
        PrivateKey::from_pem(&pem).expect("key 2")
    }

    fn get_csr_token(private_key: &PrivateKey) -> String {
        let claims = CsrClaims {
            sub: "CoolSubject".to_owned(),
            nbf: epoch_until!(0),
            exp: epoch_until!(10),
        };
        let jwt = Jwt::new(SignatureHashType::RsaSha256, claims);
        jwt.encode(&private_key).expect("jwt encode")
    }

    fn build_saphir_req(token: &str) -> SyncRequest {
        let req = request::Builder::new()
            .method(Method::POST)
            .uri("/sign")
            .header(header::DATE, "Tue, 07 Jun 2014 20:51:35 GMT")
            .header(header::AUTHORIZATION, format!("BEARER {}", token))
            .body(vec![])
            .expect("couldn't build request");
        let (parts, body) = req.into_parts();
        SyncRequest::new(parts, body)
    }

    fn config(den_key: Option<PublicKey>) -> ServerConfig {
        let mut config = ServerConfig::default();
        config.backend = BackendType::Memory;
        config.provisioner_public_key = den_key;
        config
    }

    #[test]
    fn token_authorized() {
        let key = get_private_key_1();
        let token = get_csr_token(&key);
        let saphir_req = build_saphir_req(&token);
        let config = config(Some(key.to_public_key()));
        match check_authorization(&config, &saphir_req).expect("auth") {
            Authorized::Token(_) => {}
            unexpected => panic!("expected token, got {:?}", unexpected),
        }
    }

    #[test]
    fn token_unauthorized_bad_signature() {
        let token = get_csr_token(&get_private_key_1());
        let saphir_req = build_saphir_req(&token);
        let config = config(Some(get_private_key_2().to_public_key()));
        let err = check_authorization(&config, &saphir_req).err().expect("auth err");
        assert_eq!(
            err,
            "couldn\'t validate json web token: signature error: invalid signature"
        );
    }

    #[test]
    fn token_unauthorized_no_den_key() {
        let token = get_csr_token(&get_private_key_1());
        let saphir_req = build_saphir_req(&token);
        let config = config(None);
        let err = check_authorization(&config, &saphir_req).err().expect("auth err");
        assert_eq!(err, "provisioner public key is missing");
    }
}
