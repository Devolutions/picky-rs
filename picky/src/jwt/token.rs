use crate::{
    key::{PrivateKey, PublicKey},
    signature::{SignatureError, SignatureHashType},
};
use base64::DecodeError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::Snafu;
use std::borrow::Cow;

#[derive(Debug, Snafu)]
pub enum JwtError {
    /// RSA error
    #[snafu(display("RSA error: {}", context))]
    Rsa { context: String },

    /// Json error
    #[snafu(display("JSON error: {}", source))]
    Json { source: serde_json::Error },

    /// signature error
    #[snafu(display("signature error: {}", source))]
    Signature { source: SignatureError },

    /// invalid token encoding
    #[snafu(display("input isn't a valid token string: {}", input))]
    InvalidEncoding { input: String },

    /// couldn't decode base64
    #[snafu(display("couldn't decode base64: {}", source))]
    Base64Decoding { source: DecodeError },

    /// input isn't valid utf8
    #[snafu(display("input isn't valid utf8: {}, input: {:?}", source, input))]
    InvalidUtf8 {
        source: std::string::FromUtf8Error,
        input: Vec<u8>,
    },

    /// expected JWT but got an unexpected type
    #[snafu(display("header says input is not a JWT: expected JWT, found {}", typ))]
    UnexpectedType { typ: String },
}

impl From<rsa::errors::Error> for JwtError {
    fn from(e: rsa::errors::Error) -> Self {
        JwtError::Rsa {
            context: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(e: serde_json::Error) -> Self {
        JwtError::Json { source: e }
    }
}

impl From<SignatureError> for JwtError {
    fn from(e: SignatureError) -> Self {
        JwtError::Signature { source: e }
    }
}

impl From<DecodeError> for JwtError {
    fn from(e: DecodeError) -> Self {
        JwtError::Base64Decoding { source: e }
    }
}

const JWT_TYPE: &str = "JWT";

#[derive(Serialize, Deserialize, Debug)]
struct Header<'a> {
    alg: SignatureHashType,
    typ: Cow<'a, str>,
}

pub struct Jwt<'a, C> {
    header: Header<'a>,
    claims: C,
}

impl<'a, C> Jwt<'a, C> {
    pub fn new(hashtype: SignatureHashType, claims: C) -> Self {
        Jwt {
            header: Header {
                alg: hashtype,
                typ: Cow::Borrowed("JWT"),
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
}

impl<'a, C: Serialize> Jwt<'a, C> {
    pub fn encode(&self, private_key: &PrivateKey) -> Result<String, JwtError> {
        let header_base64 =
            base64::encode_config(&serde_json::to_vec(&self.header)?, base64::URL_SAFE_NO_PAD);
        let claims_base64 =
            base64::encode_config(&serde_json::to_vec(&self.claims)?, base64::URL_SAFE_NO_PAD);
        let header_claims = [header_base64, claims_base64].join(".");
        let signature = self
            .header
            .alg
            .sign(header_claims.as_bytes(), private_key)?;
        let signature_base64 = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
        Ok([header_claims, signature_base64].join("."))
    }
}

impl<'a, C: DeserializeOwned> Jwt<'a, C> {
    pub fn decode(encoded_token: &str, public_key: &PublicKey) -> Result<Self, JwtError> {
        let first_dot_idx = encoded_token
            .find('.')
            .ok_or_else(|| JwtError::InvalidEncoding {
                input: encoded_token.to_owned(),
            })?;

        let last_dot_idx = encoded_token
            .rfind('.')
            .ok_or_else(|| JwtError::InvalidEncoding {
                input: encoded_token.to_owned(),
            })?;

        snafu::ensure!(
            first_dot_idx != last_dot_idx && last_dot_idx + 1 < encoded_token.len(),
            InvalidEncoding {
                input: encoded_token.to_owned(),
            }
        );

        let header_json =
            base64::decode_config(&encoded_token[..first_dot_idx], base64::URL_SAFE_NO_PAD)?;
        let header = serde_json::from_slice::<Header>(&header_json)?;

        snafu::ensure!(
            header.typ == JWT_TYPE,
            UnexpectedType {
                typ: header.typ.to_owned(),
            }
        );

        let signature =
            base64::decode_config(&encoded_token[last_dot_idx + 1..], base64::URL_SAFE_NO_PAD)?;

        header.alg.verify(
            public_key,
            &encoded_token[..last_dot_idx].as_bytes(),
            &signature,
        )?;

        let claims_json = base64::decode_config(
            &encoded_token[first_dot_idx + 1..last_dot_idx],
            base64::URL_SAFE_NO_PAD,
        )?;
        let claims = serde_json::from_slice(&claims_json)?;

        Ok(Jwt { header, claims })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::Pem;

    const ENCODED_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3\
                               ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MT\
                               UxNjIzOTAyMn0.ekfvYsHi-JLCVSDY3QzveVYCnZzeotJ0WS_GO3dxQODW\
                               iX5hR2WRkePOm2WKl-5ChXjE4_T4kcukgcKHQtXZ5m68kM6RyRrkRqrk3L\
                               6EftR2DAslATNXDLM3JPEzvcLgFI1U1BFeELw9GGo8HHx9j7nAMJmBCIvS\
                               HPDWsQxq9Xkoa2jOTwmtn5JX9WMFwbtKSN-POdNaa8gBIn9NJhtjSDPtCq\
                               ATFai7N6EcBcOhd7p8RWFbgiA_92FAgZW1P6XMxVRT1BHlw3YL9HS80QBr\
                               OyyD-daWq5FQZWY-kljVhCALLLvSr43pq4XwO1h66iegyWIVLSFyVfOAWl\
                               lw7BoYPQ";

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Claims {
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

    #[test]
    fn encode_rsa_sha256() {
        let claims = Claims {
            sub: Cow::Borrowed("1234567890"),
            name: Cow::Borrowed("John Doe"),
            admin: true,
            iat: 1516239022,
        };

        let jwt = Jwt::new(SignatureHashType::RsaSha256, claims);
        let encoded = jwt.encode(&get_private_key_1()).unwrap();
        assert_eq!(encoded, ENCODED_JWT);
    }

    #[test]
    fn decode_rsa_sha256() {
        let public_key = get_private_key_1().to_public_key();
        let jwt = Jwt::<Claims>::decode(ENCODED_JWT, &public_key).unwrap();
        let claims = jwt.into_claims();
        assert_eq!(
            claims,
            Claims {
                sub: Cow::Borrowed("1234567890"),
                name: Cow::Borrowed("John Doe"),
                admin: true,
                iat: 1516239022,
            },
        )
    }

    #[test]
    fn decode_rsa_sha256_invalid_signature_err() {
        let public_key = get_private_key_2().to_public_key();
        let err = Jwt::<Claims>::decode(ENCODED_JWT, &public_key)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "signature error: invalid signature");
    }

    #[test]
    fn decode_invalid_base64_err() {
        let public_key = get_private_key_1().to_public_key();
        let err = Jwt::<Claims>::decode("aieoè~†.tésp.à", &public_key)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "couldn\'t decode base64: Invalid byte 195, offset 4."
        );
    }

    #[test]
    fn decode_invalid_json_err() {
        let public_key = get_private_key_1().to_public_key();

        let err = Jwt::<Claims>::decode("abc.abc.abc", &public_key)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "JSON error: expected value at line 1 column 1"
        );

        let err = Jwt::<Claims>::decode("eyAiYWxnIjogIkhTMjU2IH0K.abc.abc", &public_key)
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

        let err = Jwt::<Claims>::decode("abc.abc.", &public_key)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "input isn\'t a valid token string: abc.abc."
        );

        let err = Jwt::<Claims>::decode("abc.abc", &public_key).err().unwrap();
        assert_eq!(
            err.to_string(),
            "input isn\'t a valid token string: abc.abc"
        );

        let err = Jwt::<Claims>::decode("abc", &public_key).err().unwrap();
        assert_eq!(err.to_string(), "input isn\'t a valid token string: abc");
    }
}
