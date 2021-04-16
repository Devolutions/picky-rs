use base64::DecodeError;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::{Pem, PemError};
use picky::x509::certificate::CertError;
use picky::x509::csr::CsrError;
use picky::x509::Cert;
use serde::{de, ser, Serialize};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("duration since unix epoch")
        .as_secs()
}

// === Greedy Error === //

/// I eat and format any error I can
#[derive(Debug)]
pub struct GreedyError(pub String);

impl Error for GreedyError {}

impl fmt::Display for GreedyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for GreedyError {
    fn from(e: String) -> Self {
        Self(e)
    }
}

impl From<&str> for GreedyError {
    fn from(e: &str) -> Self {
        Self(e.to_owned())
    }
}

impl From<saphir::hyper::error::Error> for GreedyError {
    fn from(e: saphir::hyper::error::Error) -> Self {
        Self(format!("hyper: {}", e))
    }
}

impl From<PemError> for GreedyError {
    fn from(e: PemError) -> Self {
        Self(format!("pem: {}", e))
    }
}

impl From<CertError> for GreedyError {
    fn from(e: CertError) -> Self {
        Self(format!("cert: {}", e))
    }
}

impl From<CsrError> for GreedyError {
    fn from(e: CsrError) -> Self {
        Self(format!("csr: {}", e))
    }
}

impl From<serde_json::Error> for GreedyError {
    fn from(e: serde_json::Error) -> Self {
        Self(format!("json: {}", e))
    }
}

impl From<DecodeError> for GreedyError {
    fn from(e: DecodeError) -> Self {
        Self(format!("base64 decode: {}", e))
    }
}

/// A path or something else
#[derive(Clone, Debug)]
pub enum PathOr<T: Clone + Debug> {
    Path(PathBuf),
    Some(T),
}

macro_rules! path_or_impl_serde {
    ($ty:ident) => {
        impl<'de> de::Deserialize<'de> for PathOr<$ty> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                struct V;
                impl<'de> de::Visitor<'de> for V {
                    type Value = PathOr<$ty>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(concat!("a path or some pem-formatted ", stringify!($ty)))
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        if let Ok(pem) = v.parse::<Pem>() {
                            let thing = $ty::from_pem(&pem)
                                .map_err(|e| E::custom(format!(concat!(stringify!($ty), " from pem: {}"), e)))?;
                            Ok(PathOr::Some(thing))
                        } else {
                            Ok(PathOr::Path(PathBuf::from(v)))
                        }
                    }
                }

                deserializer.deserialize_str(V)
            }
        }

        impl Serialize for PathOr<$ty> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ser::Serializer,
            {
                let s = match self {
                    PathOr::Path(path) => path.to_string_lossy().into_owned(),
                    PathOr::Some(thing) => thing
                        .to_pem()
                        .map_err(|e| ser::Error::custom(format!(concat!(stringify!($ty), " to pem: {}"), e)))?
                        .to_string(),
                };

                serializer.serialize_str(&s)
            }
        }
    };
}

path_or_impl_serde!(Cert);
path_or_impl_serde!(PrivateKey);
path_or_impl_serde!(PublicKey);
