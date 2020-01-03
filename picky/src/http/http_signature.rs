use crate::{
    http::{
        http_request::{HttpRequest, HttpRequestError},
        Header,
    },
    key::{PrivateKey, PublicKey},
    signature::{SignatureError, SignatureHashType},
};
use base64::DecodeError;
use http::header::HeaderName;
use snafu::Snafu;
use std::{cell::RefCell, collections::HashMap, str::FromStr};

// === error type === //

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HttpSignatureError {
    /// couldn't decode base64
    #[snafu(display("couldn't decode base64: {}", source))]
    Base64Decoding { source: DecodeError },

    /// signature is not yet valid
    #[snafu(display("signature is not yet valid (created: {}, now: {})", created, now))]
    NotYetValid { created: u64, now: u64 },

    /// certificate expired
    #[snafu(display("certificate expired (not after: {}, now: {})", not_after, now))]
    Expired { not_after: u64, now: u64 },

    /// signature error occurred
    #[snafu(display("signature error: {}", source))]
    Signature { source: SignatureError },

    /// couldn't generate signing string
    #[snafu(display("couldn't generate signing string: {}", source))]
    SigningString { source: HttpRequestError },

    /// missing required builder argument
    #[snafu(display("missing required builder argument `{}`", arg))]
    MissingBuilderArgument { arg: &'static str },

    /// builder requires a non empty `headers` parameter
    BuilderEmptyHeaders,

    /// required parameter is missing from http signature string
    #[snafu(display("required parameter is missing from http signature string: {}", parameter))]
    MissingRequiredParameter { parameter: &'static str },

    /// a parameter is present but invalid
    #[snafu(display("invalid parameter: {}", parameter))]
    InvalidParameter { parameter: &'static str },
}

impl From<DecodeError> for HttpSignatureError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decoding { source: e }
    }
}

impl From<SignatureError> for HttpSignatureError {
    fn from(e: SignatureError) -> Self {
        Self::Signature { source: e }
    }
}

impl From<HttpRequestError> for HttpSignatureError {
    fn from(e: HttpRequestError) -> Self {
        Self::SigningString { source: e }
    }
}

// === http signature ===

/// Contains signature parameters.
///
/// This doesn't support `algorithm` signature parameter.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HttpSignature {
    /// An opaque string that the server can
    /// use to look up the component they need to validate the signature.
    pub key_id: String,

    /// In original string format, `headers` should be a lowercased, quoted list of HTTP header
    /// fields, separated by a single space character.
    ///
    /// For instance : `(request-target) (created) host date cache-control x-emptyheader x-example`.
    pub headers: Vec<Header>,

    /// The `created` field expresses when the signature was
    /// created.  The value MUST be a Unix timestamp integer value.  A
    /// signature with a `created` timestamp value that is in the future MUST
    /// NOT be processed.
    pub created: Option<u64>,

    /// The `expires` field expresses when the signature ceases to
    /// be valid.  The value MUST be a Unix timestamp integer value.  A
    /// signature with an `expires` timestamp value that is in the past MUST
    /// NOT be processed.
    pub expires: Option<u64>,

    /// Base 64 encoded digital signature, as described in RFC 4648, Section 4.  The
    /// client uses the `algorithm` and `headers` signature parameters to
    /// form a canonicalized `signing string`.  This `signing string` is then
    /// signed with the key associated with `key_id` and the algorithm
    /// corresponding to `algorithm`.  The `signature` parameter is then set
    /// to the base 64 encoding of the signature.
    pub signature: String,
}

impl HttpSignature {
    pub fn verify(
        &self,
        signature_type: SignatureHashType,
        public_key: &PublicKey,
        signing_string: &str,
        now: u64,
    ) -> Result<(), HttpSignatureError> {
        if let Some(expires) = self.expires {
            if expires < now {
                return Err(HttpSignatureError::Expired {
                    not_after: expires,
                    now,
                });
            }
        }

        if let Some(created) = self.created {
            if now < created {
                return Err(HttpSignatureError::NotYetValid { created, now });
            }
        }

        let decoded_signature = base64::decode(&self.signature)?;
        signature_type.verify(public_key, signing_string.as_bytes(), &decoded_signature)?;

        Ok(())
    }
}

const HTTP_SIGNATURE_HEADER: &str = "Signature";
const HTTP_SIGNATURE_KEY_ID: &str = "keyId";
const HTTP_SIGNATURE_SIGNATURE: &str = "signature";
const HTTP_SIGNATURE_CREATED: &str = "created";
const HTTP_SIGNATURE_EXPIRES: &str = "expires";
const HTTP_SIGNATURE_HEADERS: &str = "headers";

impl ToString for HttpSignature {
    fn to_string(&self) -> String {
        let mut acc = Vec::with_capacity(5);

        acc.push(format!(
            "{} {}=\"{}\"",
            HTTP_SIGNATURE_HEADER, HTTP_SIGNATURE_KEY_ID, self.key_id
        ));

        if let Some(created) = self.created {
            acc.push(format!("{}=\"{}\"", HTTP_SIGNATURE_CREATED, created));
        }

        if let Some(expires) = self.expires {
            acc.push(format!("{}=\"{}\"", HTTP_SIGNATURE_EXPIRES, expires));
        }

        acc.push(format!(
            "{}=\"{}\"",
            HTTP_SIGNATURE_HEADERS,
            self.headers
                .iter()
                .map(|header| header.as_str())
                .collect::<Vec<&str>>()
                .join(" "),
        ));

        acc.push(format!("{}=\"{}\"", HTTP_SIGNATURE_SIGNATURE, self.signature));

        acc.join(", ")
    }
}

impl FromStr for HttpSignature {
    type Err = HttpSignatureError;

    fn from_str(http_authorization_header: &str) -> Result<Self, Self::Err> {
        let items = http_authorization_header
            .trim_start_matches(HTTP_SIGNATURE_HEADER)
            .split(',')
            .collect::<Vec<&str>>();
        let mut keys = HashMap::new();
        for item in items {
            if let Some(index) = item.find('=') {
                let (key, value) = item.split_at(index);
                if value.len() >= 3 {
                    keys.insert(key.trim(), value[2..value.len() - 1].to_owned());
                }
            }
        }

        let headers = {
            if let Some(headers_str) = keys.remove(HTTP_SIGNATURE_HEADERS) {
                let headers_str_vec = headers_str.split(' ').collect::<Vec<&str>>();
                let mut headers = Vec::with_capacity(headers_str_vec.len());
                for header_str in headers_str_vec {
                    headers.push(
                        Header::from_str(header_str).map_err(|_| HttpSignatureError::InvalidParameter {
                            parameter: HTTP_SIGNATURE_HEADERS,
                        })?,
                    );
                }
                headers
            } else {
                vec![Header::Created]
            }
        };

        let created = if let Some(created) = keys.remove(HTTP_SIGNATURE_CREATED) {
            Some(
                created
                    .parse::<u64>()
                    .map_err(|_| HttpSignatureError::InvalidParameter {
                        parameter: HTTP_SIGNATURE_CREATED,
                    })?,
            )
        } else {
            None
        };

        let expires = if let Some(created) = keys.remove(HTTP_SIGNATURE_EXPIRES) {
            Some(
                created
                    .parse::<u64>()
                    .map_err(|_| HttpSignatureError::InvalidParameter {
                        parameter: HTTP_SIGNATURE_EXPIRES,
                    })?,
            )
        } else {
            None
        };

        Ok(HttpSignature {
            key_id: keys
                .remove(HTTP_SIGNATURE_KEY_ID)
                .ok_or_else(|| HttpSignatureError::MissingRequiredParameter {
                    parameter: HTTP_SIGNATURE_KEY_ID,
                })?,
            headers,
            created,
            expires,
            signature: keys.remove(HTTP_SIGNATURE_SIGNATURE).ok_or_else(|| {
                HttpSignatureError::MissingRequiredParameter {
                    parameter: HTTP_SIGNATURE_SIGNATURE,
                }
            })?,
        })
    }
}

// === http signature builder === //

// Statically checks the field actually exists and returns a &'static str of the field name
macro_rules! field_str {
    ($field:ident) => {{
        ::static_assertions::assert_fields!(HttpSignatureBuilderInner: $field);
        stringify!($field)
    }};
}

#[derive(Default, Clone, Debug)]
struct HttpSignatureBuilderInner<'a> {
    key_id: Option<String>,
    signature_method: Option<(&'a PrivateKey, SignatureHashType)>,
    created: Option<u64>,
    expires: Option<u64>,
    headers: Vec<Header>,
}

#[derive(Default, Clone, Debug)]
/// Utility to generate `HttpSignature`s
pub struct HttpSignatureBuilder<'a> {
    inner: RefCell<HttpSignatureBuilderInner<'a>>,
}

impl<'a> HttpSignatureBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    /// Required
    pub fn key_id<S: Into<String>>(&self, key_id: S) -> &Self {
        self.inner.borrow_mut().key_id = Some(key_id.into());
        self
    }

    #[inline]
    /// Required
    pub fn signature_method(&self, private_key: &'a PrivateKey, signature_type: SignatureHashType) -> &Self {
        self.inner.borrow_mut().signature_method = Some((private_key, signature_type));
        self
    }

    #[inline]
    /// At least one of `created`, `expires`, `request_target` or `http_header` is required.
    pub fn created(&self, unix_timestamp: u64) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.created = Some(unix_timestamp);
        inner_mut.headers.push(Header::Created);
        drop(inner_mut);
        self
    }

    #[inline]
    /// At least one of `created`, `expires`, `request_target` or `http_header` is required.
    pub fn expires(&self, unix_timestamp: u64) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.expires = Some(unix_timestamp);
        inner_mut.headers.push(Header::Expires);
        drop(inner_mut);
        self
    }

    #[inline]
    /// At least one of `created`, `expires`, `request_target` or `http_header` is required.
    pub fn request_target(&self) -> &Self {
        self.inner.borrow_mut().headers.push(Header::RequestTarget);
        self
    }

    #[inline]
    /// At least one of `created`, `expires`, `request_target` or `http_header` is required.
    pub fn http_header(&self, header: HeaderName) -> &Self {
        self.inner.borrow_mut().headers.push(Header::Name(header));
        self
    }

    pub fn build(&self, http_request: &impl HttpRequest) -> Result<HttpSignature, HttpSignatureError> {
        let mut inner = self.inner.borrow_mut();

        let (private_key, signature_type) = {
            inner
                .signature_method
                .take()
                .ok_or(HttpSignatureError::MissingBuilderArgument {
                    arg: field_str!(signature_method),
                })?
        };
        let key_id = inner.key_id.take().ok_or(HttpSignatureError::MissingBuilderArgument {
            arg: field_str!(key_id),
        })?;

        let created = inner.created.take();
        let expires = inner.expires.take();
        let headers: Vec<Header> = inner.headers.drain(..).collect();

        if headers.is_empty() {
            return Err(HttpSignatureError::BuilderEmptyHeaders);
        }

        drop(inner);

        let signing_string = {
            // Generate signing string.
            // See https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.3

            let mut acc = Vec::with_capacity(headers.len());
            for header in &headers {
                match header {
                    Header::Name(header_name) => {
                        let concatenated_values = http_request.get_header_concatenated_values(header_name)?;
                        if concatenated_values.is_empty() {
                            acc.push(format!("{}:", header_name.as_str()));
                        } else {
                            acc.push(format!("{}: {}", header_name.as_str(), concatenated_values));
                        }
                    }
                    Header::RequestTarget => {
                        acc.push(format!(
                            "{} {}",
                            http_request.get_lowercased_method()?,
                            http_request.get_target()?
                        ));
                    }
                    Header::Created => acc.push(format!(
                        "{}: {}",
                        header.as_str(),
                        created.expect("Some by builder construction")
                    )),
                    Header::Expires => acc.push(format!(
                        "{}: {}",
                        header.as_str(),
                        expires.expect("Some by builder construction")
                    )),
                }
            }

            acc.join("\n")
        };

        let signature_binary = signature_type.sign(signing_string.as_bytes(), private_key)?;

        Ok(HttpSignature {
            key_id,
            headers,
            created,
            expires,
            signature: base64::encode(&signature_binary),
        })
    }
}
