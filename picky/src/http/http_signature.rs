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
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::HashMap,
    fmt::{self, Debug},
    str::FromStr,
};

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
    SigningStringGeneration { source: HttpRequestError },

    /// invalid signing string
    #[snafu(display("signing string invalid for line `{}`", line))]
    InvalidSigningString { line: String },

    /// missing required builder argument
    #[snafu(display("missing required builder argument `{}`", arg))]
    MissingBuilderArgument { arg: &'static str },

    /// builder requires a non empty `headers` parameter
    BuilderEmptyHeaders,

    /// `headers` parameter shouldn't be provided when using builder with a pre-generated signing string
    BuilderHeadersProvidedWithPreGenerated,

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
        Self::SigningStringGeneration { source: e }
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
    pub fn verifier<'a>(&'a self) -> HttpSignatureVerifier<'a> {
        HttpSignatureVerifier {
            http_signature: self,
            inner: Default::default(),
        }
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
                vec![]
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

macro_rules! builder_argument_missing_err {
    ($field:ident) => {{
        ::static_assertions::assert_fields!(HttpSignatureBuilderInner: $field);
        HttpSignatureError::MissingBuilderArgument {
            arg: stringify!($field),
        }
    }};
}

#[derive(Clone)]
enum SigningStringGenMethod<'a> {
    PreGenerated(&'a str),
    FromHttpRequest(&'a dyn HttpRequest),
}

impl<'a> Debug for SigningStringGenMethod<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningStringGenMethod::")?;
        match self {
            SigningStringGenMethod::PreGenerated(signing_string) => write!(f, "PreGenerated({})", signing_string),
            SigningStringGenMethod::FromHttpRequest(_) => write!(f, "FromHttpRequest(...)"),
        }
    }
}

#[derive(Default, Clone, Debug)]
struct HttpSignatureBuilderInner<'a> {
    key_id: Option<String>,
    signature_method: Option<(&'a PrivateKey, SignatureHashType)>,
    created: Option<u64>,
    expires: Option<u64>,
    headers: Vec<Header>,
    signing_string_generation: Option<SigningStringGenMethod<'a>>,
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
    /// If generating signing string, at least one of `created`, `expires`, `request_target`
    /// or `http_header` is required otherwise DO NOT provide.
    pub fn created(&self, unix_timestamp: u64) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.created = Some(unix_timestamp);
        inner_mut.headers.push(Header::Created);
        drop(inner_mut);
        self
    }

    #[inline]
    /// If generating signing string, at least one of `created`, `expires`, `request_target`
    /// or `http_header` is required otherwise DO NOT provide.
    pub fn expires(&self, unix_timestamp: u64) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.expires = Some(unix_timestamp);
        inner_mut.headers.push(Header::Expires);
        drop(inner_mut);
        self
    }

    #[inline]
    /// If generating signing string, at least one of `created`, `expires`, `request_target`
    /// or `http_header` is required otherwise DO NOT provide.
    pub fn request_target(&self) -> &Self {
        self.inner.borrow_mut().headers.push(Header::RequestTarget);
        self
    }

    #[inline]
    /// If generating signing string, at least one of `created`, `expires`, `request_target`
    /// or `http_header` is required otherwise DO NOT provide.
    pub fn http_header(&self, header: HeaderName) -> &Self {
        self.inner.borrow_mut().headers.push(Header::Name(header));
        self
    }

    #[inline]
    /// Required (alternative: `pre_generated_signing_string`).
    pub fn generate_signing_string_using_http_request(&self, http_request: &'a dyn HttpRequest) -> &Self {
        self.inner.borrow_mut().signing_string_generation = Some(SigningStringGenMethod::FromHttpRequest(http_request));
        self
    }

    #[inline]
    /// Required (alternative: `generate_signing_string_using_http_request`).
    pub fn pre_generated_signing_string(&self, signing_string: &'a str) -> &Self {
        self.inner.borrow_mut().signing_string_generation = Some(SigningStringGenMethod::PreGenerated(signing_string));
        self
    }

    pub fn build(&self) -> Result<HttpSignature, HttpSignatureError> {
        let mut inner = self.inner.borrow_mut();

        let (private_key, signature_type) = {
            inner
                .signature_method
                .take()
                .ok_or(builder_argument_missing_err!(signature_method))?
        };
        let key_id = inner.key_id.take().ok_or(builder_argument_missing_err!(key_id))?;

        let signing_string_generation = inner
            .signing_string_generation
            .take()
            .ok_or(builder_argument_missing_err!(signing_string_generation))?;

        let mut created = inner.created.take();
        let mut expires = inner.expires.take();
        let mut headers: Vec<Header> = inner.headers.drain(..).collect();

        drop(inner);

        let signature_binary = match signing_string_generation {
            SigningStringGenMethod::PreGenerated(signing_string) => {
                if !headers.is_empty() {
                    return Err(HttpSignatureError::BuilderHeadersProvidedWithPreGenerated);
                }

                // parse pre-generated signing string to fill our HttpSignature struct properly.

                for line in signing_string.lines() {
                    let mut split = line.split(":");
                    let key = split.next().expect("there is always at least one element in the split");
                    if let Some(value) = split.next() {
                        match key {
                            Header::CREATED_STR => {
                                headers.push(Header::Created);
                                created =
                                    Some(value.trim().parse().map_err(|_| {
                                        HttpSignatureError::InvalidSigningString { line: line.to_owned() }
                                    })?);
                            }
                            Header::EXPIRES_STR => {
                                headers.push(Header::Expires);
                                expires =
                                    Some(value.trim().parse().map_err(|_| {
                                        HttpSignatureError::InvalidSigningString { line: line.to_owned() }
                                    })?);
                            }
                            header_name => headers
                                .push(Header::Name(HeaderName::from_str(header_name).map_err(|_| {
                                    HttpSignatureError::InvalidSigningString { line: line.to_owned() }
                                })?)),
                        }
                    } else if key.starts_with("get")
                        || key.starts_with("post")
                        || key.starts_with("put")
                        || key.starts_with("delete")
                    {
                        headers.push(Header::RequestTarget);
                    } else {
                        return Err(HttpSignatureError::InvalidSigningString { line: line.to_owned() });
                    }
                }

                signature_type.sign(signing_string.as_bytes(), private_key)?
            }
            SigningStringGenMethod::FromHttpRequest(http_request) => {
                // Generate signing string.
                // See https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.3

                if headers.is_empty() {
                    return Err(HttpSignatureError::BuilderEmptyHeaders);
                }

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

                let signing_string = acc.join("\n");

                signature_type.sign(signing_string.as_bytes(), private_key)?
            }
        };

        Ok(HttpSignature {
            key_id,
            headers,
            created,
            expires,
            signature: base64::encode(&signature_binary),
        })
    }
}

// === http signature verifier === /

macro_rules! verifier_argument_missing_err {
    ($field:ident) => {{
        ::static_assertions::assert_fields!(HttpSignatureVerifierInner: $field);
        HttpSignatureError::MissingBuilderArgument {
            arg: stringify!($field),
        }
    }};
}

#[derive(Default, Clone, Debug)]
struct HttpSignatureVerifierInner<'a> {
    now: Option<u64>,
    signature_method: Option<(&'a PublicKey, SignatureHashType)>,
    signing_string_generation: Option<SigningStringGenMethod<'a>>,
}

#[derive(Clone, Debug)]
/// Utility to verify `HttpSignature`s
pub struct HttpSignatureVerifier<'a> {
    http_signature: &'a HttpSignature,
    inner: RefCell<HttpSignatureVerifierInner<'a>>,
}

impl<'a> HttpSignatureVerifier<'a> {
    #[inline]
    /// Optional. Required only if http signature contains (expires) or (created) parameters.
    pub fn now(&self, unix_timestamp: u64) -> &Self {
        self.inner.borrow_mut().now = Some(unix_timestamp);
        self
    }

    #[inline]
    /// Required
    pub fn signature_method(&self, public_key: &'a PublicKey, signature_type: SignatureHashType) -> &Self {
        self.inner.borrow_mut().signature_method = Some((public_key, signature_type));
        self
    }

    #[inline]
    /// Required (alternative: `pre_generated_signing_string`).
    pub fn generate_signing_string_using_http_request(&self, http_request: &'a dyn HttpRequest) -> &Self {
        self.inner.borrow_mut().signing_string_generation = Some(SigningStringGenMethod::FromHttpRequest(http_request));
        self
    }

    #[inline]
    /// Required (alternative: `generate_signing_string_using_http_request`).
    pub fn pre_generated_signing_string(&self, signing_string: &'a str) -> &Self {
        self.inner.borrow_mut().signing_string_generation = Some(SigningStringGenMethod::PreGenerated(signing_string));
        self
    }

    pub fn verify(&self) -> Result<(), HttpSignatureError> {
        let mut inner = self.inner.borrow_mut();

        let (public_key, signature_type) = {
            inner
                .signature_method
                .take()
                .ok_or(verifier_argument_missing_err!(signature_method))?
        };

        let signing_string_generation = inner
            .signing_string_generation
            .take()
            .ok_or(verifier_argument_missing_err!(signing_string_generation))?;

        if let Some(expires) = self.http_signature.expires {
            let now = inner.now.take().ok_or(verifier_argument_missing_err!(now))?;
            if expires < now {
                return Err(HttpSignatureError::Expired {
                    not_after: expires,
                    now,
                });
            }
        }

        if let Some(created) = self.http_signature.created {
            let now = inner.now.take().ok_or(verifier_argument_missing_err!(now))?;
            if now < created {
                return Err(HttpSignatureError::NotYetValid { created, now });
            }
        }

        drop(inner);

        let signing_string = match signing_string_generation {
            SigningStringGenMethod::PreGenerated(signing_string) => Cow::Borrowed(signing_string),
            SigningStringGenMethod::FromHttpRequest(http_request) => {
                let headers = if self.http_signature.headers.is_empty() {
                    &[Header::Created][..]
                } else {
                    self.http_signature.headers.as_slice()
                };

                let mut acc = Vec::with_capacity(headers.len());
                for header in headers {
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
                            self.http_signature.created.ok_or_else(|| {
                                HttpSignatureError::MissingRequiredParameter {
                                    parameter: HTTP_SIGNATURE_CREATED,
                                }
                            })?
                        )),
                        Header::Expires => acc.push(format!(
                            "{}: {}",
                            header.as_str(),
                            self.http_signature.expires.ok_or_else(|| {
                                HttpSignatureError::MissingRequiredParameter {
                                    parameter: HTTP_SIGNATURE_EXPIRES,
                                }
                            })?
                        )),
                    }
                }

                Cow::Owned(acc.join("\n"))
            }
        };

        let decoded_signature = base64::decode(&self.http_signature.signature)?;
        signature_type.verify(public_key, signing_string.as_bytes(), &decoded_signature)?;

        Ok(())
    }
}
