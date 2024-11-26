use saphir::http::StatusCode;
use saphir::request::Request;
use std::fmt;

// === result extension === //

pub trait StatusCodeResult<T> {
    fn bad_request(self) -> Result<T, StatusCode>;
    fn bad_request_desc(self, desc: &str) -> Result<T, StatusCode>;

    fn not_found(self) -> Result<T, StatusCode>;

    fn internal_error(self) -> Result<T, StatusCode>;
    fn internal_error_desc(self, desc: &str) -> Result<T, StatusCode>;

    fn service_unavailable(self) -> Result<T, StatusCode>;
}

macro_rules! status_code_on_error {
    ($result:ident, $code:ident) => {{
        match $result {
            Ok(val) => Ok(val),
            Err(e) => {
                log::error!("{}", e);
                Err(StatusCode::$code)
            }
        }
    }};
    ($result:ident, $code:ident, $desc:ident) => {{
        match $result {
            Ok(val) => Ok(val),
            Err(e) => {
                log::error!("{}: {}", $desc, e);
                Err(StatusCode::$code)
            }
        }
    }};
}

impl<T, E: fmt::Display> StatusCodeResult<T> for Result<T, E> {
    fn bad_request(self) -> Result<T, StatusCode> {
        status_code_on_error!(self, BAD_REQUEST)
    }

    fn bad_request_desc(self, desc: &str) -> Result<T, StatusCode> {
        status_code_on_error!(self, BAD_REQUEST, desc)
    }

    fn not_found(self) -> Result<T, StatusCode> {
        status_code_on_error!(self, NOT_FOUND)
    }

    fn internal_error(self) -> Result<T, StatusCode> {
        status_code_on_error!(self, INTERNAL_SERVER_ERROR)
    }

    fn internal_error_desc(self, desc: &str) -> Result<T, StatusCode> {
        status_code_on_error!(self, INTERNAL_SERVER_ERROR, desc)
    }

    fn service_unavailable(self) -> Result<T, StatusCode> {
        status_code_on_error!(self, SERVICE_UNAVAILABLE)
    }
}

macro_rules! status_code_on_none {
    ($opt:ident, $code:ident) => {{
        $opt.ok_or(StatusCode::$code)
    }};
    ($opt:ident, $code:ident, $desc:ident) => {{
        match $opt {
            Some(val) => Ok(val),
            None => {
                log::error!("{}", $desc);
                Err(StatusCode::$code)
            }
        }
    }};
}

impl<T> StatusCodeResult<T> for Option<T> {
    fn bad_request(self) -> Result<T, StatusCode> {
        status_code_on_none!(self, BAD_REQUEST)
    }

    fn bad_request_desc(self, desc: &str) -> Result<T, StatusCode> {
        status_code_on_none!(self, BAD_REQUEST, desc)
    }

    fn not_found(self) -> Result<T, StatusCode> {
        status_code_on_none!(self, NOT_FOUND)
    }

    fn internal_error(self) -> Result<T, StatusCode> {
        status_code_on_none!(self, INTERNAL_SERVER_ERROR)
    }

    fn internal_error_desc(self, desc: &str) -> Result<T, StatusCode> {
        status_code_on_none!(self, INTERNAL_SERVER_ERROR, desc)
    }

    fn service_unavailable(self) -> Result<T, StatusCode> {
        status_code_on_none!(self, SERVICE_UNAVAILABLE)
    }
}

// === saphir request extension === //

pub trait SaphirRequestExt {
    fn get_header_string_value(&self, header_name: &str) -> Option<String>;
}

impl<T> SaphirRequestExt for Request<T> {
    fn get_header_string_value(&self, header_name: &str) -> Option<String> {
        if let Some(hdr) = self.headers().get(header_name) {
            if let Ok(hdr_value) = hdr.to_str() {
                if !hdr_value.is_empty() {
                    return Some(hdr_value.to_string());
                }
            }
        }
        None
    }
}

// === header format === //

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    PemFile,
    Json,
    PkixCertBinary,
    PkixCertBase64,
    Pkcs10Binary,
    Pkcs10Base64,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Format::PemFile => write!(f, "pem file"),
            Format::Json => write!(f, "json"),
            Format::PkixCertBinary => write!(f, "binary-encoded pkix-cert"),
            Format::PkixCertBase64 => write!(f, "base64-encoded pkix-cert"),
            Format::Pkcs10Binary => write!(f, "binary-encoded pkcs10"),
            Format::Pkcs10Base64 => write!(f, "base64-encoded pkcs10"),
        }
    }
}

impl Format {
    pub fn request_format<T>(req: &Request<T>) -> Result<Self, String> {
        let content_type_opt = req.get_header_string_value("Content-Type");

        if let Some(content_type) = content_type_opt {
            Self::new(content_type.as_str())
        } else {
            Err("Content-Type header is missing".to_string())
        }
    }

    pub fn response_format<T>(req: &Request<T>) -> Result<Self, String> {
        let accept_opt = req.get_header_string_value("Accept").map(|s| {
            // cannot panic
            s.split(',').next().unwrap().split(';').next().unwrap().to_owned()
        });

        if let Some(accept) = accept_opt {
            Self::new(accept.as_str())
        } else {
            Err("Accept header is missing".to_string())
        }
    }

    fn new(mime: &str) -> Result<Self, String> {
        match mime {
            "application/x-pem-file" => Ok(Self::PemFile),
            "application/json" => Ok(Self::Json),
            "application/pkix-cert" => Ok(Self::PkixCertBinary),
            "application/pkix-cert-base64" => Ok(Self::PkixCertBase64),
            "application/pkcs10" => Ok(Self::Pkcs10Binary),
            "application/pkcs10-base64" => Ok(Self::Pkcs10Base64),
            unsupported => Err(format!("unsupported format: {}", unsupported)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saphir::prelude::Body;

    fn new_saphir_request(headers: Vec<(&'static str, &'static str)>) -> Request<Body> {
        use saphir::http::header::HeaderValue;

        let mut request = saphir::http::Request::builder();
        for (header, value) in headers.into_iter() {
            request
                .headers_mut()
                .expect("headers mut")
                .insert(header, HeaderValue::from_static(value));
        }
        Request::new(request.body(Body::empty()).expect("request"), None)
    }

    #[test]
    fn request_format() {
        let format =
            Format::request_format(&new_saphir_request(vec![("Content-Type", "application/x-pem-file")])).unwrap();
        assert_eq!(format, Format::PemFile);

        let format = Format::request_format(&new_saphir_request(vec![("Content-Type", "application/json")])).unwrap();
        assert_eq!(format, Format::Json);

        let format =
            Format::request_format(&new_saphir_request(vec![("Content-Type", "application/pkix-cert")])).unwrap();
        assert_eq!(format, Format::PkixCertBinary);

        let format =
            Format::request_format(&new_saphir_request(vec![("Content-Type", "application/pkcs10-base64")])).unwrap();
        assert_eq!(format, Format::Pkcs10Base64);
    }

    #[test]
    fn request_format_err() {
        let err = Format::request_format(&new_saphir_request(vec![])).err().unwrap();
        assert_eq!(err, "Content-Type header is missing");

        let err = Format::request_format(&new_saphir_request(vec![("Content-Type", "application/unknown")]))
            .err()
            .unwrap();
        assert_eq!(err, "unsupported format: application/unknown");
    }

    #[test]
    fn response_format() {
        let format = Format::response_format(&new_saphir_request(vec![("Accept", "application/x-pem-file")])).unwrap();
        assert_eq!(format, Format::PemFile);

        let format = Format::response_format(&new_saphir_request(vec![(
            "Accept",
            "application/json;q=0.5, application/x-pem-file",
        )]))
        .unwrap();
        assert_eq!(format, Format::Json);

        let format = Format::response_format(&new_saphir_request(vec![(
            "Accept",
            "application/pkix-cert, application/pkix-cert-base64, application/x-pem-file, snateinsrturiest",
        )]))
        .unwrap();
        assert_eq!(format, Format::PkixCertBinary);

        let format =
            Format::response_format(&new_saphir_request(vec![("Accept", "application/pkcs10-base64;q=1")])).unwrap();
        assert_eq!(format, Format::Pkcs10Base64);
    }

    #[test]
    fn response_format_err() {
        let err = Format::response_format(&new_saphir_request(vec![])).err().unwrap();
        assert_eq!(err, "Accept header is missing");
    }
}
