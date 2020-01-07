use http::header::{HeaderName, InvalidHeaderName};
use std::str::FromStr;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Header {
    /// Lowercased HTTP header field name
    Name(HeaderName),
    /// Special `(request-target)` header field
    RequestTarget,
    /// Special `(created)` header field
    Created,
    /// Special `(expires)` header field
    Expires,
}

impl Header {
    pub const REQUEST_TARGET_STR: &'static str = "(request-target)";
    pub const CREATED_STR: &'static str = "(created)";
    pub const EXPIRES_STR: &'static str = "(expires)";

    pub fn as_str(&self) -> &str {
        match self {
            Header::Name(header_name) => header_name.as_str(),
            Header::RequestTarget => Self::REQUEST_TARGET_STR,
            Header::Created => Self::CREATED_STR,
            Header::Expires => Self::EXPIRES_STR,
        }
    }
}

impl ToString for Header {
    fn to_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl FromStr for Header {
    type Err = InvalidHeaderName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::REQUEST_TARGET_STR => Ok(Self::RequestTarget),
            Self::CREATED_STR => Ok(Self::Created),
            Self::EXPIRES_STR => Ok(Self::Expires),
            _ => Ok(Header::Name(HeaderName::from_str(s)?)),
        }
    }
}
