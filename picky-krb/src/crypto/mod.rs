mod aes;
pub mod nfold;

/// https://www.rfc-editor.org/rfc/rfc3962.html#section-4
/// the 8-octet ASCII string "kerberos"
pub const KERBEROS: &[u8; 8] = b"kerberos";
