pub(crate) mod decrypt;
pub(crate) mod des3_cbc_sha1_kd;
pub(crate) mod encrypt;
mod key_derivation;

pub const DES3_BLOCK_SIZE: usize = 8;
pub const DES3_KEY_SIZE: usize = 24;
pub const DES3_MAC_SIZE: usize = 3;

pub use des3_cbc_sha1_kd::Des3CbcSha1Kd;
pub use key_derivation::{derive_key, derive_key_from_password};
