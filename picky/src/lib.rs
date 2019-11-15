#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod models;
pub mod oids;
pub mod pem;
pub mod serde;

#[cfg(feature = "controller")]
pub mod controller;

#[cfg(test)]
mod test_files {
    pub const RSA_2048_PK_1: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");

    pub const CSR: &str = include_str!("../../test_assets/certification_request.csr");

    pub const INTERMEDIATE_CA: &str = include_str!("../../test_assets/intermediate_ca.crt");
    pub const ROOT_CA: &str = include_str!("../../test_assets/root_ca.crt");
}
