#[macro_use]
extern crate serde_derive;

pub mod controllers;
pub mod error;
pub mod models;
pub mod oids;
pub mod pem;
pub mod serde;

#[cfg(test)]
mod test_files {
    pub const RSA_2048_PK_1: &str = include_str!("../test_files/private_keys/rsa-2048-pk_1.key");
    //pub const RSA_2048_PK_2: &str = include_str!("../test_files/private_keys/rsa-2048-pk_2.key");
    //pub const RSA_2048_PK_3: &str = include_str!("../test_files/private_keys/rsa-2048-pk_3.key");
    //pub const RSA_2048_PK_4: &str = include_str!("../test_files/private_keys/rsa-2048-pk_4.key");
    //pub const RSA_2048_PK_5: &str = include_str!("../test_files/private_keys/rsa-2048-pk_5.key");
    //pub const RSA_2048_PK_6: &str = include_str!("../test_files/private_keys/rsa-2048-pk_6.key");
    //pub const RSA_4096_PK_1: &str = include_str!("../test_files/private_keys/rsa-4096-pk_1.key");
    //pub const RSA_4096_PK_2: &str = include_str!("../test_files/private_keys/rsa-4096-pk_2.key");
    //pub const RSA_4096_PK_3: &str = include_str!("../test_files/private_keys/rsa-4096-pk_3.key");

    pub const CSR: &str = include_str!("../test_files/certification_request.csr");

    pub const INTERMEDIATE_CA: &str = include_str!("../test_files/intermediate_ca.crt");
    pub const ROOT_CA: &str = include_str!("../test_files/root_ca.crt");
}
