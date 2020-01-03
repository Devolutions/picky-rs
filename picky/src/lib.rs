#[macro_use]
mod macros;
mod private;

#[cfg(feature = "http_signature")]
pub mod http;

#[cfg(feature = "jose")]
pub mod jose;

#[cfg(feature = "x509")]
pub mod x509;

pub mod algorithm_identifier;
pub mod key;
pub mod oids;
pub mod pem;
pub mod signature;

pub use algorithm_identifier::AlgorithmIdentifier;

#[cfg(test)]
mod test_files {
    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        pub const RSA_2048_PK_1: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");
        pub const RSA_2048_PK_2: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_2.key");
        pub const RSA_2048_PK_3: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_3.key");
        pub const RSA_2048_PK_4: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_4.key");

        pub const CSR: &str = include_str!("../../test_assets/certification_request.csr");

        pub const INTERMEDIATE_CA: &str = include_str!("../../test_assets/intermediate_ca.crt");
        pub const ROOT_CA: &str = include_str!("../../test_assets/root_ca.crt");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "jose")] {
        pub const JOSE_JWT_EXAMPLE: &str =
            include_str!("../../test_assets/jose/jwt_example.txt");
        pub const JOSE_JWT_WITH_EXP: &str =
            include_str!("../../test_assets/jose/jwt_with_exp.txt");
        pub const JOSE_JWK_SET: &str =
            include_str!("../../test_assets/jose/jwk_set.json");
    }}
}
