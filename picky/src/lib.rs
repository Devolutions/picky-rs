#[cfg(feature = "http_signature")]
pub mod http;

#[cfg(feature = "jose")]
pub mod jose;

#[cfg(feature = "x509")]
pub mod x509;

pub mod hash;
pub mod key;
pub mod pem;
pub mod signature;

pub use picky_asn1_x509::{oids, AlgorithmIdentifier};

#[cfg(test)]
mod test_files {
    pub const RSA_2048_PK_1: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");
    pub const RSA_2048_PK_7: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_7.key");
    pub const RSA_4096_PK_3: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_3.key");

    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        pub const RSA_2048_PK_2: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_2.key");
        pub const RSA_2048_PK_3: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_3.key");
        pub const RSA_2048_PK_4: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_4.key");

        pub const INTERMEDIATE_CA: &str = include_str!("../../test_assets/intermediate_ca.crt");
        pub const ROOT_CA: &str = include_str!("../../test_assets/root_ca.crt");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "jose")] {
        pub const JOSE_JWT_SIG_EXAMPLE: &str =
            include_str!("../../test_assets/jose/jwt_sig_example.txt");
        pub const JOSE_JWT_SIG_WITH_EXP: &str =
            include_str!("../../test_assets/jose/jwt_sig_with_exp.txt");
        pub const JOSE_JWK_SET: &str =
            include_str!("../../test_assets/jose/jwk_set.json");
    }}
}
