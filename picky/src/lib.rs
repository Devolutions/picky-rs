//! [![Crates.io](https://img.shields.io/crates/v/picky.svg)](https://crates.io/crates/picky)
//! [![docs.rs](https://docs.rs/picky/badge.svg)](https://docs.rs/picky)
//! ![Crates.io](https://img.shields.io/crates/l/picky)
//! # picky
//!
//! Portable X.509, PKI, JOSE and HTTP signature implementation.

#[cfg(feature = "http_signature")]
pub mod http;

#[cfg(feature = "jose")]
pub mod jose;

#[cfg(feature = "x509")]
pub mod x509;

#[cfg(feature = "ssh")]
pub mod ssh;

pub mod hash;
pub mod key;
pub mod pem;
pub mod signature;

pub use picky_asn1_x509::{oid, oids, AlgorithmIdentifier};

#[cfg(test)]
mod test_files {
    pub const RSA_2048_PK_1: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");
    pub const RSA_2048_PK_7: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_7.key");
    pub const RSA_4096_PK_3: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_3.key");

    pub const EC_NIST256_PK_1: &str = include_str!("../../test_assets/private_keys/ec-nist256-pk_1.key");

    // openssl ec -in ec-secp256r1-priv-key.pem -no_public -out ec-secp256r1-nopublic-priv-key.pem
    pub const EC_NIST256_NOPUBLIC_DER_PK_1: &str =
        include_str!("../../test_assets/private_keys/ec-nist256-nopublic-der-pk_1.key");

    // openssl ec -in ec-secp384r1-priv-key.pem -no_public -out ec-secp384r1-nopublic-priv-key.pem
    pub const EC_NIST384_NOPUBLIC_DER_PK_1: &str =
        include_str!("../../test_assets/private_keys/ec-nist384-nopublic-der-pk_1.key");

    pub const EC_NIST256_DER_PK_1: &str = include_str!("../../test_assets/private_keys/ec-nist256-der-pk_1.key");

    pub const EC_NIST384_DER_PK_1: &str = include_str!("../../test_assets/private_keys/ec-nist384-der-pk_1.key");

    pub const EC_NIST521_DER_PK_1: &str = include_str!("../../test_assets/private_keys/ec-nist521-der-pk_1.key");

    // openssl ecparam -name secp256r1 -genkey -noout -out ec-secp256r1-priv-key.pem
    // openssl ec -in ec-secp256r1-priv-key.pem -pubout > ec-secp256r1-pub-key.pem
    pub const EC_NIST256_PK_1_PUB: &str = include_str!("../../test_assets/public_keys/ec-nist256-pk_1.key");

    // openssl ecparam -name secp384r1 -genkey -noout -out ec-secp384r1-priv-key.pem
    // openssl ec -in ec-secp384r1-priv-key.pem -pubout > ec-secp384r1-pub-key.pem
    pub const EC_NIST384_PK_1_PUB: &str = include_str!("../../test_assets/public_keys/ec-nist384-pk_1.key");

    // openssl ecparam -name secp256k1 -genkey -noout -out ec-secp256k1-priv-key.pem
    // openssl ec -in ec-secp256k1-priv-key.pem -pubout > ec-secp256k1-pub-key.pem
    pub const EC_PUBLIC_KEY_SECP256K1_PEM: &str = include_str!("../../test_assets/public_keys/ec-secp256k1-pk_1.key");

    cfg_if::cfg_if! { if  #[cfg(feature = "pkcs7")]  {
        pub const PKCS7: &str = include_str!("../../test_assets/pkcs7.p7b");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "ctl")] {
        pub const CERTIFICATE_TRUST_LIST: &[u8] = include_bytes!("../../test_assets/authroot.stl");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "x509")] {
        pub const RSA_2048_PK_2: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_2.key");
        pub const RSA_2048_PK_3: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_3.key");
        pub const RSA_2048_PK_4: &str =
            include_str!("../../test_assets/private_keys/rsa-2048-pk_4.key");

        pub const EC_NIST256_PK_2: &str = include_str!("../../test_assets/private_keys/ec-nist256-pk_2.key");
        pub const EC_NIST384_PK_1: &str = include_str!("../../test_assets/private_keys/ec-nist384-pk_1.key");

        pub const INTERMEDIATE_CA: &str = include_str!("../../test_assets/intermediate_ca.crt");
        pub const ROOT_CA: &str = include_str!("../../test_assets/root_ca.crt");

        pub const PSDIAG_ROOT: &str = include_str!("../../test_assets/authenticode-psdiagnostics/1_psdiag_root.pem");
        pub const PSDIAG_INTER: &str = include_str!("../../test_assets/authenticode-psdiagnostics/2_psdiag_inter.pem");
        pub const PSDIAG_LEAF: &str = include_str!("../../test_assets/authenticode-psdiagnostics/3_psdiag_leaf.pem");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "jose")] {
        pub const JOSE_JWT_SIG_EXAMPLE: &str =
            include_str!("../../test_assets/jose/jwt_sig_example.txt");
        pub const JOSE_JWT_SIG_WITH_EXP: &str =
            include_str!("../../test_assets/jose/jwt_sig_with_exp.txt");
        pub const JOSE_JWK_SET: &str =
            include_str!("../../test_assets/jose/jwk_set.json");

        pub const JOSE_JWK_EC_P256_JSON: &str =
            include_str!("../../test_assets/jose/jwk_ec_p256.json");
        pub const JOSE_JWK_EC_P384_JSON: &str =
            include_str!("../../test_assets/jose/jwk_ec_p384.json");

        pub const JOSE_JWT_SIG_ES256: &str =
            include_str!("../../test_assets/jose/jwt_sig_es256.txt");
        pub const JOSE_JWT_SIG_ES384: &str =
            include_str!("../../test_assets/jose/jwt_sig_es384.txt");
    }}

    cfg_if::cfg_if! { if #[cfg(feature = "ssh")] {
        // ssh-keygen -t ecdsa -b 256 -C "test_ecdsa@picky.com"
        pub const SSH_PRIVATE_KEY_EC_P256: &str =
            include_str!("../../test_assets/ssh/ssh_key_p256");

        // ssh-keygen -t ecdsa -b 384 -C "test_ecdsa@picky.com"
        pub const SSH_PRIVATE_KEY_EC_P384: &str =
            include_str!("../../test_assets/ssh/ssh_key_p384");

        // ssh-keygen -t ecdsa -b 521 -C "test_ecdsa@picky.com"
        pub const SSH_PRIVATE_KEY_EC_P521: &str =
            include_str!("../../test_assets/ssh/ssh_key_p521");

        // ssh-keygen -t ecdsa -b 256 -C "test_ecdsa@picky.com"
        pub const SSH_PRIVATE_KEY_EC_P256_ENCRYPTED: &str =
            include_str!("../../test_assets/ssh/ssh_encrypted_key_p256");

        pub const SSH_PUBLIC_KEY_EC_P256: &str = include_str!("../../test_assets/ssh/ssh_key_p256.pub");
        pub const SSH_PUBLIC_KEY_EC_P384: &str = include_str!("../../test_assets/ssh/ssh_key_p384.pub");
        pub const SSH_PUBLIC_KEY_EC_P521: &str = include_str!("../../test_assets/ssh/ssh_key_p521.pub");

        // ssh-keygen -h -s ./ssh_ca_key -V '+1000w' -I abcd -z 00001 -n server.example.com ./ssh_key_p256.pub
        pub const SSH_CERT_EC_P256: &str = include_str!("../../test_assets/ssh/ssh_cert_p256.crt");
        // ssh-keygen -h -s ./ssh_ca_key -V '+1000w' -I abcd -z 00001 -n server.example.com ./ssh_key_p384.pub
        pub const SSH_CERT_EC_P384: &str = include_str!("../../test_assets/ssh/ssh_cert_p384.crt");

    }}
}
