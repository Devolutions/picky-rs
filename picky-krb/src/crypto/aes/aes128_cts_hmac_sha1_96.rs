use crate::crypto::{Cipher, CipherSuite, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt;
use super::encrypt::encrypt;
use super::{AesSize, AES128_KEY_SIZE, derive_key_from_password};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Aes128CtsHmacSha196;

impl Aes128CtsHmacSha196 {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for Aes128CtsHmacSha196 {
    fn key_size(&self) -> usize {
        AES128_KEY_SIZE
    }

    fn cipher_type(&self) -> CipherSuite {
        CipherSuite::Aes256CtsHmacSha196
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        encrypt(key, key_usage, payload, &AesSize::Aes128)
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        decrypt(key, key_usage, cipher_data, &AesSize::Aes128)
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt, &AesSize::Aes256)
    }
}
