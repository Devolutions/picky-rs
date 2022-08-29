use crate::crypto::{Cipher, CipherSuites, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt;
use super::encrypt::encrypt;
use super::{AesSize, AES128_KEY_SIZE};

#[derive(Clone, Debug)]
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

    fn cipher_type(&self) -> CipherSuites {
        CipherSuites::Aes256CtsHmacSha196
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        encrypt(key, key_usage, payload, &AesSize::Aes128)
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        decrypt(key, key_usage, cipher_data, &AesSize::Aes128)
    }

    fn checksum(&self, _key: &[u8], _key_usage: i32, _payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        todo!()
    }
}
