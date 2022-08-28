use crate::crypto::{Cipher, CipherSuites, KerberosCryptoResult};

use super::DES3_BLOCK_SIZE;

pub struct Des3CbcSha1Kd;

impl Des3CbcSha1Kd {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for Des3CbcSha1Kd {
    fn key_size(&self) -> usize {
        DES3_BLOCK_SIZE
    }

    fn cipher_type(&self) -> CipherSuites {
        CipherSuites::Des3CbcSha1Kd
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        todo!()
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        todo!()
    }

    fn checksum(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        todo!()
    }
}
