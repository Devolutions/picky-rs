use crate::crypto::{Cipher, CipherSuite, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt;
use super::encrypt::encrypt;
use super::{AesSize, AES256_KEY_SIZE, derive_key_from_password};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Aes256CtsHmacSha196;

impl Aes256CtsHmacSha196 {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for Aes256CtsHmacSha196 {
    fn key_size(&self) -> usize {
        AES256_KEY_SIZE
    }

    fn cipher_type(&self) -> CipherSuite {
        CipherSuite::Aes256CtsHmacSha196
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        encrypt(key, key_usage, payload, &AesSize::Aes256)
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        decrypt(key, key_usage, cipher_data, &AesSize::Aes256)
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt, &AesSize::Aes128)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::aes::key_derivation::derive_key_from_password;
    use crate::crypto::aes::AesSize;
    use crate::crypto::Cipher;

    use super::Aes256CtsHmacSha196;

    #[test]
    fn aes256_cts_hmac_sha1_96_encrypt() {
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,
        ];
        let key = derive_key_from_password("test", "EXAMPLEp1", &AesSize::Aes256).unwrap();
        println!("key: {:?}", key);
        let cipher = Aes256CtsHmacSha196::new();

        let encrypted = cipher.encrypt(&key, 5, &plaintext).unwrap();

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219,
                96, 18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220,
                113, 173, 31, 154, 73, 236, 25
            ],
            encrypted.as_slice()
        );
    }

    #[test]
    fn aes256_cts_hmac_sha1_96_decrypt() {
        let cipher_data = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219, 96,
            18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220, 113, 173,
            31, 154, 73, 236, 25,
        ];
        let key = derive_key_from_password("test", "EXAMPLEp1", &AesSize::Aes256).unwrap();
        println!("key: {:?}", key);
        let cipher = Aes256CtsHmacSha196::new();

        let plaintext = cipher.decrypt(&key, 5, &cipher_data).unwrap();

        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54],
            plaintext.as_slice()
        );
    }
}
