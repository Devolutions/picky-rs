use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::{Cipher, CipherSuite, KerberosCryptoResult};

use super::decrypt::decrypt_message;
use super::encrypt::encrypt_message;
use super::key_derivation::random_to_key;
use super::{derive_key_from_password, DES3_BLOCK_SIZE, DES3_KEY_SIZE, DES3_SEED_LEN};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Des3CbcSha1Kd;

impl Des3CbcSha1Kd {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for Des3CbcSha1Kd {
    fn key_size(&self) -> usize {
        DES3_KEY_SIZE
    }

    fn seed_bit_len(&self) -> usize {
        DES3_SEED_LEN * 8
    }

    fn random_to_key(&self, key: Vec<u8>) -> Vec<u8> {
        random_to_key(&key)
    }

    fn cipher_type(&self) -> CipherSuite {
        CipherSuite::Des3CbcSha1Kd
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        encrypt_message(key, key_usage, payload, OsRng::default().gen::<[u8; DES3_BLOCK_SIZE]>())
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        decrypt_message(key, key_usage, cipher_data)
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::des::decrypt::decrypt_message;
    use crate::crypto::des::encrypt::encrypt_message;

    #[test]
    fn encrypt() {
        let key = [
            115, 248, 21, 32, 230, 42, 157, 138, 158, 254, 157, 145, 13, 110, 64, 107, 173, 206, 247, 93, 55, 146, 167,
            138,
        ];
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,
        ];
        let confounder = [161, 52, 157, 33, 238, 232, 185, 93];

        let cipher_data = encrypt_message(&key, 5, &plaintext, confounder).unwrap();

        assert_eq!(
            &[
                126, 136, 43, 80, 62, 251, 57, 122, 225, 31, 122, 177, 228, 203, 192, 209, 209, 50, 207, 26, 25, 42,
                111, 102, 243, 28, 130, 32, 30, 129, 155, 136, 93, 10, 246, 56, 89, 215, 120, 254, 207, 136, 121, 74,
                156, 20, 56, 227, 234, 98, 203, 221
            ],
            cipher_data.as_slice()
        );
    }

    #[test]
    fn decrypt() {
        let key = [
            115, 248, 21, 32, 230, 42, 157, 138, 158, 254, 157, 145, 13, 110, 64, 107, 173, 206, 247, 93, 55, 146, 167,
            138,
        ];
        let payload = [
            126, 136, 43, 80, 62, 251, 57, 122, 225, 31, 122, 177, 228, 203, 192, 209, 209, 50, 207, 26, 25, 42, 111,
            102, 243, 28, 130, 32, 30, 129, 155, 136, 93, 10, 246, 56, 89, 215, 120, 254, 207, 136, 121, 74, 156, 20,
            56, 227, 234, 98, 203, 221,
        ];

        let plaintext = decrypt_message(&key, 5, &payload).unwrap();

        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 0],
            plaintext.as_slice()
        );
    }
}
