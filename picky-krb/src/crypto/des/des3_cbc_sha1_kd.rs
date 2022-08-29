use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::common::hmac_sha1;
use crate::crypto::utils::{usage_ke, usage_ki};
use crate::crypto::{Cipher, CipherSuite, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt_des;
use super::encrypt::encrypt_des;
use super::key_derivation::derive_key;
use super::{derive_key_from_password, DES3_BLOCK_SIZE, DES3_KEY_SIZE, DES3_MAC_SIZE};

#[derive(Debug, Clone, Default, PartialEq)]
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

    fn cipher_type(&self) -> CipherSuite {
        CipherSuite::Des3CbcSha1Kd
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        if key.len() != DES3_KEY_SIZE {
            return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
        }

        // confounder (just random bytes)
        #[cfg(test)]
        let confounder = [161, 52, 157, 33, 238, 232, 185, 93];
        #[cfg(not(test))]
        let confounder = OsRng::default().gen::<[u8; DES3_BLOCK_SIZE]>();

        let mut data_to_encrypt = vec![0; DES3_BLOCK_SIZE + payload.len()];

        data_to_encrypt[0..DES3_BLOCK_SIZE].copy_from_slice(&confounder);
        data_to_encrypt[DES3_BLOCK_SIZE..].copy_from_slice(payload);

        let pad_len = (DES3_BLOCK_SIZE - (data_to_encrypt.len() % DES3_BLOCK_SIZE)) % DES3_BLOCK_SIZE;
        data_to_encrypt.extend_from_slice(&vec![0; pad_len]);

        let ke = derive_key(key, &usage_ke(key_usage))?;
        let mut encrypted = encrypt_des(&ke, &data_to_encrypt)?;

        let ki = derive_key(key, &usage_ki(key_usage))?;
        let hmac = hmac_sha1(&ki, &data_to_encrypt, DES3_MAC_SIZE);

        encrypted.extend_from_slice(&hmac);

        Ok(encrypted)
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        if key.len() != DES3_KEY_SIZE {
            return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
        }

        let (cipher_data, checksum) = cipher_data.split_at(cipher_data.len() - DES3_MAC_SIZE);

        let ke = derive_key(key, &usage_ke(key_usage))?;
        let plaintext = decrypt_des(&ke, cipher_data)?;

        let ki = derive_key(key, &usage_ki(key_usage))?;
        let calculated_hmac = hmac_sha1(&ki, &plaintext, DES3_MAC_SIZE);

        if calculated_hmac != checksum {
            return Err(KerberosCryptoError::IntegrityCheck);
        }

        Ok(plaintext[DES3_BLOCK_SIZE..].to_vec())
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Cipher;

    use super::Des3CbcSha1Kd;

    #[test]
    fn encrypt() {
        let key = [
            115, 248, 21, 32, 230, 42, 157, 138, 158, 254, 157, 145, 13, 110, 64, 107, 173, 206, 247, 93, 55, 146, 167,
            138,
        ];
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,
        ];
        let cipher = Des3CbcSha1Kd::new();

        let cipher_data = cipher.encrypt(&key, 5, &plaintext).unwrap();

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
        let plaintext = [
            126, 136, 43, 80, 62, 251, 57, 122, 225, 31, 122, 177, 228, 203, 192, 209, 209, 50, 207, 26, 25, 42, 111,
            102, 243, 28, 130, 32, 30, 129, 155, 136, 93, 10, 246, 56, 89, 215, 120, 254, 207, 136, 121, 74, 156, 20,
            56, 227, 234, 98, 203, 221,
        ];
        let cipher = Des3CbcSha1Kd::new();

        let cipher_data = cipher.decrypt(&key, 5, &plaintext).unwrap();
        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 0],
            cipher_data.as_slice()
        );
    }
}
