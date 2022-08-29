use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::common::hmac_sha1;
use crate::crypto::utils::{usage_ke, usage_ki};
use crate::crypto::{Cipher, CipherSuite, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt_des;
use super::encrypt::encrypt_des;
use super::key_derivation::derive_key;
use super::{DES3_BLOCK_SIZE, DES3_KEY_SIZE, DES3_MAC_SIZE, derive_key_from_password};

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

        todo!()
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt)
    }
}
