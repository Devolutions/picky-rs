use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::{Cipher, KerberosCryptoError, CipherSuites, utils::{usage_ke, usage_ki}, aes::encrypt::encrypt_aes_cts};

use super::{AES256_KEY_SIZE, key_derivation::derive_key, AES_BLOCK_SIZE, hmac_sha1, AesSize, AES_MAC_SIZE, decrypt::decrypt_aes_cts};

#[derive(Clone, Debug)]
pub struct Aes256CtsHmacSha196 {
    //
}

impl Aes256CtsHmacSha196 {
    pub fn new() -> Self {
        Self {}
    }
}

impl Cipher for Aes256CtsHmacSha196 {
    fn key_size(&self) -> usize {
        AES256_KEY_SIZE
    }

    fn confounder_byte_size(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn cipher_type(&self) -> CipherSuites {
        CipherSuites::Aes256CtsHmacSha196
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        if key.len() != AES256_KEY_SIZE {
            return Err(KerberosCryptoError::KeyLength(key.len(), AES256_KEY_SIZE));
        }
        
        // confounder (just random bytes)
        // let confounder = OsRng::default().gen::<[u8; AES_BLOCK_SIZE]>();
        let confounder = [161, 52, 157, 33, 238, 232, 185, 93, 167, 130, 91, 180, 167, 165, 224, 78];

        let mut data_to_encrypt = vec![0; self.confounder_byte_size() + payload.len()];
        data_to_encrypt[0..self.confounder_byte_size()].copy_from_slice(&confounder);
        data_to_encrypt[self.confounder_byte_size()..].copy_from_slice(payload);

        println!("data to enc: {:?}", data_to_encrypt);

        // derive key
        let ke = derive_key(key, &usage_ke(key_usage), AesSize::Aes256);
        println!("derived key: {:?}", key);

        // encrypt
        let mut encrypted = encrypt_aes_cts(&ke, &data_to_encrypt, AesSize::Aes256);
        println!("after enc: {:?}", encrypted);

        // append hash
        let ki = derive_key(key, &usage_ki(key_usage), AesSize::Aes256);
        let checksum = hmac_sha1(&ki, &data_to_encrypt);
        println!("checksum: {:?}", checksum);

        encrypted.extend_from_slice(&checksum);

        println!("enc: {:?}", encrypted);
        
        Ok(encrypted)
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        if cipher_data.len() < AES_BLOCK_SIZE + AES_MAC_SIZE {
            return Err(KerberosCryptoError::CipherLength(cipher_data.len(), AES_BLOCK_SIZE + AES_MAC_SIZE));
        }

        let (cipher_data, checksum) = cipher_data.split_at(cipher_data.len() - AES_MAC_SIZE);
        println!("checksum: {:?}", checksum);

        let ke = derive_key(key, &usage_ke(key_usage), AesSize::Aes256);
        let plaintext = decrypt_aes_cts(&ke, cipher_data, AesSize::Aes256);

        println!("plain text: {:?}", plaintext);

        let ki = derive_key(key, &usage_ki(key_usage), AesSize::Aes256);
        let calculated_checksum = hmac_sha1(&ki, &plaintext);

        if calculated_checksum != checksum {
            return Err(KerberosCryptoError::IntegrityCheck);
        }

        // [0..AES_BLOCK_SIZE..] = the first block is a random confounder bytes
        Ok(plaintext[AES_BLOCK_SIZE..].to_vec())
    }

    fn checksum(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use kerberos_crypto::new_kerberos_cipher;

    use crate::crypto::{aes::{key_derivation::derive_key_from_password, AesSize}, Cipher};

    use super::Aes256CtsHmacSha196;

    #[test]
    fn aes256_cts_hmac_sha1_96_encrypt() {
        let plaintext = [97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54];
        let key = derive_key_from_password("test", "EXAMPLEp1", AesSize::Aes256);
        println!("key: {:?}", key);
        let cipher = Aes256CtsHmacSha196::new();

        let encrypted = cipher.encrypt(&key, 5, &plaintext).unwrap();

        assert_eq!(&[214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219, 96, 18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220, 113, 173, 31, 154, 73, 236, 25], encrypted.as_slice());
    }

    #[test]
    fn aes256_cts_hmac_sha1_96_decrypt() {
        let cipher_data = [214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219, 96, 18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220, 113, 173, 31, 154, 73, 236, 25];
        let key = derive_key_from_password("test", "EXAMPLEp1", AesSize::Aes256);
        println!("key: {:?}", key);
        let cipher = Aes256CtsHmacSha196::new();

        let plaintext = cipher.decrypt(&key, 5, &cipher_data).unwrap();

        assert_eq!(&[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54], plaintext.as_slice());
    }

    #[test]
    fn t2() {
        let cipher_data = [214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219, 96, 18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220, 113, 173, 31, 154, 73, 236, 25];
        let mut c = new_kerberos_cipher(18).unwrap();
        let key = c.generate_key_from_string("test", "EXAMPLEp1".as_bytes());
        println!("key: {:?}", key);

        let plaintext = c.decrypt(&key, 5, &cipher_data).unwrap();
        println!("{:?}", plaintext);

        // assert_eq!(&[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54], plaintext.as_slice());
    }

    #[test]
    fn t() {
        let plaintext = [97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54];
        let mut c = new_kerberos_cipher(18).unwrap();
        let key = c.generate_key_from_string("test", "EXAMPLEp1".as_bytes());
        println!("key: {:?}", key);

        println!("{:?}", c.encrypt(&key, 5, &plaintext));
    }
}
