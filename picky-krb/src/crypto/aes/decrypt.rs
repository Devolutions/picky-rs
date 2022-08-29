use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::{Aes128, Aes256};

use crate::crypto::common::hmac_sha1;
use crate::crypto::utils::{usage_ke, usage_ki};
use crate::crypto::{KerberosCryptoError, KerberosCryptoResult};

use super::key_derivation::derive_key;
use super::{swap_two_last_blocks, AesSize, AES_BLOCK_SIZE, AES_MAC_SIZE};

pub type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
pub type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;

pub fn decrypt(key: &[u8], key_usage: i32, cipher_data: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    if cipher_data.len() < AES_BLOCK_SIZE + AES_MAC_SIZE {
        return Err(KerberosCryptoError::CipherLength(
            cipher_data.len(),
            AES_BLOCK_SIZE + AES_MAC_SIZE,
        ));
    }

    let (cipher_data, checksum) = cipher_data.split_at(cipher_data.len() - AES_MAC_SIZE);

    let ke = derive_key(key, &usage_ke(key_usage), aes_size)?;
    let plaintext = decrypt_aes_cts(&ke, cipher_data, aes_size)?;

    let ki = derive_key(key, &usage_ki(key_usage), aes_size)?;
    let calculated_checksum = hmac_sha1(&ki, &plaintext, AES_MAC_SIZE);

    if calculated_checksum != checksum {
        return Err(KerberosCryptoError::IntegrityCheck);
    }

    // [0..AES_BLOCK_SIZE] = the first block is a random confounder bytes. skip them
    Ok(plaintext[AES_BLOCK_SIZE..].to_vec())
}

pub fn decrypt_aes(key: &[u8], cipher_data: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    let mut cipher_data = cipher_data.to_vec();

    let iv = vec![0; AES_BLOCK_SIZE];

    match aes_size {
        AesSize::Aes256 => {
            let cipher = Aes256CbcDecryptor::new(key.into(), iv.as_slice().into());
            cipher.decrypt_padded_mut::<NoPadding>(&mut cipher_data)?;
        }
        AesSize::Aes128 => {
            let cipher = Aes128CbcDecryptor::new(key.into(), iv.as_slice().into());
            cipher.decrypt_padded_mut::<NoPadding>(&mut cipher_data)?;
        }
    }

    Ok(cipher_data)
}

pub fn decrypt_aes_cts(key: &[u8], cipher_data: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    if cipher_data.len() == AES_BLOCK_SIZE {
        return decrypt_aes(key, cipher_data, aes_size);
    }

    let pad_length = (AES_BLOCK_SIZE - (cipher_data.len() % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;

    let mut plaintext;

    let mut cipher_data = cipher_data.to_vec();

    if pad_length != 16 {
        // Decrypt Cn-1 with IV = 0.
        let start = cipher_data.len() + pad_length - 32;

        let dn = decrypt_aes(key, &cipher_data[start..start + 16], aes_size)?;

        let dn_len = dn.len();
        cipher_data.extend_from_slice(&dn[dn_len - pad_length..]);
    }

    if cipher_data.len() >= 2 * AES_BLOCK_SIZE {
        swap_two_last_blocks(&mut cipher_data);
    }

    plaintext = decrypt_aes(key, &cipher_data, aes_size)?;

    plaintext.resize(cipher_data.len() - pad_length, 0);

    Ok(plaintext)
}
