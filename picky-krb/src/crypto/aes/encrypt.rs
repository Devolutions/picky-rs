use aes::cipher::block_padding::NoPadding;
use aes::cipher::{KeyIvInit, BlockEncryptMut};
use aes::{Aes256, Aes128};
use cbc::Encryptor;
use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::aes::key_derivation::derive_key;
use crate::crypto::common::hmac_sha1;
use crate::crypto::utils::{usage_ke, usage_ki};
use crate::crypto::{KerberosCryptoError, KerberosCryptoResult};

use super::{swap_two_last_blocks, AesSize, AES_BLOCK_SIZE, AES_MAC_SIZE};

pub type Aes256CbcEncryptor = Encryptor<Aes256>;
pub type Aes128CbcEncryptor = Encryptor<Aes128>;

pub fn encrypt(key: &[u8], key_usage: i32, payload: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    if key.len() != aes_size.key_length() {
        return Err(KerberosCryptoError::KeyLength(key.len(), aes_size.key_length()));
    }

    // confounder (just random bytes)
    #[cfg(test)]
    let confounder = [
        161, 52, 157, 33, 238, 232, 185, 93, 167, 130, 91, 180, 167, 165, 224, 78,
    ];
    #[cfg(not(test))]
    let confounder = OsRng::default().gen::<[u8; AES_BLOCK_SIZE]>();

    let mut data_to_encrypt = vec![0; aes_size.confounder_byte_size() + payload.len()];

    data_to_encrypt[0..aes_size.confounder_byte_size()].copy_from_slice(&confounder);
    data_to_encrypt[aes_size.confounder_byte_size()..].copy_from_slice(payload);

    let ke = derive_key(key, &usage_ke(key_usage), aes_size)?;
    println!("ke: {:?}", ke);
    let mut encrypted = encrypt_aes_cts(&ke, &data_to_encrypt, aes_size)?;
    println!("encrypted: {:?}", encrypted);

    let ki = derive_key(key, &usage_ki(key_usage), aes_size)?;
    println!("ki: {:?}", ki);
    let checksum = hmac_sha1(&ki, &data_to_encrypt, AES_MAC_SIZE);
    println!("checksum: {:?}", checksum);

    encrypted.extend_from_slice(&checksum);

    Ok(encrypted)
}

pub fn encrypt_aes(key: &[u8], plaintext: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    let iv = vec![0; AES_BLOCK_SIZE];

    let mut payload = plaintext.to_vec();
    let payload_len = payload.len();

    match aes_size {
        AesSize::Aes256 => {
            let cipher = Aes256CbcEncryptor::new(key.into(), iv.as_slice().into());
            cipher.encrypt_padded_mut::<NoPadding>(&mut payload, payload_len).unwrap();
        },
        AesSize::Aes128 => {
            let cipher = Aes128CbcEncryptor::new(key.into(), iv.as_slice().into());
            cipher.encrypt_padded_mut::<NoPadding>(&mut payload, payload_len)?;
        },
    }

    Ok(payload)
}

pub fn encrypt_aes_cts(key: &[u8], payload: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    let pad_length = (AES_BLOCK_SIZE - (payload.len() % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;

    let mut padded_payload = payload.to_vec();
    padded_payload.append(&mut vec![0; pad_length]);

    let mut ciphertext = encrypt_aes(key, &padded_payload, aes_size)?;

    if ciphertext.len() <= AES_BLOCK_SIZE {
        return Ok(ciphertext);
    }

    if ciphertext.len() >= 2 * AES_BLOCK_SIZE {
        swap_two_last_blocks(&mut ciphertext);
    }

    ciphertext.resize(payload.len(), 0);

    Ok(ciphertext)
}
