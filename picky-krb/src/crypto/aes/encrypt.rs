use rand::rngs::OsRng;
use rand::Rng;

use crypto::aes::cbc_encryptor;
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

use crate::crypto::aes::hmac_sha1;
use crate::crypto::aes::key_derivation::derive_key;
use crate::crypto::utils::usage_ki;
use crate::crypto::{KerberosCryptoError, KerberosCryptoResult};

use super::{swap_two_last_blocks, AesSize, AES_BLOCK_SIZE};

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

    let ke = derive_key(key, &usage_ki(key_usage), aes_size)?;
    let mut encrypted = encrypt_aes_cts(&ke, &data_to_encrypt, aes_size)?;

    let ki = derive_key(key, &usage_ki(key_usage), aes_size)?;
    let checksum = hmac_sha1(&ki, &data_to_encrypt);

    encrypted.extend_from_slice(&checksum);

    Ok(encrypted)
}

pub fn encrypt_aes(key: &[u8], plaintext: &[u8], aes_size: &AesSize) -> KerberosCryptoResult<Vec<u8>> {
    let mut cipher = cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
        key,
        &vec![0; aes_size.block_bit_len() / 8],
        blockmodes::NoPadding,
    );

    let mut cipher_data = vec![0; plaintext.len()];

    cipher.encrypt(
        &mut RefReadBuffer::new(plaintext),
        &mut RefWriteBuffer::new(&mut cipher_data),
        true,
    )?;

    Ok(cipher_data)
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
