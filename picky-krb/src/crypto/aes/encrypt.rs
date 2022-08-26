use crypto::aes::cbc_encryptor;
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

use crate::crypto::KerberosCryptoResult;

use super::{swap_two_last_blocks, AesSize, AES_BLOCK_SIZE};

pub fn encrypt_aes(key: &[u8], plaintext: &[u8], aes_size: AesSize) -> KerberosCryptoResult<Vec<u8>> {
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

pub fn encrypt_aes_cts(key: &[u8], payload: &[u8], aes_size: AesSize) -> KerberosCryptoResult<Vec<u8>> {
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
