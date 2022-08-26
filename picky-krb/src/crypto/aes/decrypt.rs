use crypto::aes::cbc_decryptor;
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

use crate::crypto::KerberosCryptoError;

use super::{swap_two_last_blocks, AesSize, AES_BLOCK_SIZE};

pub fn decrypt_aes(key: &[u8], cipher_data: &[u8], aes_size: AesSize) -> Result<Vec<u8>, KerberosCryptoError> {
    let mut cipher = cbc_decryptor(
        crypto::aes::KeySize::KeySize256,
        key,
        &vec![0; aes_size.block_bit_len() / 8],
        blockmodes::NoPadding,
    );

    let mut payload = vec![0; cipher_data.len()];

    cipher.decrypt(
        &mut RefReadBuffer::new(cipher_data),
        &mut RefWriteBuffer::new(&mut payload),
        true,
    )?;

    Ok(payload)
}

pub fn decrypt_aes_cts(key: &[u8], cipher_data: &[u8], aes_size: AesSize) -> Result<Vec<u8>, KerberosCryptoError> {
    if cipher_data.len() == AES_BLOCK_SIZE {
        return decrypt_aes(key, cipher_data, aes_size);
    }

    let pad_length = AES_BLOCK_SIZE - (cipher_data.len() % AES_BLOCK_SIZE);

    let mut plaintext;

    let mut cipher_data = cipher_data.to_vec();
    if pad_length != 16 {
        // Decrypt Cn-1 with IV = 0.
        let start = cipher_data.len() - 32 + pad_length;

        let dn = decrypt_aes(key, &cipher_data[start..start + 16], aes_size.clone())?;

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
