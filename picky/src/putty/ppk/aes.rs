//! AES encryption and decryption utilities.

use rand::RngCore;

use crate::putty::PuttyError;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

pub const KEY_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;

/// Adds padding to the message if it is not a multiple of the AES block size.
pub fn make_padding(mut message: Vec<u8>, mut rng: impl RngCore) -> Vec<u8> {
    if message.len() % BLOCK_SIZE != 0 {
        let unpadded_size = message.len();
        let padding_size = BLOCK_SIZE - (unpadded_size % BLOCK_SIZE);

        message.resize(unpadded_size + padding_size, 0);
        rng.fill_bytes(&mut message[unpadded_size..]);
    }

    message
}

/// Encrypts the message in-place using AES-256 in CBC mode.
pub fn encrypt(message: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), PuttyError> {
    let encryptor = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| PuttyError::Aes)?;

    let len = message.len();

    encryptor
        .encrypt_padded_mut::<NoPadding>(message, len)
        .map_err(|_| PuttyError::Aes)?;

    Ok(())
}

/// Decrypts the message in-place using AES-256 in CBC mode.
pub fn decrypt(message: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), PuttyError> {
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| PuttyError::Aes)?;

    let _ = decryptor
        .decrypt_padded_mut::<NoPadding>(message)
        .map_err(|_| PuttyError::Aes);

    Ok(())
}
