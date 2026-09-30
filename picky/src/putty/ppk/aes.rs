//! AES encryption and decryption utilities.

use crate::putty::PuttyError;
use aes::cipher::KeyIvInit;
use aes::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt};
use inout::InOutBufReserved;
use rand_core::Rng;
use zeroize::Zeroizing;

pub const KEY_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;

/// Returns a copy of the message, padded with random bytes to a multiple of the AES block size.
pub fn make_padding<R: Rng>(message: &[u8], mut rng: R) -> Zeroizing<Vec<u8>> {
    let unpadded_size = message.len();
    let padded_size = unpadded_size.next_multiple_of(BLOCK_SIZE);

    // Allocate the final size up front so growing the buffer can't leave a copy of the key behind.
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_size));
    padded.extend_from_slice(message);

    if padded_size != unpadded_size {
        padded.resize(padded_size, 0);
        rng.fill_bytes(&mut padded[unpadded_size..]);
    }

    padded
}

/// Encrypts the message in-place using AES-256 in CBC mode.
pub fn encrypt(message: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), PuttyError> {
    let encryptor = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| PuttyError::Aes)?;

    let inout = InOutBufReserved::from_mut_slice(message, message.len())?;
    encryptor
        .encrypt_padded_inout::<NoPadding>(inout)
        .map_err(|_| PuttyError::Aes)?;

    Ok(())
}

/// Decrypts the message in-place using AES-256 in CBC mode.
pub fn decrypt(message: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), PuttyError> {
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| PuttyError::Aes)?;

    let _ = decryptor
        .decrypt_padded_inout::<NoPadding>(message.into())
        .map_err(|_| PuttyError::Aes);

    Ok(())
}
