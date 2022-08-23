pub mod key_derivation;

use crypto::aes::cbc_encryptor;
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

const AES_BLOCK_SIZE: usize = 16;

pub const AES128_KEY_SIZE: usize = 128 / 8;
pub const AES256_KEY_SIZE: usize = 256 / 8;

#[derive(Clone, Debug, PartialEq)]
pub enum AesSize {
    Aes256,
    Aes128,
}

impl AesSize {
    pub fn key_length(&self) -> usize {
        match self {
            AesSize::Aes256 => AES256_KEY_SIZE,
            AesSize::Aes128 => AES128_KEY_SIZE,
        }
    }

    pub fn block_bit_len(&self) -> usize {
        match self {
            AesSize::Aes256 => AES_BLOCK_SIZE * 8,
            AesSize::Aes128 => AES_BLOCK_SIZE * 8,
        }
    }

    pub fn seed_bit_len(&self) -> usize {
        self.key_length() * 8
    }
}

pub fn encrypt_aes(key: &[u8], plaintext: &[u8], aes_size: AesSize) -> Vec<u8> {
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
    );

    cipher_data
}
