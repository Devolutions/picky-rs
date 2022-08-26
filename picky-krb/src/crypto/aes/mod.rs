pub mod key_derivation;
pub mod aes256_cts_hmac_sha1_96;
pub mod encrypt;
pub mod decrypt;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;

/// [Kerberos Algorithm Profile Parameters](https://www.rfc-editor.org/rfc/rfc3962.html#section-6)
/// cipher block size 16 octets
const AES_BLOCK_SIZE: usize = 16;
/// [Kerberos Algorithm Profile Parameters](https://www.rfc-editor.org/rfc/rfc3962.html#section-6)
/// HMAC output size = 12 octets
const AES_MAC_SIZE: usize = 12;

/// [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc3962.html#section-7)
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


pub fn swap_two_last_blocks(data: &mut [u8]) {
    let len = data.len();

    for i in 0..AES_BLOCK_SIZE {
        let temp = data[i + len - 2 * AES_BLOCK_SIZE];

        data[i + len - 2 * AES_BLOCK_SIZE] = data[i + len - AES_BLOCK_SIZE];
        data[i + len - AES_BLOCK_SIZE] = temp;
    }
}

pub fn hmac_sha1(key: &[u8], payload: &[u8]) -> Vec<u8> {
    println!("hmac key: {:?}", key);

    let mut hmacker = Hmac::new(Sha1::new(), &key);
    hmacker.input(payload);

    let mut hmac = hmacker.result().code().to_vec();
    hmac.resize(AES_MAC_SIZE, 0);

    hmac
}
