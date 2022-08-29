use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;

use crate::crypto::{KerberosCryptoError, KerberosCryptoResult};

use super::{DES3_BLOCK_SIZE, DES3_KEY_SIZE};

type DesCbcCipher = cbc::Decryptor<TdesEde3>;

pub fn decrypt_des(key: &[u8], payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
    if key.len() != DES3_KEY_SIZE {
        return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
    }

    let mut payload = payload.to_vec();

    // RFC 3961: initial cipher state      All bits zero
    let iv = [0_u8; DES3_BLOCK_SIZE];

    let cipher = DesCbcCipher::new(key.into(), (&iv as &[u8]).into());

    cipher.decrypt_padded_mut::<NoPadding>(&mut payload)?;

    Ok(payload)
}
