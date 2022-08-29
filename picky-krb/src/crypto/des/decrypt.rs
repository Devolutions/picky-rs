use aes::cipher::block_padding::Pkcs7;
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

    let ct = DesCbcCipher::new(key.into(), (&iv as &[u8]).into());

    let _cipher = ct
        .decrypt_padded_mut::<Pkcs7>(&mut payload)
        .map_err(|err| KerberosCryptoError::CipherPad(format!("{:?}", err)))?;

    Ok(payload)
}
