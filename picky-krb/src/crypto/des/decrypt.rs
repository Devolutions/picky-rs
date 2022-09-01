use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;

use crate::crypto::common::hmac_sha1;
use crate::crypto::utils::{usage_ke, usage_ki};
use crate::crypto::{KerberosCryptoError, KerberosCryptoResult};

use super::{derive_key, DES3_BLOCK_SIZE, DES3_KEY_SIZE, DES3_MAC_SIZE};

type DesCbcCipher = cbc::Decryptor<TdesEde3>;

//= [Cryptosystem Profile Based on Simplified Profile](https://datatracker.ietf.org/doc/html/rfc3961#section-5.3) =//
pub fn decrypt_message(key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
    if key.len() != DES3_KEY_SIZE {
        return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
    }

    // (C1,H1) = ciphertext
    let (cipher_data, checksum) = cipher_data.split_at(cipher_data.len() - DES3_MAC_SIZE);

    let ke = derive_key(key, &usage_ke(key_usage))?;
    // (P1, newIV) = D(Ke, C1, oldstate.ivec)
    let plaintext = decrypt_des(&ke, cipher_data)?;

    let ki = derive_key(key, &usage_ki(key_usage))?;
    let calculated_hmac = hmac_sha1(&ki, &plaintext, DES3_MAC_SIZE);

    // if (H1 != HMAC(Ki, P1)[1..h])
    if calculated_hmac != checksum {
        return Err(KerberosCryptoError::IntegrityCheck);
    }

    Ok(plaintext[DES3_BLOCK_SIZE..].to_vec())
}

pub fn decrypt_des(key: &[u8], payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
    if key.len() != DES3_KEY_SIZE {
        return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
    }

    let mut payload = payload.to_vec();

    // RFC 3961: initial cipher state      All bits zero
    let iv = [0_u8; DES3_BLOCK_SIZE];

    let cipher = DesCbcCipher::new(key.into(), &iv.into());

    cipher.decrypt_padded_mut::<NoPadding>(&mut payload)?;

    Ok(payload)
}
