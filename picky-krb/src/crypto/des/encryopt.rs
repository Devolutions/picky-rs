use aes::cipher::{KeyIvInit, BlockEncryptMut, block_padding::Pkcs7};
use crypto::blockmodes::CbcEncryptor;
use des::{Des, TdesEde3, TdesEee3};

use crate::crypto::{KerberosCryptoResult, KerberosCryptoError};

use super::{DES3_KEY_SIZE, DES3_BLOCK_SIZE};


pub fn encrypt(key: &[u8], payload: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
    if key.len() != DES3_KEY_SIZE {
        return Err(KerberosCryptoError::KeyLength(key.len(), DES3_KEY_SIZE));
    }

    let pad_length = (DES3_BLOCK_SIZE - (payload.len() % DES3_BLOCK_SIZE)) % DES3_BLOCK_SIZE;
    let payload_len = payload.len();
    let mut payload = payload.to_vec();
    payload.extend_from_slice(&vec![0; pad_length]); 

    type DesCbcCipher = cbc::Encryptor<TdesEde3>;
    let iv = [0_u8; 8];
    let ct = DesCbcCipher::new(
        key.into(),
        (&iv as &[u8]).into()
    );

    let mut buf = vec![0u8; payload.len() + DES3_BLOCK_SIZE];
    // println!("{} {}", buf.len(), payload.len());
    let res = ct.encrypt_padded_b2b_mut::<Pkcs7>(&payload, &mut buf).unwrap();

    Ok(res[0..payload.len()].to_vec())
}

#[cfg(test)]
mod tests {
    use super::encrypt;

    #[test]
    fn test_encrypt() {
        let key = &[78, 101, 119, 84, 114, 105, 112, 108,
        101, 68, 69, 83, 67, 105, 112, 104, 101, 114, 40, 107, 101, 121, 41, 46
        ];
        let payload = &[115, 114, 99, 47, 99, 114, 121, 112, 116, 111, 47, 100, 101, 115, 47, 100, 101, 115, 51, 95, 99, 98, 99, 95, 115, 104, 97, 49, 95, 107, 100, 46, 114, 115];

        let cipher = encrypt(key, payload).unwrap();

        assert_eq!(&[87_u8, 99, 22, 0, 235, 138, 12, 253, 230, 59, 41, 113, 167, 76, 242, 13, 165, 158, 210, 120, 86, 75, 221, 202, 86, 77, 170, 9, 146, 89, 112, 88, 71, 246, 188, 99, 190, 8, 2, 57], cipher.as_slice());
    }
}
