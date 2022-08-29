use hmac::{Hmac, Mac};
use sha1::Sha1;

pub fn hmac_sha1(key: &[u8], payload: &[u8], mac_size: usize) -> Vec<u8> {
    let key_len = key.len();
    let mut key = key.to_vec();

    // this Hmac implementation requires 64-byte key
    key.extend_from_slice(&vec![0; 64 - key_len]);

    let mut hmacker = Hmac::<Sha1>::new(key.as_slice().into());

    hmacker.update(payload);

    let mut hmac = hmacker.finalize().into_bytes().to_vec();
    hmac.resize(mac_size, 0);

    hmac
}
