use hmac::{Hmac, Mac};
use sha1::Sha1;

//= [Checksum Profiles Based on Simplified Profile](https://datatracker.ietf.org/doc/html/rfc3961#section-5.4) =//
pub fn hmac_sha1(key: &[u8], payload: &[u8], mac_size: usize) -> Vec<u8> {
    let mut key = key.to_vec();

    // this Hmac implementation requires 64-byte key
    key.resize(64, 0);

    let mut hmacker = Hmac::<Sha1>::new(key.as_slice().into());

    hmacker.update(payload);

    let mut hmac = hmacker.finalize().into_bytes().to_vec();
    hmac.resize(mac_size, 0);

    hmac
}
