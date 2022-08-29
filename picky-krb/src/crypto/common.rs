use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;

pub fn hmac_sha1(key: &[u8], payload: &[u8], mac_size: usize) -> Vec<u8> {
    let mut hmacker = Hmac::new(Sha1::new(), key);
    hmacker.input(payload);

    let mut hmac = hmacker.result().code().to_vec();
    hmac.resize(mac_size, 0);

    hmac
}
