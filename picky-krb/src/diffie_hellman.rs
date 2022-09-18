use sha1::{Sha1, Digest};

use crate::crypto::{KerberosCryptoError, KerberosCryptoResult, Cipher};


pub struct Key(pub Vec<u8>);

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// K-truncate truncates its input to the first K bits
fn k_truncate(k: usize, mut data: Vec<u8>) -> KerberosCryptoResult<Vec<u8>> {
    if k % 8 != 0 {
        return Err(KerberosCryptoError::SeedBitLen(format!("Seed bit len must be a multiple of 8. Got: {}", k)));
    }

    let bytes_len = k / 8;

    if bytes_len > data.len() {
        return Err(KerberosCryptoError::CipherLength(data.len(), bytes_len));
    }

    data.resize(bytes_len, 0);

    Ok(data)
}

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// octetstring2key(x) == random-to-key(K-truncate(
///                          SHA1(0x00 | x) |
///                          SHA1(0x01 | x) |
///                          SHA1(0x02 | x) |
///                          ...
///                          ))
fn octet_string_to_key(x: &[u8], cipher: impl Cipher) -> KerberosCryptoResult<Vec<u8>> {
    let seed_len = cipher.seed_bit_len() / 8;

    let mut key = Vec::new();

    let mut i = 0;
    while key.len() < seed_len {
        let mut data = vec![i];
        data.extend_from_slice(x);

        let mut sha1 = Sha1::new();
        sha1.update(data);

        key.extend_from_slice(sha1.finalize().as_slice());
        i += 1;
    }

    Ok(cipher.random_to_key(k_truncate(seed_len, key)?))
}

pub struct DhNonce<'a> {
    pub client_nonce: &'a [u8],
    pub server_nonce: &'a [u8],
}

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// let n_c be the clientDHNonce and n_k be the serverDHNonce; otherwise, let both n_c and n_k be empty octet strings.
/// k = octetstring2key(DHSharedSecret | n_c | n_k)
pub fn generate_key(dh_shared_secret: &[u8], nonce: Option<DhNonce>, cipher: impl Cipher) -> KerberosCryptoResult<Vec<u8>> {
    let mut x = dh_shared_secret.to_vec();

    if let Some(DhNonce { client_nonce, server_nonce }) = nonce {
        x.extend_from_slice(client_nonce);
        x.extend_from_slice(server_nonce);
    }

    octet_string_to_key(&x, cipher)
}
