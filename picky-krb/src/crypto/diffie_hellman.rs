use num_bigint_dig::BigUint;
use rand::{CryptoRng, Rng, RngCore};
use sha1::{Digest, Sha1};
use thiserror::Error;

use crate::crypto::Cipher;

#[derive(Error, Debug)]
pub enum DiffieHellmanError {
    #[error("Invalid bit len: {0}")]
    BitLen(String),
    #[error("Invalid data len: expected at least {0} but got {1}.")]
    DataLen(usize, usize),
}

pub type DiffieHellmanResult<T> = Result<T, DiffieHellmanError>;

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// K-truncate truncates its input to the first K bits
fn k_truncate(k: usize, mut data: Vec<u8>) -> DiffieHellmanResult<Vec<u8>> {
    if k % 8 != 0 {
        return Err(DiffieHellmanError::BitLen(format!(
            "Seed bit len must be a multiple of 8. Got: {}",
            k
        )));
    }

    let bytes_len = k / 8;

    if bytes_len > data.len() {
        return Err(DiffieHellmanError::DataLen(bytes_len, data.len()));
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
fn octet_string_to_key(x: &[u8], cipher: &dyn Cipher) -> DiffieHellmanResult<Vec<u8>> {
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

    Ok(cipher.random_to_key(k_truncate(seed_len * 8, key)?))
}

pub struct DhNonce<'a> {
    pub client_nonce: &'a [u8],
    pub server_nonce: &'a [u8],
}

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// let n_c be the clientDHNonce and n_k be the serverDHNonce; otherwise, let both n_c and n_k be empty octet strings.
/// k = octetstring2key(DHSharedSecret | n_c | n_k)
pub fn generate_key_from_shared_secret(
    dh_shared_secret: &[u8],
    nonce: Option<DhNonce>,
    cipher: &dyn Cipher,
) -> DiffieHellmanResult<Vec<u8>> {
    let mut x = dh_shared_secret.to_vec();

    if let Some(DhNonce {
        client_nonce,
        server_nonce,
    }) = nonce
    {
        x.extend_from_slice(client_nonce);
        x.extend_from_slice(server_nonce);
    }

    octet_string_to_key(&x, cipher)
}

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// let DHSharedSecret be the shared secret value. DHSharedSecret is the value ZZ
///
/// [Generation of ZZ](https://www.rfc-editor.org/rfc/rfc2631#section-2.1.1)
/// ZZ = g ^ (xb * xa) mod p
/// ZZ = (yb ^ xa)  mod p  = (ya ^ xb)  mod p
/// where ^ denotes exponentiation
pub fn generate_dh_shared_secret(public_key: &[u8], private_key: &[u8], p: &[u8]) -> Vec<u8> {
    let public_key = BigUint::from_bytes_be(public_key);
    let private_key = BigUint::from_bytes_be(private_key);
    let p = BigUint::from_bytes_be(p);

    // ZZ = (public_key ^ private_key) mod p
    public_key.modpow(&private_key, &p).to_bytes_be()
}

//= [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1) =//
pub fn generate_key(
    public_key: &[u8],
    private_key: &[u8],
    modulus: &[u8],
    nonce: Option<DhNonce>,
    cipher: &dyn Cipher,
) -> DiffieHellmanResult<Vec<u8>> {
    let dh_shared_secret = generate_dh_shared_secret(public_key, private_key, modulus);

    generate_key_from_shared_secret(&dh_shared_secret, nonce, cipher)
}

/// [Key and Parameter Requirements](https://www.rfc-editor.org/rfc/rfc2631#section-2.2)
/// X9.42 requires that the private key x be in the interval [2, (q - 2)]
pub fn generate_private_key<R: RngCore + CryptoRng>(q: &[u8], rng: &mut R) -> Vec<u8> {
    let q = BigUint::from_bytes_be(q);

    rng.gen_range(BigUint::from_bytes_be(&[2])..(q - 1_u32)).to_bytes_be()
}

/// [Key and Parameter Requirements](https://www.rfc-editor.org/rfc/rfc2631#section-2.2)
/// y is then computed by calculating g^x mod p.
pub fn compute_public_key(private_key: &[u8], modulus: &[u8], base: &[u8]) -> Vec<u8> {
    let x = BigUint::from_bytes_be(private_key);
    let g = BigUint::from_bytes_be(base);
    let p = BigUint::from_bytes_be(modulus);

    g.modpow(&x, &p).to_bytes_be()
}
