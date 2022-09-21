use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rand::{CryptoRng, Rng, RngCore};
use sha1::{Digest, Sha1};

use crate::crypto::{Cipher, KerberosCryptoError, KerberosCryptoResult};

/// [Using Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1)
/// K-truncate truncates its input to the first K bits
fn k_truncate(k: usize, mut data: Vec<u8>) -> KerberosCryptoResult<Vec<u8>> {
    if k % 8 != 0 {
        return Err(KerberosCryptoError::SeedBitLen(format!(
            "Seed bit len must be a multiple of 8. Got: {}",
            k
        )));
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
fn octet_string_to_key(x: &[u8], cipher: &dyn Cipher) -> KerberosCryptoResult<Vec<u8>> {
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
pub fn generate_key_from_shared_secret(
    dh_shared_secret: &[u8],
    nonce: Option<DhNonce>,
    cipher: &dyn Cipher,
) -> KerberosCryptoResult<Vec<u8>> {
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

pub fn generate_key(
    public_key: &[u8],
    private_key: &[u8],
    modulus: &[u8],
    nonce: Option<DhNonce>,
    cipher: &dyn Cipher,
) -> KerberosCryptoResult<Vec<u8>> {
    let dh_shared_secret = generate_dh_shared_secret(public_key, private_key, modulus);

    generate_key_from_shared_secret(&dh_shared_secret, nonce, cipher)
}

fn divide_up(a: usize, b: usize) -> usize {
    (a + (b - 1)) / b
}

fn is_prime() -> bool {
    true
}

/// [Generation of p, q](https://www.rfc-editor.org/rfc/rfc2631#section-2.2.1.1)
/// This algorithm generates a p, q pair where q is of length m and p is of length L.
fn generate_p_and_q(m: usize, l: usize) -> (BigUint, BigUint) {
    // 1. Set m' = m/160
    let m1 = divide_up(m, 160);

    // 2. Set L'=  L/160
    let l1 = divide_up(l, 160);

    // 3. Set N'=  L/1024
    let n1 = divide_up(l, 1024);

    //

    todo!()
}

fn generate_simple_g() -> BigUint {
    BigUint::from_usize(2).unwrap()
}

/// [Generation of g](https://www.rfc-editor.org/rfc/rfc2631#section-2.2.1.2)
/// This section gives an algorithm (derived from [FIPS-186]) for generating g.
fn generate_g<R: RngCore + CryptoRng>(p: &BigUint, q: &BigUint, rng: &mut R) -> BigUint {
    let one = BigUint::from_usize(1).unwrap();
    let two = BigUint::from_usize(2).unwrap();

    let mut g = one.clone();

    // 1. Let j = (p - 1)/q.
    let j = (p - 1_u8) / q;

    while g == one {
        // 2. Set h = any integer, where 1 < h < p - 1 and h differs from any value previously tried.
        let h = rng.gen_range(two.clone()..(p - 1_u32));

        // 3. Set g = h^j mod p
        g = h.modpow(&j, p);

        // 4. If g = 1 go to step 2
    }

    g
}

pub fn generate_parameters<R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (p, q) = generate_p_and_q(0, 0);

    let g = generate_g(&p, &q, rng);

    todo!()
}

/// returns (p, g, q)
pub fn get_default_parameters() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        vec![
            255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220,
            28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4,
            221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194,
            69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6,
            183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236,
            230, 83, 129, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
        vec![2],
        vec![
            127, 255, 255, 255, 255, 255, 255, 255, 228, 135, 237, 81, 16, 180, 97, 26, 98, 99, 49, 69, 192, 110, 14,
            104, 148, 129, 39, 4, 69, 51, 230, 58, 1, 5, 223, 83, 29, 137, 205, 145, 40, 165, 4, 60, 199, 26, 2, 110,
            247, 202, 140, 217, 230, 157, 33, 141, 152, 21, 133, 54, 249, 47, 138, 27, 167, 240, 154, 182, 182, 168,
            225, 34, 242, 66, 218, 187, 49, 47, 63, 99, 122, 38, 33, 116, 211, 27, 246, 181, 133, 255, 174, 91, 122, 3,
            91, 246, 247, 28, 53, 253, 173, 68, 207, 210, 215, 79, 146, 8, 190, 37, 143, 243, 36, 148, 51, 40, 246,
            115, 41, 192, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
    )
}

/// [Key and Parameter Requirements](https://www.rfc-editor.org/rfc/rfc2631#section-2.2)
/// X9.42 requires that the private key x be in the interval [2, (q - 2)]
pub fn generate_private_key<R: RngCore + CryptoRng>(q: &[u8], rng: &mut R) -> Vec<u8> {
    let q = BigUint::from_bytes_be(q);

    rng.gen_range(BigUint::from_usize(2).unwrap()..=(q - 1_u32))
        .to_bytes_be()
}

/// [Key and Parameter Requirements](https://www.rfc-editor.org/rfc/rfc2631#section-2.2)
/// y is then computed by calculating g^x mod p.
pub fn compute_public_key(private_key: &[u8], modulus: &[u8], base: &[u8]) -> Vec<u8> {
    let x = BigUint::from_bytes_be(private_key);
    let g = BigUint::from_bytes_be(base);
    let p = BigUint::from_bytes_be(modulus);

    g.modpow(&x, &p).to_bytes_be()
}

#[cfg(test)]
mod tests {
    use picky_asn1::wrapper::IntegerAsn1;

    #[test]
    fn p() {
        assert_eq!(
            &[
                2, 129, 129, 0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198,
                98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74,
                8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225,
                53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107,
                11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75,
                31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255, 255, 255
            ],
            picky_asn1_der::to_vec(&IntegerAsn1::from(vec![
                0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128,
                220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142,
                52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109,
                109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255,
                92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230,
                73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255, 255, 255
            ]))
            .unwrap()
            .as_slice(),
        );
    }

    #[test]
    fn dh() {
        let client_nonce = [
            72, 91, 60, 222, 24, 28, 4, 155, 141, 138, 44, 10, 136, 54, 202, 60, 146, 234, 183, 130, 109, 34, 94, 10,
            87, 237, 162, 55, 173, 100, 115, 43,
        ];
        let server_nonce = [
            160, 135, 139, 83, 106, 40, 32, 75, 125, 12, 23, 191, 191, 163, 215, 162, 217, 132, 196, 80, 212, 102, 88,
            251, 252, 135, 151, 137, 121, 58, 199, 71,
        ];
    }
}
