use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

use crate::crypto::nfold::n_fold;
use crate::crypto::KERBEROS;

/// https://www.rfc-editor.org/rfc/rfc3962.html#section-4
/// Default iteration count (rounds) for pbkdf2 function:
/// 00 00 10 00 (decimal 4,096, indicating 4,096 iterations)
const AES_ITERATION_COUNT: u32 = 0x1000;

use super::{encrypt_aes, AesSize};

// as given
fn random_to_key(data: Vec<u8>) -> Vec<u8> {
    data
}

fn derive_key(key: &[u8], well_known: &[u8], aes_size: AesSize) -> Vec<u8> {
    let block_bit_len = aes_size.block_bit_len();
    let seed_bit_len = aes_size.seed_bit_len();

    let mut n_fold_usage = n_fold(well_known, block_bit_len);

    // let mut out = vec![0; seed_bit_len / 8];
    let key_len = aes_size.key_length();
    let mut out = Vec::with_capacity(key_len);

    while out.len() < key_len {
        n_fold_usage = encrypt_aes(key, &n_fold_usage, aes_size.clone());
        out.append(&mut n_fold_usage.clone());
    }

    out
}

pub fn derive_key_from_password<P: AsRef<[u8]>, S: AsRef<[u8]>>(password: P, salt: S, aes_size: AesSize) -> Vec<u8> {
    let mut tmp = vec![0; aes_size.key_length()];

    pbkdf2::<Hmac<Sha1>>(password.as_ref(), salt.as_ref(), AES_ITERATION_COUNT, &mut tmp);

    let temp_key = random_to_key(tmp);

    derive_key(&temp_key, KERBEROS, aes_size)
}

#[cfg(test)]
mod tests {
    // use kerberos_crypto::new_kerberos_cipher;

    use crate::crypto::aes::AesSize;

    use super::derive_key_from_password;

    #[test]
    fn test_derive_key_from_password() {
        let password = "5hYYSAfFJp";
        let salt = "EXAMPLE.COMtest1";

        let key = derive_key_from_password(password, salt, AesSize::Aes256);

        assert_eq!(
            &[
                218_u8, 222, 209, 204, 21, 174, 23, 222, 170, 99, 164, 144, 247, 103, 137, 68, 117, 143, 59, 37, 90,
                84, 37, 105, 203, 32, 235, 167, 97, 238, 171, 172
            ] as &[u8],
            key.as_slice()
        );
    }

    // #[test]
    // fn ex() {
    //     let password = "5hYYSAfFJp";
    //     let salt = "EXAMPLE.COMtest1";

    //     let c = new_kerberos_cipher(18).unwrap();
    //     println!("key: {:?}", c.generate_key_from_string(password, salt.as_bytes()));
    // }
}
