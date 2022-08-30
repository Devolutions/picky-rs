use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::{Cipher, CipherSuite, KerberosCryptoError, KerberosCryptoResult};

use super::decrypt::decrypt_message;
use super::encrypt::encrypt_message;
use super::{derive_key_from_password, AesSize, AES256_KEY_SIZE, AES_BLOCK_SIZE};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Aes256CtsHmacSha196;

impl Aes256CtsHmacSha196 {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for Aes256CtsHmacSha196 {
    fn key_size(&self) -> usize {
        AES256_KEY_SIZE
    }

    fn cipher_type(&self) -> CipherSuite {
        CipherSuite::Aes256CtsHmacSha196
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> Result<Vec<u8>, KerberosCryptoError> {
        encrypt_message(
            key,
            key_usage,
            payload,
            &AesSize::Aes256,
            OsRng::default().gen::<[u8; AES_BLOCK_SIZE]>(),
        )
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        decrypt_message(key, key_usage, cipher_data, &AesSize::Aes256)
    }

    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>> {
        derive_key_from_password(password, salt, &AesSize::Aes256)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::aes::decrypt::decrypt_message;
    use crate::crypto::aes::encrypt::encrypt_message;
    use crate::crypto::aes::AesSize;

    fn encrypt(plaintext: &[u8]) -> Vec<u8> {
        let key = [
            22, 151, 234, 93, 29, 64, 176, 109, 232, 140, 95, 54, 168, 107, 20, 251, 155, 71, 70, 148, 50, 145, 49,
            157, 182, 139, 235, 19, 11, 199, 3, 135,
        ];

        encrypt_message(
            &key,
            5,
            &plaintext,
            &AesSize::Aes256,
            [
                161, 52, 157, 33, 238, 232, 185, 93, 167, 130, 91, 180, 167, 165, 224, 78,
            ],
        )
        .unwrap()
    }

    fn decrypt(payload: &[u8]) -> Vec<u8> {
        let key = [
            22, 151, 234, 93, 29, 64, 176, 109, 232, 140, 95, 54, 168, 107, 20, 251, 155, 71, 70, 148, 50, 145, 49,
            157, 182, 139, 235, 19, 11, 199, 3, 135,
        ];

        decrypt_message(&key, 5, payload, &AesSize::Aes256).unwrap()
    }

    #[test]
    fn encrypt_half() {
        // incomplete block
        let plaintext = [97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95];

        assert_eq!(
            &[
                153, 67, 25, 51, 230, 39, 92, 105, 17, 234, 98, 208, 165, 181, 181, 225, 214, 122, 109, 174, 37, 138,
                242, 223, 137, 137, 242, 184, 235, 239, 155, 12, 185, 70, 139, 212, 37, 35, 90
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn encrypt_one() {
        // one block
        let plaintext = [97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95];

        assert_eq!(
            &[
                10, 164, 28, 60, 222, 116, 184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 214, 122, 109, 174, 37, 138,
                242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 0, 1, 133, 19, 130, 154, 121, 77, 48, 11, 189, 137
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn encrypt_one_and_half() {
        // one block + incomplete block
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,
        ];

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219,
                96, 18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220,
                113, 173, 31, 154, 73, 236, 25
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn encrypt_two() {
        // two blocks
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 5, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 107,
            101, 121, 95, 100, 101, 114, 105, 118,
        ];

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 214, 57, 118, 48, 238,
                82, 92, 83, 182, 254, 200, 38, 71, 6, 142, 72, 115, 214, 107, 193, 38, 10, 184, 156, 34, 121, 228, 100,
                13, 228, 159, 52, 191, 126, 65, 159, 253, 157, 62, 9, 125, 106, 82, 136
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn encrypt_two_and_half() {
        // two blocks + incomplete block
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 107,
            101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114,
        ];

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222,
                116, 184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 64, 87, 14, 62, 62, 12, 77, 137, 200, 194, 20, 216,
                149, 179, 128, 92, 156, 39, 25, 101, 126, 251, 45, 121, 20, 103, 36, 246, 54, 67, 200, 167, 244, 214,
                209,
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn encrypt_three() {
        // three blocks
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 46,
            107, 101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114, 115, 46, 99, 114, 121, 112,
            116, 111,
        ];

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222,
                116, 184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 35, 238, 183, 171, 208, 35, 185, 212, 190, 49, 9, 49,
                122, 105, 47, 155, 81, 226, 246, 250, 147, 120, 239, 83, 65, 157, 252, 73, 142, 130, 107, 70, 233, 12,
                140, 124, 156, 243, 171, 176, 162, 128, 119, 189
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn three_and_half() {
        // three blocks + incomplete block
        let plaintext = [
            97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 46,
            107, 101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114, 115, 46, 99, 114, 121, 112,
            116, 111, 46, 114, 115, 46, 112, 105, 99, 107, 121, 45, 114, 115, 46,
        ];

        assert_eq!(
            &[
                214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222,
                116, 184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 81, 226, 246, 250, 147, 120, 239, 83, 65, 157, 252,
                73, 142, 130, 107, 70, 54, 89, 220, 119, 43, 138, 67, 4, 82, 98, 225, 84, 221, 24, 143, 47, 35, 238,
                183, 171, 208, 35, 185, 212, 190, 49, 9, 49, 122, 221, 131, 75, 188, 8, 114, 203, 108, 140, 156, 131,
                175
            ],
            encrypt(&plaintext).as_slice()
        );
    }

    #[test]
    fn decrypt_half() {
        // incomplete block
        let payload = [
            153, 67, 25, 51, 230, 39, 92, 105, 17, 234, 98, 208, 165, 181, 181, 225, 214, 122, 109, 174, 37, 138, 242,
            223, 137, 137, 242, 184, 235, 239, 155, 12, 185, 70, 139, 212, 37, 35, 90,
        ];

        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95,],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_one() {
        // one block
        let payload = [
            10, 164, 28, 60, 222, 116, 184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 214, 122, 109, 174, 37, 138, 242,
            223, 137, 137, 242, 93, 162, 124, 121, 114, 0, 1, 133, 19, 130, 154, 121, 77, 48, 11, 189, 137,
        ];

        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95,],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_one_and_half() {
        // one block + incomplete block
        let payload = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 161, 144, 68, 138, 219, 96,
            18, 26, 10, 139, 245, 156, 28, 218, 173, 28, 10, 164, 28, 60, 222, 116, 184, 96, 153, 3, 46, 220, 113, 173,
            31, 154, 73, 236, 25,
        ];

        assert_eq!(
            &[97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_two() {
        // two blocks
        let payload = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 214, 57, 118, 48, 238, 82,
            92, 83, 182, 254, 200, 38, 71, 6, 142, 72, 115, 214, 107, 193, 38, 10, 184, 156, 34, 121, 228, 100, 13,
            228, 159, 52, 191, 126, 65, 159, 253, 157, 62, 9, 125, 106, 82, 136,
        ];

        assert_eq!(
            &[
                97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 5, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 107,
                101, 121, 95, 100, 101, 114, 105, 118
            ],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_two_and_half() {
        // two blocks + incomplete block
        let payload = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222, 116,
            184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 64, 87, 14, 62, 62, 12, 77, 137, 200, 194, 20, 216, 149, 179,
            128, 92, 156, 39, 25, 101, 126, 251, 45, 121, 20, 103, 36, 246, 54, 67, 200, 167, 244, 214, 209,
        ];

        assert_eq!(
            &[
                97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54,
                107, 101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114,
            ],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_three() {
        // three blocks
        let payload = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222, 116,
            184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 35, 238, 183, 171, 208, 35, 185, 212, 190, 49, 9, 49, 122,
            105, 47, 155, 81, 226, 246, 250, 147, 120, 239, 83, 65, 157, 252, 73, 142, 130, 107, 70, 233, 12, 140, 124,
            156, 243, 171, 176, 162, 128, 119, 189,
        ];

        assert_eq!(
            &[
                97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 46,
                107, 101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114, 115, 46, 99, 114, 121,
                112, 116, 111,
            ],
            decrypt(&payload).as_slice()
        );
    }

    #[test]
    fn decrypt_three_and_half() {
        // three blocks + incomplete block
        let payload = [
            214, 122, 109, 174, 37, 138, 242, 223, 137, 137, 242, 93, 162, 124, 121, 114, 10, 164, 28, 60, 222, 116,
            184, 67, 131, 207, 244, 3, 10, 249, 22, 244, 81, 226, 246, 250, 147, 120, 239, 83, 65, 157, 252, 73, 142,
            130, 107, 70, 54, 89, 220, 119, 43, 138, 67, 4, 82, 98, 225, 84, 221, 24, 143, 47, 35, 238, 183, 171, 208,
            35, 185, 212, 190, 49, 9, 49, 122, 221, 131, 75, 188, 8, 114, 203, 108, 140, 156, 131, 175,
        ];

        assert_eq!(
            &[
                97, 101, 115, 50, 53, 54, 95, 99, 116, 115, 95, 104, 109, 97, 99, 95, 115, 104, 97, 49, 95, 57, 54, 46,
                107, 101, 121, 95, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 46, 114, 115, 46, 99, 114, 121,
                112, 116, 111, 46, 114, 115, 46, 112, 105, 99, 107, 121, 45, 114, 115, 46
            ],
            decrypt(&payload).as_slice()
        );
    }
}
