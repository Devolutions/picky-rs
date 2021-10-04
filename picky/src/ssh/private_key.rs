use super::SshParser;
use crate::ssh::{ByteArray, Mpint, SshString};
use aes::cipher::{NewCipher, StreamCipher};
use aes::{Aes128, Aes128Ctr, Aes256, Aes256Ctr};
use block_modes::block_padding::NoPadding;
use block_modes::BlockMode;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use std::io::{Cursor, Read, Write};
use std::string;
use thiserror::Error;

type Aes128Cbc = block_modes::Cbc<Aes128, NoPadding>;
type Aes256Cbc = block_modes::Cbc<Aes256, NoPadding>;

const PRIVATE_KEY_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PRIVATE_KEY_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";
const AUTH_MAGIC: &str = "openssh-key-v1";
const KEY_TYPE_RSA: &str = "ssh-rsa";

pub trait SshPrivateKeyParser {
    type Error;

    fn decode(stream: impl Read, passphrase: Option<&str>) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

#[derive(Debug, Error)]
pub enum SshPrivateKeyError {
    #[error(transparent)]
    FromUtf8Error(#[from] string::FromUtf8Error),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    CouldNotWriteKey(#[from] std::io::Error),
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
    #[error("Unsupported kdf: {0}")]
    UnsupportedKdf(String),
    #[error("Invalid auth magic header")]
    InvalidAuthMagicHeader,
    #[error("Invalid keys amount. Expected 1 but got {0}")]
    InvalidKeysAmount(u32),
    #[error("Check numbers are not equal: {0} {1}. Wrong passphrase or key if corrupted")]
    InvalidCheckNumbers(u32, u32),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Can not decrypt private key: {0:?}")]
    DecryptionError(#[from] block_modes::BlockModeError),
    #[error("Can not hash the passphrase: {0:?}")]
    HashingError(#[from] bcrypt_pbkdf::Error),
}

#[derive(Debug)]
pub struct SshPrivateKey {
    inner_key: SshInnerPrivateKey,
    passphrase: Option<String>,
    comment: String,
}

#[derive(Debug)]
pub enum SshInnerPrivateKey {
    Rsa(RsaPrivateKey),
}

impl SshPrivateKey {
    // pub fn from_pem_str(pem: &str) -> Result<Self, SshPrivateKeyError> {
    //     SshParser::decode(pem.as_bytes())
    // }
    //
    // pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<Self, SshPrivateKeyError> {
    //     let mut slice = raw.as_ref();
    //     SshParser::decode(&mut slice)
    // }
    //
    // pub fn to_pem(&self) -> Result<String, SshPrivateKeyError> {
    //     let buffer = self.to_raw()?;
    //     Ok(String::from_utf8(buffer)?)
    // }
    //
    // pub fn to_raw(&self) -> Result<Vec<u8>, SshPrivateKeyError> {
    //     let mut cursor = Cursor::new(Vec::with_capacity(1024));
    //     self.encode(&mut cursor)?;
    //     Ok(cursor.into_inner())
    // }

    pub fn read_all(mut stream: impl Read) -> Vec<u8> {
        let mut data = Vec::new();
        let mut buff = vec![0; 1024];
        while let Ok(n) = stream.read(&mut buff) {
            if n > 1 {
                data.extend_from_slice(&buff[0..n]);
            } else {
                break;
            }
        }
        data
    }
}

impl SshPrivateKeyParser for SshPrivateKey {
    type Error = SshPrivateKeyError;

    fn decode(stream: impl Read, passphrase: Option<&str>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data = SshPrivateKey::read_all(stream);
        if !data.starts_with(&data[0..PRIVATE_KEY_HEADER.len()])
            || !data.ends_with(&data[(data.len() - PRIVATE_KEY_FOOTER.len() - 1)..])
        {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        let data = base64::decode(&data[PRIVATE_KEY_HEADER.len()..(data.len() - PRIVATE_KEY_FOOTER.len() - 1)])?;
        let mut cursor = Cursor::new(data);
        let mut auth_magic = vec![0; 14];
        cursor.read_exact(&mut auth_magic)?;
        if auth_magic != AUTH_MAGIC.as_bytes() {
            return Err(SshPrivateKeyError::InvalidAuthMagicHeader);
        }
        cursor.read_u8()?; // skip 1 byte (null-byte)

        let cipher_name: SshString = SshParser::decode(&mut cursor).unwrap();
        let kdf_name: SshString = SshParser::decode(&mut cursor).unwrap();
        let kdf_options: ByteArray = SshParser::decode(&mut cursor).unwrap();
        let keys_amount = cursor.read_u32::<BigEndian>()?;

        if keys_amount != 1 {
            return Err(SshPrivateKeyError::InvalidKeysAmount(keys_amount));
        }

        // read public key
        let _: ByteArray = SshParser::decode(&mut cursor)?;

        // read private key
        let private_key: ByteArray = SshParser::decode(&mut cursor)?;
        let data = decrypt(cipher_name, kdf_name, kdf_options, passphrase, private_key)?;

        let mut private_key = parse_decrypted_private_key(data)?;
        private_key.passphrase = passphrase.map(|p| p.to_owned());
        Ok(private_key)
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut result_key = Vec::new();
        result_key.extend_from_slice(b"openssh-key-v1\0");
        if let Some(passphrase) = self.passphrase.clone() {
            SshString("aes256-ctr".to_owned()).encode(&mut result_key)?;
            SshString("bcrypt".to_owned()).encode(&mut result_key)?;

            let mut random = rand::thread_rng();
            let mut salt = Vec::with_capacity(16);
            for _ in 0..16 {
                salt.push(random.gen::<u8>());
            }
            let rounds = 16;

            let mut kdf_options = Vec::new();
            ByteArray(salt.clone()).encode(&mut kdf_options)?;
            kdf_options.write_u32::<BigEndian>(rounds)?;

            ByteArray(kdf_options).encode(&mut result_key)?;

            result_key.write_u32::<BigEndian>(1)?;

            match &self.inner_key {
                SshInnerPrivateKey::Rsa(rsa) => {
                    let (public_key, mut private_key) = encode_private_rsa(rsa)?;

                    SshString(self.comment.clone()).encode(&mut private_key)?;
                    // now we must encrypt private_key
                    let n = 48;
                    let mut hash = vec![0; n];
                    bcrypt_pbkdf::bcrypt_pbkdf(&passphrase, &salt, rounds, &mut hash)?;

                    let (key, iv) = hash.split_at(n - 16);
                    let mut cipher = Aes256Ctr::new_from_slices(key.clone(), iv.clone()).unwrap();

                    let private_key_len = private_key.len();
                    private_key.resize(private_key_len + 32, 0u8);
                    cipher.apply_keystream(&mut private_key);
                    private_key.truncate(private_key_len);

                    ByteArray(public_key).encode(&mut result_key)?;
                    ByteArray(private_key).encode(&mut result_key)?;
                }
            };
        } else {
            SshString("none".to_owned()).encode(&mut result_key)?;
            SshString("none".to_owned()).encode(&mut result_key)?;
            SshString("".to_owned()).encode(&mut result_key)?;

            result_key.write_u32::<BigEndian>(1)?;

            match &self.inner_key {
                SshInnerPrivateKey::Rsa(rsa) => {
                    let (public_key, mut private_key) = encode_private_rsa(rsa)?;

                    SshString(self.comment.clone()).encode(&mut private_key)?;

                    ByteArray(public_key).encode(&mut result_key)?;
                    ByteArray(private_key).encode(&mut result_key)?;
                }
            }
        }
        stream.write_all(
            format!(
                "{}{}{}",
                PRIVATE_KEY_HEADER,
                base64::encode(result_key),
                PRIVATE_KEY_FOOTER
            )
            .as_bytes(),
        )?;
        Ok(())
    }
}

fn encode_private_rsa(rsa: &RsaPrivateKey) -> Result<(Vec<u8>, Vec<u8>), SshPrivateKeyError> {
    let mut public_key = Vec::new();
    SshString("ssh-rsa".to_owned()).encode(&mut public_key)?;
    Mpint(rsa.e().to_bytes_be()).encode(&mut public_key)?;
    Mpint(rsa.n().to_bytes_be()).encode(&mut public_key)?;

    let mut private_key = Vec::new();
    let check = rand::thread_rng().gen::<u32>();
    private_key.write_u32::<BigEndian>(check)?;
    private_key.write_u32::<BigEndian>(check)?;

    SshString("ssh-rsa".to_owned()).encode(&mut private_key)?;
    Mpint(rsa.n().to_bytes_be()).encode(&mut private_key)?;
    Mpint(rsa.e().to_bytes_be()).encode(&mut private_key)?;
    Mpint(rsa.d().to_bytes_be()).encode(&mut private_key)?;

    for prime in rsa.primes().iter() {
        Mpint(prime.to_bytes_be()).encode(&mut private_key)?;
    }
    Ok((public_key, private_key))
}

fn decrypt(
    cipher_name: SshString,
    kdf_name: SshString,
    kdf_options: ByteArray,
    passphrase: Option<&str>,
    data: ByteArray,
) -> Result<Vec<u8>, SshPrivateKeyError> {
    if kdf_name.0 == "none" {
        Ok(data.0)
    } else {
        let n = match cipher_name.0.as_str() {
            "aes128-cbc" | "aes128-ctr" => 32,
            "aes256-cbc" | "aes256-ctr" => 48,
            name => return Err(SshPrivateKeyError::UnsupportedCipher(name.to_owned())),
        };
        // 48 - max block size
        let mut key = [0; 48];
        match kdf_name.0.as_str() {
            "bcrypt" => {
                let mut kdf_options = Cursor::new(kdf_options.0);
                let salt: ByteArray = SshParser::decode(&mut kdf_options)?;
                let rounds = kdf_options.read_u32::<BigEndian>()?;
                let passphrase = match passphrase {
                    Some(pass) => pass,
                    None => panic!(""),
                };
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt.0.as_slice(), rounds, &mut key[..n])?;
            }
            name => return Err(SshPrivateKeyError::UnsupportedKdf(name.to_owned())),
        };
        let (key, iv) = key.split_at(n - 16);
        let mut data = data.0;
        let start_len = data.len();
        data.resize(data.len() + 32, 0u8);
        match cipher_name.0.as_str() {
            "aes128-cbc" => {
                let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt(&mut data)?.len();
                data.truncate(n);
                Ok(data)
            }
            "aes256-cbc" => {
                let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt(&mut data)?.len();
                data.truncate(n);
                Ok(data)
            }
            "aes128-ctr" => {
                let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut data);
                data.truncate(start_len);
                Ok(data)
            }
            "aes256-ctr" => {
                let mut cipher = Aes256Ctr::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut data);
                data.truncate(start_len);
                Ok(data)
            }
            name => Err(SshPrivateKeyError::UnsupportedCipher(name.to_owned())),
        }
    }
}

fn parse_decrypted_private_key(data: Vec<u8>) -> Result<SshPrivateKey, SshPrivateKeyError> {
    let mut cursor = Cursor::new(data);
    let check0 = cursor.read_u32::<BigEndian>()?;
    let check1 = cursor.read_u32::<BigEndian>()?;
    if check0 != check1 {
        return Err(SshPrivateKeyError::InvalidCheckNumbers(check0, check1));
    }
    let key_type: SshString = SshParser::decode(&mut cursor)?;
    match key_type.0.as_str() {
        KEY_TYPE_RSA => {
            let n: Mpint = SshParser::decode(&mut cursor)?;
            let e: Mpint = SshParser::decode(&mut cursor)?;
            let d: Mpint = SshParser::decode(&mut cursor)?;
            let iqmp: Mpint = SshParser::decode(&mut cursor)?;
            let p: Mpint = SshParser::decode(&mut cursor)?;
            let q: Mpint = SshParser::decode(&mut cursor)?;

            let comment: SshString = SshParser::decode(&mut cursor)?;

            Ok(SshPrivateKey {
                comment: comment.0,
                passphrase: Option::None,
                inner_key: SshInnerPrivateKey::Rsa(RsaPrivateKey::from_components(
                    BigUint::from_bytes_be(&n.0),
                    BigUint::from_bytes_be(&e.0),
                    BigUint::from_bytes_be(&d.0),
                    vec![
                        BigUint::from_bytes_be(&iqmp.0),
                        BigUint::from_bytes_be(&p.0),
                        BigUint::from_bytes_be(&q.0),
                    ],
                )),
            })
        }
        key_type => return Err(SshPrivateKeyError::UnsupportedKeyType(key_type.to_owned())),
    }
}

#[cfg(test)]
pub mod tests {
    use crate::ssh::private_key::{SshPrivateKey, SshPrivateKeyError, SshPrivateKeyParser};

    #[test]
    fn test_decode_bcrypt() {
        let pass = "123123";
        let private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----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-----END OPENSSH PRIVATE KEY-----".to_vec();
        let private_key: Result<SshPrivateKey, SshPrivateKeyError> =
            SshPrivateKeyParser::decode(private_key.as_slice(), Option::Some(pass));
        println!("{:?}", private_key);
        assert!(private_key.is_ok());
    }

    #[test]
    fn test_decode_none() {
        let private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----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-----END OPENSSH PRIVATE KEY-----".to_vec();
        let private_key: Result<SshPrivateKey, SshPrivateKeyError> =
            SshPrivateKeyParser::decode(private_key.as_slice(), Option::None);
        println!("{:?}", private_key);
        assert!(private_key.is_ok());
    }

    #[test]
    fn test_encode_none() {
        let private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----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-----END OPENSSH PRIVATE KEY-----".to_vec();
        let private_key: Result<SshPrivateKey, SshPrivateKeyError> =
            SshPrivateKeyParser::decode(private_key.as_slice(), Option::None);
        assert!(private_key.is_ok());
        let private_key = private_key.unwrap();

        let mut private_key_data: Vec<u8> = Vec::new();
        let res = private_key.encode(&mut private_key_data);
        println!("{:?}", String::from_utf8(private_key_data).unwrap());
        assert!(res.is_ok());
    }

    #[test]
    fn test_encode_bcrypt() {
        let private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----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-----END OPENSSH PRIVATE KEY-----".to_vec();
        let private_key: SshPrivateKey =
            SshPrivateKeyParser::decode(private_key.as_slice(), Option::Some("123123")).unwrap();

        let mut new_pr: Vec<u8> = Vec::new();
        private_key.encode(&mut new_pr).unwrap();

        println!("new_pr: {}", String::from_utf8(new_pr.clone()).unwrap());

        let _private_key: SshPrivateKey =
            SshPrivateKeyParser::decode(new_pr.as_slice(), Option::Some("123123")).unwrap();
    }
}
