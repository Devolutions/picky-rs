use super::SshParser;
use crate::key::{KeyError, PrivateKey};
use crate::ssh::public_key::{SshInnerPublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{ByteArray, Mpint, SshString};
use aes::cipher::{NewCipher, StreamCipher};
use aes::{Aes128, Aes128Ctr, Aes256, Aes256Ctr};
use block_modes::block_padding::NoPadding;
use block_modes::BlockMode;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::ModInverse;
use picky_asn1_x509::PrivateKeyValue;
use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use std::io;
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
    KeyProcessingError(#[from] std::io::Error),
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
    #[error("Check numbers are not equal: {0} {1}. Wrong passphrase or key is corrupted")]
    InvalidCheckNumbers(u32, u32),
    #[error("Invalid public key: {0:?}")]
    InvalidPublicKey(#[from] SshPublicKeyError),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Can not decrypt private key: {0:?}")]
    DecryptionError(#[from] block_modes::BlockModeError),
    #[error("Can not hash the passphrase: {0:?}")]
    HashingError(#[from] bcrypt_pbkdf::Error),
    #[error("Passphrase required for encrypted private key")]
    MissingPassphrase,
    #[error("Can not generate private key: {0:?}")]
    PrivateKeyGenerationError(#[from] KeyError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct KdfOption {
    salt: Vec<u8>,
    rounds: u32,
}

impl KdfOption {
    pub fn new() -> Self {
        Self {
            salt: Vec::new(),
            rounds: 0,
        }
    }

    pub fn construct(salt: Vec<u8>, rounds: u32) -> Self {
        Self { salt, rounds }
    }
}

impl SshParser for KdfOption {
    type Error = io::Error;

    fn decode(stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(stream)?;
        if data.0.len() == 0 {
            return Ok(KdfOption::new());
        }
        let mut data = Cursor::new(data.0);
        let salt: ByteArray = SshParser::decode(&mut data)?;
        let rounds = data.read_u32::<BigEndian>()?;
        Ok(KdfOption { salt: salt.0, rounds })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        if self.salt.len() == 0 {
            stream.write_u32::<BigEndian>(0)?;
            return Ok(());
        }
        let mut data = Vec::new();
        ByteArray(self.salt.clone()).encode(&mut data)?;
        data.write_u32::<BigEndian>(self.rounds)?;
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Kdf {
    name: String,
    option: KdfOption,
}

impl Kdf {
    pub fn construct(name: String, option: KdfOption) -> Self {
        Kdf { name, option }
    }
}

#[derive(Debug)]
pub enum SshInnerPrivateKey {
    Rsa(RsaPrivateKey),
}

impl SshParser for SshInnerPrivateKey {
    type Error = SshPrivateKeyError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let key_type: SshString = SshParser::decode(&mut stream)?;
        match key_type.0.as_str() {
            KEY_TYPE_RSA => {
                let n: Mpint = SshParser::decode(&mut stream)?;
                let e: Mpint = SshParser::decode(&mut stream)?;
                let d: Mpint = SshParser::decode(&mut stream)?;
                let _iqmp: Mpint = SshParser::decode(&mut stream)?;
                let p: Mpint = SshParser::decode(&mut stream)?;
                let q: Mpint = SshParser::decode(&mut stream)?;

                Ok(SshInnerPrivateKey::Rsa(RsaPrivateKey::from_components(
                    BigUint::from_bytes_be(&n.0),
                    BigUint::from_bytes_be(&e.0),
                    BigUint::from_bytes_be(&d.0),
                    vec![BigUint::from_bytes_be(&p.0), BigUint::from_bytes_be(&q.0)],
                )))
            }
            key_type => return Err(SshPrivateKeyError::UnsupportedKeyType(key_type.to_owned())),
        }
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        match self {
            SshInnerPrivateKey::Rsa(rsa) => {
                SshString("ssh-rsa".to_owned()).encode(&mut stream)?;
                Mpint(rsa.n().to_bytes_be()).encode(&mut stream)?;
                Mpint(rsa.e().to_bytes_be()).encode(&mut stream)?;
                Mpint(rsa.d().to_bytes_be()).encode(&mut stream)?;

                let iqmp = rsa.primes()[1].clone().mod_inverse(&rsa.primes()[0]).unwrap();
                Mpint(iqmp.to_bytes_be().1).encode(&mut stream)?;

                for prime in rsa.primes().iter() {
                    Mpint(prime.to_bytes_be()).encode(&mut stream)?;
                }
            }
        };
        Ok(())
    }
}

#[derive(Debug)]
pub struct SshPrivateKey {
    kdf: Kdf,
    cipher_name: String,
    inner_key: SshInnerPrivateKey,
    passphrase: Option<String>,
    check: u32,
    comment: String,
}

impl SshPrivateKey {
    pub fn construct(
        kdf: Kdf,
        cipher_name: String,
        inner_key: SshInnerPrivateKey,
        passphrase: Option<String>,
        comment: String,
    ) -> Self {
        Self {
            kdf,
            cipher_name,
            inner_key,
            passphrase,
            comment,
            check: rand::thread_rng().gen::<u32>(),
        }
    }

    pub fn from_pem_str(pem: &str, passphrase: Option<&str>) -> Result<Self, SshPrivateKeyError> {
        SshPrivateKeyParser::decode(pem.as_bytes(), passphrase)
    }

    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R, passphrase: Option<&str>) -> Result<Self, SshPrivateKeyError> {
        let mut slice = raw.as_ref();
        SshPrivateKeyParser::decode(&mut slice, passphrase)
    }

    pub fn to_pem(&self) -> Result<String, SshPrivateKeyError> {
        let buffer = self.to_raw()?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, SshPrivateKeyError> {
        let mut cursor = Cursor::new(Vec::with_capacity(1024));
        self.encode(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    pub fn private_key_to_ssh_private_key(private_key: PrivateKey, passphrase: Option<String>) -> SshPrivateKey {
        let (kdf, cipher_name) = match &passphrase {
            Some(_) => {
                let mut salt = Vec::new();
                let rounds = 16;
                let mut rnd = rand::thread_rng();
                for _ in 0..rounds {
                    salt.push(rnd.gen::<u8>());
                }
                (
                    Kdf::construct("bcrypt".to_owned(), KdfOption::construct(salt, rounds)),
                    "".to_owned(),
                )
            }
            None => (Kdf::construct("none".to_owned(), KdfOption::new()), "none".to_owned()),
        };
        let rsa_private_key = match &private_key.as_inner().private_key {
            PrivateKeyValue::RSA(rsa) => RsaPrivateKey::from_components(
                BigUint::from_bytes_be(rsa.modulus.as_unsigned_bytes_be()),
                BigUint::from_bytes_be(rsa.public_exponent.as_unsigned_bytes_be()),
                BigUint::from_bytes_be(rsa.private_exponent.as_unsigned_bytes_be()),
                vec![
                    BigUint::from_bytes_be(rsa.prime_1.as_unsigned_bytes_be()),
                    BigUint::from_bytes_be(rsa.prime_2.as_unsigned_bytes_be()),
                ],
            ),
        };
        let inner_key = SshInnerPrivateKey::Rsa(rsa_private_key);
        SshPrivateKey::construct(kdf, cipher_name, inner_key, passphrase, "".to_owned())
    }

    pub fn generate_ssh_private_key(bits: usize, passphrase: Option<String>) -> Result<Self, SshPrivateKeyError> {
        Ok(SshPrivateKey::private_key_to_ssh_private_key(
            PrivateKey::generate_rsa(bits)?,
            passphrase,
        ))
    }

    pub fn public_key(&self) -> SshPublicKey {
        let inner_public_key = match &self.inner_key {
            SshInnerPrivateKey::Rsa(rsa) => SshInnerPublicKey::Rsa(RsaPublicKey::from(rsa)),
        };
        SshPublicKey::from_inner(inner_public_key)
    }
}

impl SshPrivateKeyParser for SshPrivateKey {
    type Error = SshPrivateKeyError;

    fn decode(mut stream: impl Read, passphrase: Option<&str>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let read_all = |stream: &mut dyn Read| {
            let mut data = Vec::new();
            let mut buff = vec![0; 1024];
            while let Ok(n) = stream.read(&mut buff) {
                if n > 0 {
                    data.extend_from_slice(&buff[0..n]);
                } else {
                    break;
                }
            }
            data
        };
        let data = read_all(&mut stream);
        if !data.starts_with(&data[0..PRIVATE_KEY_HEADER.len()])
            || !data.ends_with(&data[(data.len() - PRIVATE_KEY_FOOTER.len() - 1)..])
        {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        let data = base64::decode(&data[PRIVATE_KEY_HEADER.len()..(data.len() - PRIVATE_KEY_FOOTER.len() - 1)])?;
        println!("{:?}", data);
        let mut cursor = Cursor::new(data);

        let mut auth_magic = vec![0; 14];
        cursor.read_exact(&mut auth_magic)?;
        if auth_magic != AUTH_MAGIC.as_bytes() {
            return Err(SshPrivateKeyError::InvalidAuthMagicHeader);
        }
        cursor.read_u8()?; // skip 1 byte (null-byte)

        let cipher_name: SshString = SshParser::decode(&mut cursor)?;
        let kdf_name: SshString = SshParser::decode(&mut cursor)?;
        let kdf_option: KdfOption = SshParser::decode(&mut cursor)?;
        let keys_amount = cursor.read_u32::<BigEndian>()?;

        if keys_amount != 1 {
            return Err(SshPrivateKeyError::InvalidKeysAmount(keys_amount));
        }

        // read public key
        let _: ByteArray = SshParser::decode(&mut cursor)?;

        // read private key
        let private_key: ByteArray = SshParser::decode(&mut cursor)?;
        let data = decrypt(&cipher_name, &kdf_name, &kdf_option, &passphrase, private_key)?;

        println!("decrypted: {:?} {}", &data, data.len());

        let mut cursor = Cursor::new(data);

        let check0 = cursor.read_u32::<BigEndian>()?;
        let check1 = cursor.read_u32::<BigEndian>()?;
        if check0 != check1 {
            return Err(SshPrivateKeyError::InvalidCheckNumbers(check0, check1));
        }

        let inner_key: SshInnerPrivateKey = SshParser::decode(&mut cursor)?;

        let comment: SshString = SshParser::decode(&mut cursor)?;
        Ok(SshPrivateKey {
            inner_key,
            passphrase: passphrase.map(|p| p.to_owned()),
            kdf: Kdf {
                name: kdf_name.0,
                option: kdf_option,
            },
            cipher_name: cipher_name.0,
            check: check0,
            comment: comment.0,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut result_key = Vec::new();

        result_key.extend_from_slice(b"openssh-key-v1\0");

        if self.passphrase.is_some() {
            SshString("aes256-ctr".to_owned()).encode(&mut result_key)?;
            SshString("bcrypt".to_owned()).encode(&mut result_key)?;

            let salt = &self.kdf.option.salt;
            let rounds = self.kdf.option.rounds;

            let mut kdf_options = Vec::new();
            ByteArray(salt.clone()).encode(&mut kdf_options)?;
            kdf_options.write_u32::<BigEndian>(rounds)?;

            ByteArray(kdf_options).encode(&mut result_key)?;
        } else {
            SshString("none".to_owned()).encode(&mut result_key)?;
            SshString("none".to_owned()).encode(&mut result_key)?;
            SshString("".to_owned()).encode(&mut result_key)?;
        }

        result_key.write_u32::<BigEndian>(1)?;

        let mut public_key = Vec::new();
        self.public_key().inner_key.encode(&mut public_key)?;

        let mut private_key = Vec::new();
        private_key.write_u32::<BigEndian>(self.check)?;
        private_key.write_u32::<BigEndian>(self.check)?;
        self.inner_key.encode(&mut private_key)?;

        SshString(self.comment.clone()).encode(&mut private_key)?;

        // add padding
        for i in 1..=(8 - (private_key.len() % 8)) {
            private_key.push(i as u8);
        }

        if let Some(passphrase) = self.passphrase.clone() {
            // encrypt private_key
            let n = 48;
            let mut hash = vec![0; n];
            let salt = &self.kdf.option.salt;
            let rounds = self.kdf.option.rounds;
            bcrypt_pbkdf::bcrypt_pbkdf(&passphrase, salt, rounds, &mut hash)?;

            let (key, iv) = hash.split_at(n - 16);
            let mut cipher = Aes256Ctr::new_from_slices(key.clone(), iv.clone()).unwrap();

            let private_key_len = private_key.len();
            private_key.resize(private_key_len + 32, 0u8);
            cipher.apply_keystream(&mut private_key);
            private_key.truncate(private_key_len);
        }

        ByteArray(public_key).encode(&mut result_key)?;
        ByteArray(private_key).encode(&mut result_key)?;

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

fn decrypt(
    cipher_name: &SshString,
    kdf_name: &SshString,
    kdf_options: &KdfOption,
    passphrase: &Option<&str>,
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
        let mut key = [0; 48];
        match kdf_name.0.as_str() {
            "bcrypt" => {
                let salt = &kdf_options.salt;
                let rounds = kdf_options.rounds;
                let passphrase = match passphrase {
                    Some(pass) => pass,
                    None => return Err(SshPrivateKeyError::MissingPassphrase),
                };
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut key[..n])?;
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ssh::private_key::{SshPrivateKey, SshPrivateKeyParser};

    #[test]
    fn decode_without_passphrase_2048() {
        // ssh-keygen -t rsa -b 2048 -C "test2@picky.com" (without the passphrase)
        let ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAyPYbdoNqjj4EhuYblWIxVKLsmsOff+kLkKlFRsIJyE5YUWzPm5LyUH3LoqnL/rw/f/Og37oJO/bEn4P2lSvlf6ZagAGaLo8/8ACw4xKYUsQFHAEfreIthd/T2u9TEnN+yPS99M99bXG2tV+6He4c61TJfYrq5DsgQuMXCFmtR/IdJg8qF8lj06qEzjQ1HvXQdXruhm4sQn1HMb3VbdKQFSU3TpmzVysEaOVl3zK7KirBU9gHIOFZuE3y0oUklFuK6jOhjgQnxeo58Rb00g3p7R+YcpI1i95TAoIQ/tYScjnZzByQv+ak1BjgfOjMbEeEQl6kvi2axqTEnFcg0IHu6wAAA8iqDGUDqgxlAwAAAAdzc2gtcnNhAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7rAAAAAwEAAQAAAQATZEw6H2xE1Y8yRTocLCF+fUo/lOjrOt22096veUHgZk73bHyMEp33Tmw8Ag6BQkEOY7/+VsFVW/aVPfKpalb2/mJ1P7JVE9Wjny1ye/Te57NmhGU+LjkeVf7nfXiSqzpswdEisnL0AKkUz2vyP2vi+YeH6cPIyjvOuIMcdyrVakejnGbss19ZoXw660X/7TRqG/41KhTmlkN610JBKI2Rozecx9l3LZ3CTRpOOJ2sfssegvL+qxvvH1YVkRat4dwNZxsi+chozqWOciXrbzifBghBp0Upe5fgR2JRpyB6sMVXIHKkeP9YBQUARm1ECdbdJmPSiNYPgMKpTaEObMahAAAAgCtugmDSAwIPibrD9MAbJB6KbN15heA6vTtCLOvFe1Hikw94DYAJz+vlKadbOZW5SfGAOuIe7IynafthWm4RcbXEXxhnVtqHxzMHOZo/Mnoh+bUOesDSoERyNHokpNK6m1NKbmQeFj4n7rkcrR8hrwX8+Ng8CsBEglDi+ULtVivbAAAAgQD1vEPRUu9aD7CjkYgDyD2vNRRevARf01ImgT1tpiEA+GLHJ0xMetd7OH0wutAZuH26V19Kt4sWpsTwfdl2fIw7XHPc+G1OSqiOk6AS9qT/sy/VL1Wn7CqyAN2jikznquE6MbebTUJQSNHK9vQhn+u4hUDdEoMOLTYdWxxcjdJirQAAAIEA0VsOxBRDSTLcAr0Y97oCmb/6tU9XGAZwL2E14GVK85PnJNwHrx4aqb0qATE4iPLfE7ms+eBtT8UjHF0fxM3KDQiFSrvtgM4JjGTDS4dTYIBD/eQ0/aTaRgLOQqplyBgYVr3x7ATfcIP5961TfdiJ/QESutdb1KQquFXIMRII4vcAAAAPdGVzdDJAcGlja3kuY29tAQIDBA==-----END OPENSSH PRIVATE KEY-----";

        let private_key: SshPrivateKey = SshPrivateKeyParser::decode(ssh_private_key.as_bytes(), None).unwrap();

        println!("{:?}", &private_key);
        assert_eq!("test2@picky.com".to_owned(), private_key.comment);
        assert_eq!(
            Kdf::construct("none".to_owned(), KdfOption::construct(Vec::new(), 0)),
            private_key.kdf
        );
        assert_eq!("none", private_key.cipher_name);
    }

    #[test]
    fn decode_without_passphrase_4096() {
        // ssh-keygen -t rsa -b 4096 -C "test@picky.com" (without the passphrase)
        let ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcnNhAAAAAwEAAQAAAgEA21AiuHR9Z+HThQb/7I3zJmuKuanu0mePY9hjgxiq/A7nmTFmC03JOtblDDJVQU918l+pnul+FrAaIo80Fr4MKSwhk6pYUE57ZuRaYVxx5CsRb4zIT8wpxzUvi9Hm83sHHnLGOa7YMPugYRcHWRoRQX4n9f+rPau8u/vBnt4VCBKi3YjAw88XOusyGltuo2cTuATB7iqe15Z9iXg47ER789LwTQHXTn5L7afoDO9jh+LZvcEv1fG1TmevKFNKLPA7ohBp8AOUZ4zo2hXR1rdZg/Afp0SDcSPM2MkHKqd7eKeedj9Ba4b44IsYuu0cmsdA1DbszdjKUNDkVIEZH8v8VryJlLHj/wX6rzYlpBQFhzQw0rHOdFpq/oNCYnBtoKMBy2D8SkYyyGzqviYMR6xOE3WgNjSaHlKaSYFlOMrhpeX8dRvgXHa9AvpbDI9eB6fmhmoxDi0OzKtx81hKMfRtSoDeK9uujKH3fE+L64xeiWvRPqadKV4BL9nL7WCSz9Knax1mn295VrD+ISVp7/zWlz+mQMYhHh7IoK2PfJJoGWx5v+gJogSe2ykP0vz3pWI95ky9GmJBhe/albQM0pe8iPclch7Je3beY3ZqeviKH7hLTX5wHH6Gki7tDo6LafVQTL4peqI0nGyTSwS/LRjePrqyHLDVL1YwDp8HN56LYSsAAAdIA4ihRQOIoUUAAAAHc3NoLXJzYQAAAgEA21AiuHR9Z+HThQb/7I3zJmuKuanu0mePY9hjgxiq/A7nmTFmC03JOtblDDJVQU918l+pnul+FrAaIo80Fr4MKSwhk6pYUE57ZuRaYVxx5CsRb4zIT8wpxzUvi9Hm83sHHnLGOa7YMPugYRcHWRoRQX4n9f+rPau8u/vBnt4VCBKi3YjAw88XOusyGltuo2cTuATB7iqe15Z9iXg47ER789LwTQHXTn5L7afoDO9jh+LZvcEv1fG1TmevKFNKLPA7ohBp8AOUZ4zo2hXR1rdZg/Afp0SDcSPM2MkHKqd7eKeedj9Ba4b44IsYuu0cmsdA1DbszdjKUNDkVIEZH8v8VryJlLHj/wX6rzYlpBQFhzQw0rHOdFpq/oNCYnBtoKMBy2D8SkYyyGzqviYMR6xOE3WgNjSaHlKaSYFlOMrhpeX8dRvgXHa9AvpbDI9eB6fmhmoxDi0OzKtx81hKMfRtSoDeK9uujKH3fE+L64xeiWvRPqadKV4BL9nL7WCSz9Knax1mn295VrD+ISVp7/zWlz+mQMYhHh7IoK2PfJJoGWx5v+gJogSe2ykP0vz3pWI95ky9GmJBhe/albQM0pe8iPclch7Je3beY3ZqeviKH7hLTX5wHH6Gki7tDo6LafVQTL4peqI0nGyTSwS/LRjePrqyHLDVL1YwDp8HN56LYSsAAAADAQABAAACAC7OXIqnefhIzx7uDoLLDODfRN05Mlo/de/mR967zgo7mBwu2cuBz3e6U2oV9/IXZmHTHt1mkd1/uiQ0Efbkmq3S2FuumGiTR2z/QXbUBw6eTntTPZEiTqxQYpRhuPuv/yX1cu7urP9PRLxT8OKIWLR0m0y6Qy7HT2GDaqBgX3a4m3/SZumjch7GAYx0hRlkr2Wvxj/xYrM6UBKd0PBD8XxpQZX91ZjQBZ50HmdcVA61UKlZ6L6tdneEU3K0y/jpUKDXBfUOnoa3IR8iVwWPXhB1mBvX2IG2FUsTJG9rDUQD6iLsfybWyJkLtrx2TIuQCPsBuep44Tz8SC7s2pLZs0HeihnrM5YmqprMggvZ1TkVFoR3bq/42XO6ULy5k8QPuP6t91UN5iVljgr8H/6Jo9MuCeRA45ZPZN94Cn1mKJWYamrqRuCqDR5za3A0oHPKYUAfzzD90BLL6Yaib75VpiEDTkOiBuW3MJUcJsqZipDDl/6eas2Qyloplw60dx42FzcRIDXkXzRNn8hBSy7xmQ5MOKGBszCeV/eTBtRITQN38yDVMerb8xDlwOsTtjo3PHCg4HEqqSzjv/B0op9aP7RJ8zp9xLOGlxRZ9YhAlHctUOO6ATsv4uCFwCniZbVOdcUEYwNebYQ0x3IRGUF6RpqjOudUwgLlo0Lq1KV05fM5AAABAC7fkAB4l5YMAseu+lcj+CwHySzcI+baRFCrMIKldNjEPvvZcCSOU/n5pgp2bw0ulw8c4mFQv0GsG//qQCBX1IrIWO0/nRBjEUTPIe2BUswoxm3+F7pirphdIpABKMzV7ZvENn53p2ByrW9+uiwwXLo/z4tH18JW41Jyp5mXH2+1iWIYzq5d4gVgMKLGnqWG3DisViHBGg/ExxQCayeXAhlcXVaWZiaVYsgyreaQg58S2RRUIveWP+ZAeb8+ZJ72ZjIYLc0GIbP673GpcNWkRlCykTJXF9x+Ts0trffqvSxF+2YJnaacLSWJmWFU1BsxUO2pIM4SI8VeHYBdEoAVqcQAAAEBAPUodhyNIr8dtcJona8Lkn+3BxLdvYAV1bnlWnUcG9m0RQ2L95kH6folOG00aWhRgJHFDoXcCaHND8Mg3PkAXYUKCucipiIITyd8YeYnF0ckau5GmUEzwc6s4HcGyFilX1yBoyLE7hFMzOJ4+Rcq+zpD2TfaWcuoo+njDWEHeTbzvGIDQoBYsPnGOtw57q9IA5oWYAG3LtwygazmNF2xeEnMEtYPyPu7+W0teO0QIJiHWEuK/yLPOb+RHBfA6YJ1f9Jcgc614DxyW6qnB5YuzQBovLzgp/7j9J4Z9F8n8f9PAwYScf7IG8icVVhl5NwNgfNOpcjdg6+YB8Z0AXa4dYcAAAEBAOUDEl6yS1nwZ0QsJwfHE232dpsOqxxqfV4ei4R8/obq+b5YPHiUgbt2PlHyHtgfQr639BwMmIaAMSR9CLti44Mw6Z3k2DEz3Ef4+XilPeScNiZmWfYanWmVwFEtb2c+YT3QweUH3DUAViHL+UdU7xp+zhkrd04daVPpYc9NNN9b9Gwmj6Pm0RP05UJxsG1ipvN1rGpaCsJiLfS9IoSsKh0Vzdzdty1YvFhEErTl0WBVGGK6xaA5lfMtaclWi2mGGNXfWflyQzkz87eYlPe2RhM7jW1Lo9h1BBYE6R+jKt3q0mHwRehj+updAAXJx0RWF7EDQVJtlTfSrUCm+SSFoD0AAAAOdGVzdEBwaWNreS5jb20BAgMEBQ==-----END OPENSSH PRIVATE KEY-----";

        let private_key: SshPrivateKey = SshPrivateKeyParser::decode(ssh_private_key.as_bytes(), None).unwrap();

        println!("{:?}", &private_key);
        assert_eq!("test@picky.com".to_owned(), private_key.comment);
        assert_eq!(
            Kdf::construct("none".to_owned(), KdfOption::construct(Vec::new(), 0)),
            private_key.kdf
        );
        assert_eq!("none", private_key.cipher_name);
    }

    #[test]
    fn decode_with_passphrase_2048() {
        // ssh-keygen -t rsa -b 2048 -C "test_with_pass2@picky.com"
        let passphrase = Some("123123");
        let ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBIMsVovOqXSrZa+iEvQwXzAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCkR5WaC3NTPZdj9X/bX88YYbR2k5r3aE+I/ezxzbG6xIJi+So9AohypAhReyW97XSGut5n6a9O+n/c9nCiXFVoyXbMSdM90Av5bu799+V4w3kBlRzN5D3A6uIZRjglwc3Xso9kthneNByB7OjZuSDdmuWE3YOgmW0TirP3dztbtVScLPZUSsEveIMt90awuOFWaEUshqb7l713bdEB0Tb77Z1wZpt6UmIgpraV58kN/ahepbY8lirMS4ym75wtBe6PgyKGKIR3aNQdbfHYMHCgxNQMAFUt2yD9f+JE5HWG7kyKDcLTHCY60dtKTNfpcByi4Bwm3209V4rGYSKAzFXvAAAD0CdYEpFE8Dda2GBNy1l5vDNdbyJvx7SSP49l4OmHsgRE2WneNC9CfO2IxPRNXsPEmXimeubqm6alsmJ1Ch+KsdjvyU7WIEnjuonClLWx6rhsuppJqZSICbikMUXjhlHpLirGnL0WoaBnLYEVYgu8cMbIgE9BNho+bS+1qvyIrIdIblJwwc66CJKUYPz1yRA84WIMZOWlsYfeHnCvTGjiYUG2YFayVAuXvAz/ND3bQYUlO34XOOsJvZxfQNEg1/tzhB7RvcGOG1InoQxT6dZtTp85CkTU/QQ6w2eYj4qDDmsFm/eSDgEFfOJDLrfHsB4+G2aBZLmgk2bn7vo3JBkcPAETX6kKd7bkyEfhLVph9i48vbmNJ8mXWiXMoRXqRgkKqBAMVnuXtbKVDVzzlZXIFu1cbuKyt0zUg7jBIeIdG+5U0L6qygTjOKU6aP+dK1wRc0XyC8jxTJupt2eTEKBLzy4TwlLH5QhEcj1ccoV97PyslJ/NnQx8IKflHxxxQF4CbYgyXt9fWZpBfaD9TVWgsFoKrlZ9HOb6s5WJMwijgNLfllKNkJB/KpQUIwMAqEjkfk4HyKeC9sfCHkjkXoZO28GypRR8Bd5M+/QfotFvcdRHqbvv+mj1y6nBIv0hv5eqJEil5s/dwGI7cexMGBjPVOPK63kbh6JlMcrb58jKid1VTzUbxxKm6YfL2aQpGp/veGPZRkm+x3DHoANYLYJ64WRQgBOGcf4QSqiTxP9Y5ZxfQuheDzOkiQCt3ToTWwguXtVLm3AAUKxUhHVgMy2PQNFXcNsPWGCzhOW1FzC82iZhuQi7SlTX7iA40np23nMkHu37hkHpfpipySxEIIjv1T0UglqN25hPlHDIjrTRwcBVxikVhP0IFbDUtlmqSP5MkDEE2ZKTeD0ivd8c2WLO5RUoEICaTVHOx+MxOJ9L07ZhA2NMKiMMqhe0bXwZoFFHMUxXh8+iTTy89oE1PQ7xz/d6hJUtbqJ/N2xpcWMNtnvbjWpxzwhjPGiqKx8GCtpGoAjpUeNqWL9V0a20rJBYqzJGLYfKDd+PW2XTtOHbQwl0DFNq41jP4nYnaFo2YCjWb3mleRUWkU5SoUHq+vUvs4dxqKjlzvKnK5pcyH9bnpKPaBI28QHtye7o25AfkOj7eHVSe5CV4u8okVaBEq1OFhBeWm+jx1fBrk82hEGamuq1GZsZre2y9jauusOFcMXrV5oxJjBLLbGCi0i5ES0O+kBOlB/kY3hdkReCHCJlMN7v92mkSsadahzwx3fTQWCwgVDg6LLN+xCPGFTMts4XDwg=-----END OPENSSH PRIVATE KEY-----";

        let private_key: SshPrivateKey = SshPrivateKeyParser::decode(ssh_private_key.as_bytes(), passphrase).unwrap();

        println!("{:?}", &private_key);
        assert_eq!("test_with_pass2@picky.com".to_owned(), private_key.comment);
        assert_eq!(
            Kdf::construct(
                "bcrypt".to_owned(),
                KdfOption::construct(
                    vec![72, 50, 197, 104, 188, 234, 151, 74, 182, 90, 250, 33, 47, 67, 5, 243],
                    16
                )
            ),
            private_key.kdf
        );
        assert_eq!("aes256-ctr", private_key.cipher_name);
    }

    #[test]
    fn encode_without_passphrase_2048() {
        // ssh-keygen -t rsa -b 2048 -C "test2@picky.com" (without the passphrase)
        let ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAyPYbdoNqjj4EhuYblWIxVKLsmsOff+kLkKlFRsIJyE5YUWzPm5LyUH3LoqnL/rw/f/Og37oJO/bEn4P2lSvlf6ZagAGaLo8/8ACw4xKYUsQFHAEfreIthd/T2u9TEnN+yPS99M99bXG2tV+6He4c61TJfYrq5DsgQuMXCFmtR/IdJg8qF8lj06qEzjQ1HvXQdXruhm4sQn1HMb3VbdKQFSU3TpmzVysEaOVl3zK7KirBU9gHIOFZuE3y0oUklFuK6jOhjgQnxeo58Rb00g3p7R+YcpI1i95TAoIQ/tYScjnZzByQv+ak1BjgfOjMbEeEQl6kvi2axqTEnFcg0IHu6wAAA8iqDGUDqgxlAwAAAAdzc2gtcnNhAAABAQDI9ht2g2qOPgSG5huVYjFUouyaw59/6QuQqUVGwgnITlhRbM+bkvJQfcuiqcv+vD9/86Dfugk79sSfg/aVK+V/plqAAZoujz/wALDjEphSxAUcAR+t4i2F39Pa71MSc37I9L30z31tcba1X7od7hzrVMl9iurkOyBC4xcIWa1H8h0mDyoXyWPTqoTONDUe9dB1eu6GbixCfUcxvdVt0pAVJTdOmbNXKwRo5WXfMrsqKsFT2Acg4Vm4TfLShSSUW4rqM6GOBCfF6jnxFvTSDentH5hykjWL3lMCghD+1hJyOdnMHJC/5qTUGOB86MxsR4RCXqS+LZrGpMScVyDQge7rAAAAAwEAAQAAAQATZEw6H2xE1Y8yRTocLCF+fUo/lOjrOt22096veUHgZk73bHyMEp33Tmw8Ag6BQkEOY7/+VsFVW/aVPfKpalb2/mJ1P7JVE9Wjny1ye/Te57NmhGU+LjkeVf7nfXiSqzpswdEisnL0AKkUz2vyP2vi+YeH6cPIyjvOuIMcdyrVakejnGbss19ZoXw660X/7TRqG/41KhTmlkN610JBKI2Rozecx9l3LZ3CTRpOOJ2sfssegvL+qxvvH1YVkRat4dwNZxsi+chozqWOciXrbzifBghBp0Upe5fgR2JRpyB6sMVXIHKkeP9YBQUARm1ECdbdJmPSiNYPgMKpTaEObMahAAAAgCtugmDSAwIPibrD9MAbJB6KbN15heA6vTtCLOvFe1Hikw94DYAJz+vlKadbOZW5SfGAOuIe7IynafthWm4RcbXEXxhnVtqHxzMHOZo/Mnoh+bUOesDSoERyNHokpNK6m1NKbmQeFj4n7rkcrR8hrwX8+Ng8CsBEglDi+ULtVivbAAAAgQD1vEPRUu9aD7CjkYgDyD2vNRRevARf01ImgT1tpiEA+GLHJ0xMetd7OH0wutAZuH26V19Kt4sWpsTwfdl2fIw7XHPc+G1OSqiOk6AS9qT/sy/VL1Wn7CqyAN2jikznquE6MbebTUJQSNHK9vQhn+u4hUDdEoMOLTYdWxxcjdJirQAAAIEA0VsOxBRDSTLcAr0Y97oCmb/6tU9XGAZwL2E14GVK85PnJNwHrx4aqb0qATE4iPLfE7ms+eBtT8UjHF0fxM3KDQiFSrvtgM4JjGTDS4dTYIBD/eQ0/aTaRgLOQqplyBgYVr3x7ATfcIP5961TfdiJ/QESutdb1KQquFXIMRII4vcAAAAPdGVzdDJAcGlja3kuY29tAQIDBA==-----END OPENSSH PRIVATE KEY-----";
        let private_key: SshPrivateKey = SshPrivateKeyParser::decode(ssh_private_key.as_bytes(), None).unwrap();

        let mut ssh_private_key_after: Vec<u8> = Vec::new();
        private_key.encode(&mut ssh_private_key_after).unwrap();

        let ssh_private_key_after = String::from_utf8(ssh_private_key_after).unwrap();
        println!("{}", &ssh_private_key_after);
        assert_eq!(ssh_private_key.to_owned(), ssh_private_key_after);
    }

    #[test]
    fn encode_with_passphrase_2048() {
        // ssh-keygen -t rsa -b 2048 -C "test_with_pass2@picky.com"
        let passphrase = Some("123123");
        let ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBIMsVovOqXSrZa+iEvQwXzAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCkR5WaC3NTPZdj9X/bX88YYbR2k5r3aE+I/ezxzbG6xIJi+So9AohypAhReyW97XSGut5n6a9O+n/c9nCiXFVoyXbMSdM90Av5bu799+V4w3kBlRzN5D3A6uIZRjglwc3Xso9kthneNByB7OjZuSDdmuWE3YOgmW0TirP3dztbtVScLPZUSsEveIMt90awuOFWaEUshqb7l713bdEB0Tb77Z1wZpt6UmIgpraV58kN/ahepbY8lirMS4ym75wtBe6PgyKGKIR3aNQdbfHYMHCgxNQMAFUt2yD9f+JE5HWG7kyKDcLTHCY60dtKTNfpcByi4Bwm3209V4rGYSKAzFXvAAAD0CdYEpFE8Dda2GBNy1l5vDNdbyJvx7SSP49l4OmHsgRE2WneNC9CfO2IxPRNXsPEmXimeubqm6alsmJ1Ch+KsdjvyU7WIEnjuonClLWx6rhsuppJqZSICbikMUXjhlHpLirGnL0WoaBnLYEVYgu8cMbIgE9BNho+bS+1qvyIrIdIblJwwc66CJKUYPz1yRA84WIMZOWlsYfeHnCvTGjiYUG2YFayVAuXvAz/ND3bQYUlO34XOOsJvZxfQNEg1/tzhB7RvcGOG1InoQxT6dZtTp85CkTU/QQ6w2eYj4qDDmsFm/eSDgEFfOJDLrfHsB4+G2aBZLmgk2bn7vo3JBkcPAETX6kKd7bkyEfhLVph9i48vbmNJ8mXWiXMoRXqRgkKqBAMVnuXtbKVDVzzlZXIFu1cbuKyt0zUg7jBIeIdG+5U0L6qygTjOKU6aP+dK1wRc0XyC8jxTJupt2eTEKBLzy4TwlLH5QhEcj1ccoV97PyslJ/NnQx8IKflHxxxQF4CbYgyXt9fWZpBfaD9TVWgsFoKrlZ9HOb6s5WJMwijgNLfllKNkJB/KpQUIwMAqEjkfk4HyKeC9sfCHkjkXoZO28GypRR8Bd5M+/QfotFvcdRHqbvv+mj1y6nBIv0hv5eqJEil5s/dwGI7cexMGBjPVOPK63kbh6JlMcrb58jKid1VTzUbxxKm6YfL2aQpGp/veGPZRkm+x3DHoANYLYJ64WRQgBOGcf4QSqiTxP9Y5ZxfQuheDzOkiQCt3ToTWwguXtVLm3AAUKxUhHVgMy2PQNFXcNsPWGCzhOW1FzC82iZhuQi7SlTX7iA40np23nMkHu37hkHpfpipySxEIIjv1T0UglqN25hPlHDIjrTRwcBVxikVhP0IFbDUtlmqSP5MkDEE2ZKTeD0ivd8c2WLO5RUoEICaTVHOx+MxOJ9L07ZhA2NMKiMMqhe0bXwZoFFHMUxXh8+iTTy89oE1PQ7xz/d6hJUtbqJ/N2xpcWMNtnvbjWpxzwhjPGiqKx8GCtpGoAjpUeNqWL9V0a20rJBYqzJGLYfKDd+PW2XTtOHbQwl0DFNq41jP4nYnaFo2YCjWb3mleRUWkU5SoUHq+vUvs4dxqKjlzvKnK5pcyH9bnpKPaBI28QHtye7o25AfkOj7eHVSe5CV4u8okVaBEq1OFhBeWm+jx1fBrk82hEGamuq1GZsZre2y9jauusOFcMXrV5oxJjBLLbGCi0i5ES0O+kBOlB/kY3hdkReCHCJlMN7v92mkSsadahzwx3fTQWCwgVDg6LLN+xCPGFTMts4XDwg=-----END OPENSSH PRIVATE KEY-----";
        let private_key: SshPrivateKey = SshPrivateKeyParser::decode(ssh_private_key.as_bytes(), passphrase).unwrap();

        let mut ssh_private_key_after: Vec<u8> = Vec::new();
        private_key.encode(&mut ssh_private_key_after).unwrap();

        let ssh_private_key_after = String::from_utf8(ssh_private_key_after).unwrap();
        println!("{}", &ssh_private_key_after);
        assert_eq!(ssh_private_key.to_owned(), ssh_private_key_after);
    }

    #[test]
    fn test_private_key_generation() {
        let private_key = SshPrivateKey::generate_ssh_private_key(2048, Option::Some("123".to_string())).unwrap();
        let mut data = Vec::new();
        private_key.encode(&mut data).unwrap();
        println!("{}", String::from_utf8(data.clone()).unwrap());
        let _: SshPrivateKey = SshPrivateKeyParser::decode(data.as_slice(), Option::Some("123")).unwrap();
    }

    #[test]
    fn kdf_option_decode() {
        let mut cursor = Cursor::new(vec![
            0, 0, 0, 24, 0, 0, 0, 16, 72, 50, 197, 104, 188, 234, 151, 74, 182, 90, 250, 33, 47, 67, 5, 243, 0, 0, 0,
            16,
        ]);
        let kdf_option: KdfOption = SshParser::decode(&mut cursor).unwrap();
        let KdfOption { salt, rounds } = kdf_option;
        assert_eq!(
            vec![72, 50, 197, 104, 188, 234, 151, 74, 182, 90, 250, 33, 47, 67, 5, 243],
            salt
        );
        assert_eq!(16, rounds);

        let mut cursor = Cursor::new(vec![0, 0, 0, 0]);
        let kdf_option: KdfOption = SshParser::decode(&mut cursor).unwrap();
        let KdfOption { salt, rounds } = kdf_option;
        assert_eq!(Vec::<u8>::new(), salt);
        assert_eq!(0, rounds);
    }

    #[test]
    fn kdf_option_encode() {
        let mut res: Vec<u8> = Vec::new();
        let kdf_option = KdfOption::construct(
            vec![72, 50, 197, 104, 188, 234, 151, 74, 182, 90, 250, 33, 47, 67, 5, 243],
            16,
        );

        kdf_option.encode(&mut res).unwrap();

        assert_eq!(
            vec![
                0, 0, 0, 24, 0, 0, 0, 16, 72, 50, 197, 104, 188, 234, 151, 74, 182, 90, 250, 33, 47, 67, 5, 243, 0, 0,
                0, 16
            ],
            res
        );

        res.clear();
        let kdf_option = KdfOption::new();

        kdf_option.encode(&mut res).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }
}
