use super::SshParser;
use crate::key::PublicKey;
use crate::ssh::{Mpint, SshString};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use std::io::{self, Cursor, Read, Write};
use std::string;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshPublicKeyError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    FromUtf8Error(#[from] string::FromUtf8Error),
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Unknown key type. We only support RSA")]
    UnknownKeyType,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SshPublicKey {
    inner_key: SshInnerPublicKey,
    comment: String,
}

impl SshPublicKey {
    pub fn from_pem_str(pem: &str) -> Result<Self, SshPublicKeyError> {
        SshParser::decode(pem.as_bytes())
    }

    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<Self, SshPublicKeyError> {
        let mut slice = raw.as_ref();
        SshParser::decode(&mut slice)
    }

    pub fn to_pem(&self) -> Result<String, SshPublicKeyError> {
        let buffer = self.to_raw()?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, SshPublicKeyError> {
        let mut cursor = Cursor::new(Vec::with_capacity(1024));
        self.encode(&mut cursor)?;
        Ok(cursor.into_inner())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SshInnerPublicKey {
    Rsa(RsaPublicKey),
}

impl SshParser for SshPublicKey {
    type Error = SshPublicKeyError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error> {
        let mut buffer = Vec::with_capacity(1024);

        let mut read_to_buffer_till_whitespace = |buffer: &mut Vec<u8>| -> io::Result<()> {
            loop {
                let symbol = stream.read_u8().unwrap();
                if symbol as char == ' ' {
                    break;
                } else {
                    buffer.push(symbol);
                }
            }
            Ok(())
        };

        read_to_buffer_till_whitespace(&mut buffer).unwrap();

        let header = String::from_utf8_lossy(&buffer).to_string();
        buffer.clear();

        let inner_key = match header.as_str() {
            "ssh-rsa" => {
                read_to_buffer_till_whitespace(&mut buffer);
                let decoded = base64::decode(&mut buffer)?;
                let mut cursor = Cursor::new(decoded);

                let _: SshString = SshParser::decode(&mut cursor)?;
                let e: Mpint = SshParser::decode(&mut cursor)?;
                let n: Mpint = SshParser::decode(&mut cursor)?;

                buffer.clear();
                SshInnerPublicKey::Rsa(RsaPublicKey::new(
                    BigUint::from_bytes_be(&n.0),
                    BigUint::from_bytes_be(&e.0),
                )?)
            }
            _ => return Err(SshPublicKeyError::UnknownKeyType),
        };

        let _ = stream.read(&mut buffer)?;
        let comment = String::from_utf8(buffer)?;

        Ok(SshPublicKey { inner_key, comment })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        match &self.inner_key {
            SshInnerPublicKey::Rsa(rsa) => {
                let key_type = "ssh-rsa"; //

                stream.write_all(key_type.as_bytes())?;
                stream.write_u8(' ' as u8)?;

                let buffer = vec![0u8; 1024];
                let mut cursor = Cursor::new(buffer);

                let ssh_string = SshString(key_type.to_string());
                ssh_string.encode(&mut cursor)?;

                let e = Mpint(rsa.e().to_bytes_be());
                e.encode(&mut cursor);

                let n = Mpint(rsa.n().to_bytes_be());
                n.encode(&mut cursor);

                let buffer = cursor.into_inner();
                stream.write_all(base64::encode(buffer).as_bytes());
            }
        }

        stream.write_u8(' ' as u8)?;
        stream.write_all(self.comment.as_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::SshParser;

    const SSH_RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHtOWAdeCfP4+n8dIhqrXy8SWhhme+tupC7QiQ2VwezXSvE4Ua0B4WkPfdBIMcXl2/W89jcwnZzrgUvCoIFuctyHu0AtVm2YwWIHxxeBU0ZtrByl2lwFx8Ybobhy+RaEN2HiKDfn9CLC1zlKmXj0Edh+bkSAasQa0TTmfBfvzngqto8G1CuMOKx4TAZ3ismcEr6DlIb1iReQBq1KQYql6gPcaTm2uMujSH7Dg9N9LMQm+gYz2maLkHHrtUZKYCm0uVljtA+1eISuhSFBHHxn3O+WOn8zC6MltCg9toSksrG5uoP6xCKHMnmQOp6U60GUDYgT61IzUcscdhAzJ+iMrd sasha@sasha";

    #[test]
    fn decode_ssh_rsa_public_key() {
        let public_key: SshPublicKey = SshParser::decode(SSH_RSA_PUBLIC_KEY.as_bytes()).unwrap();
    }
}
