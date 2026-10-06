use crate::key::ec::{EcdsaKeypair, EcdsaPublicKey};
use crate::key::ed::{EdKeypair, EdPublicKey};
use crate::ssh::certificate::{
    SshCertType, SshCertTypeError, SshCertificate, SshCertificateError, SshCriticalOption, SshCriticalOptionError,
    SshExtension, SshExtensionError, SshSignature, SshSignatureError, Timestamp,
};
use crate::ssh::private_key::{
    AES256_CTR, AUTH_MAGIC, BCRYPT, KdfOption, NONE, SshBasePrivateKey, SshPrivateKey, SshPrivateKeyError,
};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{Base64Writer, EcCurveSshExt as _, EdAlgorithmSshExt as _, SSH_COMBO_ED25519_KEY_LENGTH, key_type};

use super::certificate::SshSignatureBlob;
use super::key_identifier;
use base64::engine::general_purpose;
use byteorder::{BigEndian, WriteBytesExt};
#[cfg(feature = "rustcrypto")]
use rsa::BoxedUint;
use std::io::{self, Write};

pub trait SshWriteExt {
    type Error;

    fn write_ssh_string(&mut self, data: &str) -> Result<(), Self::Error>;
    fn write_ssh_bytes(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn write_ssh_mpint_bytes(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    #[cfg(feature = "rustcrypto")]
    fn write_ssh_mpint(&mut self, data: &BoxedUint) -> Result<(), Self::Error>;
}

impl<T> SshWriteExt for T
where
    T: Write,
{
    type Error = io::Error;

    fn write_ssh_string(&mut self, data: &str) -> Result<(), Self::Error> {
        self.write_ssh_bytes(data.as_bytes())
    }

    fn write_ssh_bytes(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.write_u32::<BigEndian>(
            u32::try_from(data.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SSH field is too large"))?,
        )?;
        self.write_all(data)
    }

    fn write_ssh_mpint_bytes(&mut self, mut data: &[u8]) -> Result<(), Self::Error> {
        while data.first() == Some(&0) {
            data = &data[1..];
        }
        let size = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SSH mpint is too large"))?;
        // If the most significant bit would be set for
        // a positive number, the number MUST be preceded by a zero byte.
        if size > 0 && data[0] & 0b10000000 != 0 {
            self.write_u32::<BigEndian>(
                size.checked_add(1)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SSH mpint is too large"))?,
            )?;
            self.write_u8(0)?;
        } else {
            self.write_u32::<BigEndian>(size)?;
        }
        self.write_all(data)
    }

    #[cfg(feature = "rustcrypto")]
    fn write_ssh_mpint(&mut self, data: &BoxedUint) -> Result<(), Self::Error> {
        self.write_ssh_mpint_bytes(&data.to_be_bytes_trimmed_vartime())
    }
}

pub trait SshComplexTypeEncode {
    type Error;

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

impl SshComplexTypeEncode for SshCertType {
    type Error = SshCertTypeError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<BigEndian>((*self).into())?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshCriticalOption {
    type Error = SshCriticalOptionError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_ssh_string(self.option_type.as_str())?;
        let mut data = Vec::new();
        match self.option_type {
            super::certificate::SshCriticalOptionType::ForceCommand
            | super::certificate::SshCriticalOptionType::SourceAddress => data.write_ssh_string(&self.data)?,
            super::certificate::SshCriticalOptionType::VerifyRequired if self.data.is_empty() => {}
            super::certificate::SshCriticalOptionType::VerifyRequired => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "nonempty SSH critical flag").into());
            }
        }
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl<T> SshComplexTypeEncode for Vec<T>
where
    T: SshComplexTypeEncode,
    T::Error: From<std::io::Error>,
{
    type Error = T::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for elem in self.iter() {
            elem.encode(&mut data)?;
        }
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshExtension {
    type Error = SshExtensionError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_ssh_string(self.extension_type.as_str())?;
        stream.write_ssh_string(self.data.as_str())?;
        Ok(())
    }
}

impl SshComplexTypeEncode for Vec<String> {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for s in self.iter() {
            data.write_ssh_string(s)?;
        }
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshSignature {
    type Error = SshSignatureError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        super::certificate::SshSignatureFormat::new(self.format.as_str())?;
        let sk_format = matches!(
            self.format,
            super::certificate::SshSignatureFormat::SkEd25519
                | super::certificate::SshSignatureFormat::SkEcdsaSha2NistP256
        );
        if sk_format != matches!(self.blob, SshSignatureBlob::Sk { .. }) {
            return Err(SshSignatureError::UnsupportedSignatureFormat(
                self.format.as_str().to_owned(),
            ));
        }
        let mut encoded = Vec::new();
        encoded.write_ssh_string(self.format.as_str())?;

        match &self.blob {
            SshSignatureBlob::Standard(data) => {
                encoded.write_ssh_bytes(data)?;
            }
            SshSignatureBlob::Sk { data, flags, counter } => {
                encoded.write_ssh_bytes(data)?;
                encoded.write_u8(*flags)?;
                encoded.write_u32::<BigEndian>(*counter)?;
            }
        };

        stream.write_ssh_bytes(&encoded)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for KdfOption {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        if self.salt.is_empty() {
            stream.write_u32::<BigEndian>(0)?;
            return Ok(());
        }
        let mut data = Vec::new();
        data.write_ssh_bytes(&self.salt)?;
        data.write_u32::<BigEndian>(self.rounds)?;
        stream.write_ssh_bytes(&data)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for Timestamp {
    type Error = io::Error;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u64::<BigEndian>(self.0)?;
        Ok(())
    }
}

impl SshComplexTypeEncode for SshBasePublicKey {
    type Error = SshPublicKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_ssh_string(self.key_type()?)?;
        self.encode_body(stream)
    }
}

impl SshBasePublicKey {
    pub(crate) fn key_type(&self) -> Result<&'static str, SshPublicKeyError> {
        let key_type = match self {
            Self::Rsa(_) => key_type::RSA,
            Self::Ec(key) => EcdsaPublicKey::try_from(key)?.curve().to_ecdsa_ssh_key_type()?,
            Self::Ed(key) => EdPublicKey::try_from(key)?.algorithm().to_ed_ssh_key_type()?,
            Self::SkEcdsaSha2NistP256 { .. } => key_type::SK_ECDSA_SHA2_NIST_P256,
            Self::SkEd25519 { .. } => key_type::SK_ED25519,
        };
        #[cfg(feature = "fips")]
        if matches!(self, Self::SkEcdsaSha2NistP256 { .. } | Self::SkEd25519 { .. }) {
            return Err(SshPublicKeyError::UnsupportedKeyType(key_type.to_owned()));
        }
        Ok(key_type)
    }

    pub(crate) fn encode_body(&self, mut stream: impl Write) -> Result<(), SshPublicKeyError> {
        self.key_type()?;
        match self {
            SshBasePublicKey::Rsa(rsa) => {
                let picky_asn1_x509::PublicKey::Rsa(rsa) = &rsa.as_inner().subject_public_key else {
                    return Err(SshPublicKeyError::InvalidEncoding);
                };
                stream.write_ssh_mpint_bytes(rsa.public_exponent.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.modulus.as_unsigned_bytes_be())?;
                Ok(())
            }
            SshBasePublicKey::Ec(ec) => {
                let key = EcdsaPublicKey::try_from(ec)?;
                stream.write_ssh_string(key.curve().to_ecdsa_ssh_key_identifier()?)?;
                stream.write_ssh_bytes(key.encoded_point())?;
                Ok(())
            }
            SshBasePublicKey::Ed(ed) => {
                let key = EdPublicKey::try_from(ed)?;
                stream.write_ssh_bytes(key.data())?;
                Ok(())
            }
            SshBasePublicKey::SkEcdsaSha2NistP256 { base_key, application } => {
                let key = EcdsaPublicKey::try_from(base_key)?;

                stream.write_ssh_string(key_identifier::ECDSA_SHA2_NIST_P256)?;
                stream.write_ssh_bytes(key.encoded_point())?;

                stream.write_ssh_string(application.as_str())?;

                Ok(())
            }
            SshBasePublicKey::SkEd25519 { base_key, application } => {
                let key = EdPublicKey::try_from(base_key)?;

                stream.write_ssh_bytes(key.data())?;

                stream.write_ssh_string(application.as_str())?;

                Ok(())
            }
        }
    }
}

impl SshComplexTypeEncode for SshPublicKey {
    type Error = SshPublicKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        // Write key type
        stream.write_all(self.inner_key.key_type()?.as_bytes())?;

        stream.write_u8(b' ')?;

        {
            let mut base64_write = Base64Writer::new(&mut stream, &general_purpose::STANDARD);
            self.inner_key.encode(&mut base64_write)?;
            base64_write.finish()?;
        }

        stream.write_u8(b' ')?;
        stream.write_all(self.comment.as_bytes())?;
        stream.write_all("\r\n".as_bytes())?;

        Ok(())
    }
}

impl SshComplexTypeEncode for SshBasePrivateKey {
    type Error = SshPrivateKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        #[cfg(feature = "fips")]
        if matches!(self, Self::SkEcdsaSha2NistP256 { .. } | Self::SkEd25519 { .. }) {
            return Err(SshPrivateKeyError::UnsupportedKeyType("security key".to_owned()));
        }
        match self {
            SshBasePrivateKey::Rsa(rsa) => {
                let picky_asn1_x509::PrivateKeyValue::Rsa(rsa) = &rsa.as_inner().private_key else {
                    return Err(SshPrivateKeyError::InvalidKeyFormat);
                };
                let rsa = &rsa.0;
                stream.write_ssh_string(key_type::RSA)?;
                stream.write_ssh_mpint_bytes(rsa.modulus.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.public_exponent.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.private_exponent.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.coefficient.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.prime_1.as_unsigned_bytes_be())?;
                stream.write_ssh_mpint_bytes(rsa.prime_2.as_unsigned_bytes_be())?;
            }
            SshBasePrivateKey::Ec(key) => {
                let keypair = EcdsaKeypair::try_from(key)?;
                self.base_public_key()?.encode(&mut stream)?;
                stream.write_ssh_mpint_bytes(keypair.secret())?;
            }
            SshBasePrivateKey::Ed(key) => {
                let keypair = EdKeypair::try_from(key)?;
                let public_key = EdPublicKey::try_from(&keypair)?;
                self.base_public_key()?.encode(&mut stream)?;

                // SSH Ed25519 key private kye field contains secret in first 32 bytes and the
                // public key copy in the last 32 bytes.
                let mut secret = Vec::with_capacity(SSH_COMBO_ED25519_KEY_LENGTH);
                secret.extend_from_slice(keypair.secret());
                secret.extend_from_slice(public_key.data());

                stream.write_ssh_bytes(&secret)?;
            }
            SshBasePrivateKey::SkEcdsaSha2NistP256 { flags, handle, .. }
            | SshBasePrivateKey::SkEd25519 { flags, handle, .. } => {
                self.base_public_key()?.encode(&mut stream)?;
                stream.write_u8(*flags)?;
                stream.write_ssh_bytes(handle)?;
                // Reserved
                stream.write_ssh_bytes(&[])?;
            }
        };

        Ok(())
    }
}

impl SshComplexTypeEncode for SshPrivateKey {
    type Error = SshPrivateKeyError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        const AES256_CTR_BLOCK_SIZE: usize = 16;
        const UNENCRYPTED_PADDING_SIZE: usize = 8;

        #[cfg(feature = "fips")]
        if self.passphrase.is_some() || self.cipher_name != NONE || self.kdf != Default::default() {
            return Err(SshPrivateKeyError::UnsupportedCipher(self.cipher_name.clone()));
        }
        if self.base_key.base_public_key()? != self.public_key.inner_key {
            return Err(SshPrivateKeyError::InvalidKeyFormat);
        }
        stream.write_all(AUTH_MAGIC.as_bytes())?;
        stream.write_u8(b'\0')?;

        if self.passphrase.is_some() {
            stream.write_ssh_string(AES256_CTR)?;
            stream.write_ssh_string(BCRYPT)?;

            let salt = &self.kdf.option.salt;
            let rounds = self.kdf.option.rounds;

            let mut kdf_options = Vec::new();
            kdf_options.write_ssh_bytes(salt)?;
            kdf_options.write_u32::<BigEndian>(rounds)?;

            stream.write_ssh_bytes(&kdf_options)?;
        } else {
            stream.write_ssh_string(NONE)?;
            stream.write_ssh_string(NONE)?;
            stream.write_ssh_string("")?;
        }

        stream.write_u32::<BigEndian>(1)?; // keys amount

        let mut public_key = Vec::new();
        self.public_key().inner_key.encode(&mut public_key)?;
        stream.write_ssh_bytes(&public_key)?;

        public_key.clear();
        let mut private_key = public_key;

        private_key.write_u32::<BigEndian>(self.check)?;
        private_key.write_u32::<BigEndian>(self.check)?;
        self.base_key.encode(&mut private_key)?;

        private_key.write_ssh_string(&self.comment)?;

        let padding_size = if self.passphrase.is_some() {
            AES256_CTR_BLOCK_SIZE
        } else {
            UNENCRYPTED_PADDING_SIZE
        };

        // add padding
        for i in 1..=(padding_size - (private_key.len() % padding_size)) {
            private_key.push(i as u8);
        }

        if let Some(passphrase) = &self.passphrase {
            super::private_key::encrypt(passphrase, &self.kdf.option, &mut private_key)?;
        }

        stream.write_ssh_bytes(&private_key)?;

        Ok(())
    }
}

impl SshComplexTypeEncode for SshCertificate {
    type Error = SshCertificateError;

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_all(self.cert_key_type.as_str().as_bytes())?;
        stream.write_u8(b' ')?;

        let mut cert_data = Base64Writer::new(stream, &general_purpose::STANDARD);
        self.encode_signed(&mut cert_data)?;
        self.signature.encode(&mut cert_data)?;
        let mut stream = cert_data.finish()?;
        stream.write_u8(b' ')?;
        stream.write_all(self.comment.as_bytes())?;
        stream.write_all("\r\n".as_bytes())?;
        Ok(())
    }
}

impl SshCertificate {
    pub(crate) fn encode_signed(&self, mut cert_data: impl Write) -> Result<(), SshCertificateError> {
        let expected_type = self.cert_key_type.subject_key_type()?;
        if self.public_key.inner_key.key_type()? != expected_type {
            return Err(SshCertificateError::InvalidCertificateKeyType(
                self.cert_key_type.as_str().to_owned(),
            ));
        }
        cert_data.write_ssh_string(self.cert_key_type.as_str())?;
        cert_data.write_ssh_bytes(&self.nonce)?;
        self.public_key.inner_key.encode_body(&mut cert_data)?;
        cert_data.write_u64::<BigEndian>(self.serial)?;

        self.cert_type.encode(&mut cert_data)?;

        cert_data.write_ssh_string(self.key_id.as_str())?;

        self.valid_principals.encode(&mut cert_data)?;
        self.valid_after.encode(&mut cert_data)?;
        self.valid_before.encode(&mut cert_data)?;
        self.critical_options.encode(&mut cert_data)?;
        self.extensions.encode(&mut cert_data)?;

        cert_data.write_ssh_bytes(&[])?; // reserved

        let mut rsa_key = Vec::new();
        self.signature_key.inner_key.encode(&mut rsa_key)?;

        cert_data.write_ssh_bytes(&rsa_key)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::SshWriteExt;
    #[cfg(feature = "rustcrypto")]
    use rsa::BoxedUint;

    #[test]
    fn ssh_string_encode() {
        let mut res = Vec::new();
        let ssh_string = "picky";

        res.write_ssh_string(ssh_string).unwrap();

        assert_eq!(vec![0, 0, 0, 5, 112, 105, 99, 107, 121], res);

        res.clear();
        let ssh_string = "";

        res.write_ssh_string(ssh_string).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[test]
    fn byte_array_encode() {
        let mut res = Vec::new();
        let byte_array = [1, 2, 3, 4, 5, 6];

        res.write_ssh_bytes(&byte_array).unwrap();

        assert_eq!(vec![0, 0, 0, 6, 1, 2, 3, 4, 5, 6], res);

        res.clear();
        let byte_array = [];

        res.write_ssh_bytes(&byte_array).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn mpint_encoding() {
        let mpint = BoxedUint::from_be_slice_vartime(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
        let mut res = Vec::new();
        res.write_ssh_mpint(&mpint).unwrap();

        assert_eq!(
            res,
            vec![0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        );

        let mpint = BoxedUint::from_be_slice_vartime(&[0x80]);
        let mut res = Vec::new();
        res.write_ssh_mpint(&mpint).unwrap();

        assert_eq!(res, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
    }
}
