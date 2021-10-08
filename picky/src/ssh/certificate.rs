use crate::ssh::public_key::{SshInnerPublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{ByteArray, Mpint, SshParser, SshString, SshTime};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use std::convert::TryFrom;
use std::io;
use std::io::{Cursor, Read, Write};
use std::string;
use thiserror::Error;

const RSA_CERTIFICATE_HEADER: &str = "ssh-rsa-cert-v01@openssh.com";

#[derive(Debug, Error)]
pub enum SshCertificateError {
    #[error("Can not process the certificate: {0:?}")]
    CertificateProcessingError(#[from] std::io::Error),
    #[error("Unsupported certificate type: {0}")]
    UnsupportedCertificateType(String),
    #[error("Unsupported critical option type: {0}")]
    UnsupportedCriticalOptionType(String),
    #[error("Unsupported extension type: {0}")]
    UnsupportedExtensionType(String),
    #[error("Can not parse. Expected UTF-8 valid text: {0:?}")]
    FromUtf8Error(#[from] string::FromUtf8Error),
    #[error("Invalid base64 string: {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Invalid certificate type. Expected 1 or 2 but got: {0}")]
    InvalidCertificateType(u32),
    #[error("Invalid certificate key type: {0}")]
    InvalidCertificateKeyType(String),
    #[error("Certificate had invalid public key: {0:?}")]
    InvalidPublicKey(#[from] SshPublicKeyError),
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),
}

#[derive(Debug, Clone)]
pub enum SshCertType {
    Client,
    Host,
}

impl TryFrom<u32> for SshCertType {
    type Error = SshCertificateError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SshCertType::Client),
            2 => Ok(SshCertType::Host),
            x => Err(SshCertificateError::InvalidCertificateType(x)),
        }
    }
}

impl Into<u32> for SshCertType {
    fn into(self) -> u32 {
        match self {
            SshCertType::Client => 1,
            SshCertType::Host => 2,
        }
    }
}

impl SshParser for SshCertType {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(SshCertType::try_from(stream.read_u32::<BigEndian>()?)?)
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<BigEndian>(self.clone().into())?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum SshCertificateKeyType {
    SshRsaV01,
}

#[derive(Debug)]
pub enum SshCriticalOptionType {
    ForceCommand,
    SourceAddress,
    VerifyRequired,
}

impl TryFrom<String> for SshCriticalOptionType {
    type Error = SshCertificateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "force-command" => Ok(SshCriticalOptionType::ForceCommand),
            "source-address" => Ok(SshCriticalOptionType::SourceAddress),
            "verify-required" => Ok(SshCriticalOptionType::VerifyRequired),
            _ => Err(SshCertificateError::UnsupportedCriticalOptionType(value)),
        }
    }
}

impl ToString for SshCriticalOptionType {
    fn to_string(&self) -> String {
        match self {
            SshCriticalOptionType::ForceCommand => "force-command".to_owned(),
            SshCriticalOptionType::SourceAddress => "source-address".to_owned(),
            SshCriticalOptionType::VerifyRequired => "verify-required".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct SshCriticalOption {
    option_type: SshCriticalOptionType,
    data: String,
}

impl SshParser for SshCriticalOption {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let option_type: SshString = SshParser::decode(&mut stream)?;
        let data: SshString = SshParser::decode(&mut stream)?;
        Ok(SshCriticalOption {
            option_type: SshCriticalOptionType::try_from(option_type.0)?,
            data: data.0,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        SshString(self.option_type.to_string()).encode(&mut stream)?;
        SshString(self.data.clone()).encode(&mut stream)?;
        Ok(())
    }
}

impl SshParser for Vec<SshCriticalOption> {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len() as u64;
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::new();
        while cursor.position() < len {
            res.push(SshParser::decode(&mut cursor)?);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        println!("{}", self.len());
        for critical_option in self.iter() {
            critical_option.encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum SshExtensionType {
    NoTouchRequired,
    PermitX11Forwarding,
    PermitAgentForwarding,
    PermitPortForwarding,
    PermitPty,
    PermitUserPc,
}

impl TryFrom<String> for SshExtensionType {
    type Error = SshCertificateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "no-touch-required" => Ok(SshExtensionType::NoTouchRequired),
            "permit-X11-forwarding" => Ok(SshExtensionType::PermitX11Forwarding),
            "permit-agent-forwarding" => Ok(SshExtensionType::PermitAgentForwarding),
            "permit-port-forwarding" => Ok(SshExtensionType::PermitPortForwarding),
            "permit-pty" => Ok(SshExtensionType::PermitPty),
            "permit-user-rc" => Ok(SshExtensionType::PermitUserPc),
            _ => Err(SshCertificateError::UnsupportedExtensionType(value)),
        }
    }
}

impl ToString for SshExtensionType {
    fn to_string(&self) -> String {
        match self {
            SshExtensionType::NoTouchRequired => "no-touch-required".to_owned(),
            SshExtensionType::PermitUserPc => "permit-user-rc".to_owned(),
            SshExtensionType::PermitPty => "permit-pty".to_owned(),
            SshExtensionType::PermitAgentForwarding => "permit-agent-forwarding".to_owned(),
            SshExtensionType::PermitPortForwarding => "permit-port-forwarding".to_owned(),
            SshExtensionType::PermitX11Forwarding => "permit-X11-forwarding".to_owned(),
        }
    }
}

impl SshParser for SshExtensionType {
    type Error = SshCertificateError;

    fn decode(stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(SshExtensionType::try_from(SshString::decode(stream)?.0)?)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        SshString(self.to_string()).encode(stream)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SshExtension {
    extension_type: SshExtensionType,
    data: String,
}

impl SshParser for SshExtension {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let extension_type: SshString = SshParser::decode(&mut stream)?;
        let data: SshString = SshParser::decode(&mut stream)?;
        Ok(SshExtension {
            extension_type: SshExtensionType::try_from(extension_type.0)?,
            data: data.0,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        SshString(self.extension_type.to_string()).encode(&mut stream)?;
        SshString(self.data.clone()).encode(&mut stream)?;
        Ok(())
    }
}

impl SshParser for Vec<SshExtension> {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len() as u64;
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::new();
        while cursor.position() < len {
            res.push(SshParser::decode(&mut cursor)?);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        println!("{}", self.len());
        for critical_option in self.iter() {
            critical_option.encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

impl SshParser for Vec<String> {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len() as u64;
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::new();
        while cursor.position() < len {
            res.push(SshString::decode(&mut cursor)?.0);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for s in self.iter() {
            SshString(s.clone()).encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SshCertificate {
    key_type: SshCertificateKeyType,
    public_key: SshPublicKey,
    nonce: ByteArray,
    serial: u64,
    cert_type: SshCertType,
    key_id: String,
    valid_principals: Vec<String>,
    valid_after: SshTime,
    valid_before: SshTime,
    critical_options: Vec<SshCriticalOption>,
    extensions: Vec<SshExtension>,
    signature_key: SshPublicKey,
    signature: Vec<u8>,
    comment: String,
}

impl SshCertificate {
    pub fn from_pem_str(pem: &str) -> Result<Self, SshCertificateError> {
        SshParser::decode(pem.as_bytes())
    }

    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<Self, SshCertificateError> {
        let mut slice = raw.as_ref();
        SshParser::decode(&mut slice)
    }

    pub fn to_pem(&self) -> Result<String, SshCertificateError> {
        let buffer = self.to_raw()?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, SshCertificateError> {
        let mut cursor = Cursor::new(Vec::with_capacity(1024));
        self.encode(&mut cursor)?;
        Ok(cursor.into_inner())
    }
}

impl SshParser for SshCertificate {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut read_to_buffer_till_whitespace = |buffer: &mut Vec<u8>| -> io::Result<()> {
            loop {
                match stream.read_u8() {
                    Ok(symbol) => {
                        if symbol as char == ' ' {
                            break;
                        } else {
                            buffer.push(symbol);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        break;
                    }
                    Err(e) => return Err(e),
                };
            }
            Ok(())
        };
        let mut cert_type = Vec::new();
        read_to_buffer_till_whitespace(&mut cert_type)?;
        match String::from_utf8(cert_type)?.as_str() {
            RSA_CERTIFICATE_HEADER => {}
            cert_type => return Err(SshCertificateError::UnsupportedCertificateType(cert_type.to_owned())),
        };
        let mut cert_data = Vec::new();
        read_to_buffer_till_whitespace(&mut cert_data)?;

        let cert_data = base64::decode(cert_data)?;
        let mut cursor = Cursor::new(cert_data);

        let cert_key_type: SshString = SshParser::decode(&mut cursor)?;
        let cert_key_type = match cert_key_type.0.as_str() {
            RSA_CERTIFICATE_HEADER => SshCertificateKeyType::SshRsaV01,
            cert_key_type => return Err(SshCertificateError::InvalidCertificateKeyType(cert_key_type.to_owned())),
        };

        let nonce: ByteArray = SshParser::decode(&mut cursor)?;

        let inner_public_key = match &cert_key_type {
            SshCertificateKeyType::SshRsaV01 => {
                let e: Mpint = SshParser::decode(&mut cursor)?;
                let n: Mpint = SshParser::decode(&mut cursor)?;
                SshInnerPublicKey::Rsa(RsaPublicKey::new(
                    BigUint::from_bytes_be(&n.0),
                    BigUint::from_bytes_be(&e.0),
                )?)
            }
        };

        let serial = cursor.read_u64::<BigEndian>()?;
        let cert_type: SshCertType = SshParser::decode(&mut cursor)?;

        let key_id: SshString = SshParser::decode(&mut cursor)?;

        let valid_principals: Vec<String> = SshParser::decode(&mut cursor)?;

        let valid_after: SshTime = SshParser::decode(&mut cursor)?;
        let valid_before: SshTime = SshParser::decode(&mut cursor)?;

        let critical_options: Vec<SshCriticalOption> = SshParser::decode(&mut cursor)?;

        let extensions: Vec<SshExtension> = SshParser::decode(&mut cursor)?;

        let _: ByteArray = SshParser::decode(&mut cursor)?;

        // here is public key
        let signature_key: ByteArray = SshParser::decode(&mut cursor)?;
        let signature_public_key: SshInnerPublicKey = SshParser::decode(signature_key.0.as_slice())?;

        let signature: ByteArray = SshParser::decode(&mut cursor)?;

        let mut comment = Vec::new();
        read_to_buffer_till_whitespace(&mut comment)?;

        Ok(SshCertificate {
            key_type: cert_key_type,
            public_key: SshPublicKey::from_inner(inner_public_key),
            nonce,
            serial,
            cert_type,
            key_id: key_id.0,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: SshPublicKey::from_inner(signature_public_key),
            signature: signature.0,
            comment: String::from_utf8(comment)?,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write(RSA_CERTIFICATE_HEADER.as_bytes())?;
        stream.write_u8(' ' as u8)?;

        let mut cert_data = Vec::new();
        match &self.key_type {
            SshCertificateKeyType::SshRsaV01 => SshString(RSA_CERTIFICATE_HEADER.to_owned()).encode(&mut cert_data)?,
        };
        ByteArray(self.nonce.0.clone()).encode(&mut cert_data)?;
        match &self.public_key.inner_key {
            SshInnerPublicKey::Rsa(rsa) => {
                Mpint(rsa.e().to_bytes_be()).encode(&mut cert_data)?;
                Mpint(rsa.n().to_bytes_be()).encode(&mut cert_data)?;
            }
        };
        cert_data.write_u64::<BigEndian>(self.serial)?;
        self.cert_type.encode(&mut cert_data)?;
        SshString(self.key_id.clone()).encode(&mut cert_data)?;
        self.valid_principals.encode(&mut cert_data)?;
        self.valid_after.encode(&mut cert_data)?;
        self.valid_before.encode(&mut cert_data)?;
        self.critical_options.encode(&mut cert_data)?;
        self.extensions.encode(&mut cert_data)?;
        ByteArray(Vec::new()).encode(&mut cert_data)?;
        let mut rsa_key = Vec::new();
        self.signature_key.inner_key.encode(&mut rsa_key)?;
        ByteArray(rsa_key).encode(&mut cert_data)?;
        ByteArray(self.signature.clone()).encode(&mut cert_data)?;

        stream.write(base64::encode(cert_data).as_bytes())?;
        stream.write_u8(' ' as u8)?;

        stream.write(self.comment.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::ssh::certificate::{SshCertificate, SshCertificateError};
    use crate::ssh::SshParser;

    #[test]
    fn test_decode() {
        let cert = b"ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgRask7lW3wv86YhfVWBdm0wJ0T6AFIdoXqlQdqAK6JXgAAAADAQABAAABgQCl1TxqXj4BMygs00pZtfrsThPvA6WB9Wyi/UKTkifxhecPC2/8HoJBbqoSlm4CVPt/hLkdSbJERUCA97d4OA3Tz3uwRrQinrEC0g6eYJXhKNUHMsDd3JvNa4emI/WAp46iP4aJ/UW9lGW1YA3fgN3/dmYHBVDL7QKp/oHyZbO0JNbhhDCG7Fwp7txaWkASW4GMDBJJiQtpLe/tGYW6JMCAvrO/3Y37rXeIetvMcw1LecmWwVbRjSULqmScPKYa+n4UnwFgisdmyzNuRIZHDHXCkQIIB2K8b5wJhEQUAPvs+8gWTw00MYycAFPdgjv/CRJj7M1ZdcFydMTJlw9IoO2HNNyqo3l9SiqvrzdICrGJ5PmaakQpZMecosVW/refJMKybCOigr/11yuG2soKy7+Nbxz8AHYPhcpDCUV/6VRFmRV0CYt8qWwETqE9npWFUAal01rMqvVsDHhg6anc5wrmd9tp2k6aUMfZ135nbVmlQtZylkVyLkNvYAICZWBmJ/kAAAAAAAAAAAAAAAIAAAAHcWthdGlvbgAAABQAAAAQbWFpbi5xa2F0aW9uLmNvbQAAAABhWzTwAAAAAGGJWbAAAAAAAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQCpDY4gkD/TAvfZdSGlymgc1njCh3/Tcyoe3t5O4m32dRo54d3w4nuP4/p7UzeXMOXIoyA576CjFzbg/fBwHhxooRcXquSA5Low0W6231q0Gv2iJ0AnXIK9Xycmf4LZ8BmVukjHONH2qKBXcbIwqozAmNt50Sx2s+0EFWE8cIDu+k9pA1qeRSQijjBnaDu6xER1DgYFJa7np7kYsAusk738RiOuhjlLAFSBgJu3z5y/iiuz7fq0ZKFczmzvuokIT1c1ClaXtOfKvnjqJUewqEnkSHStt4Jg+8SZoR3w68vdgkdBjhtgYl62OcTBS9XtgDn+Tqfeu8uTAEBab2XTDWTx/TEWCV0qNp8y09DGDE/JTFSi/hrhVLAvZaUBIq3ZCwbC4xa/obTJumNV8dgWxg/yZ/hTRrza2dPoEpbmo13ekuKpXao0ecw26fGCLyLIA7wBYBqrg6/AdMzsC5efFZa2zqHET9CdXopzlHxzhvtdrUumtpIOy6LYp07uEbZNbLMAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYCaoAufe/4j7ULdd5819Xi8tYooFniH0L59WkQQPk7lL/qM4m4RIolx7ZNeUB7G2zEG95S99R6JfkgOiTUqMbrU2YUAi/lNjQv5ZIEx2hBrBFRciuUAuuUXJ6DVvqAf80R4+rs/7hgruEwm8cgbf490Ylu1tapoldvD9BtZopJL2hrKmoZdFtNfKWaVctvodT3u+3WS72Nlw375dBz7VhgzL2r50V6YGkhqMKqI0ym7V3bIld3PxO94pVYLwKX417+5CU6wzCceKgTrwDCgHMJlQqFZv/VrlxHpD+HIi4ND0oq5566aQAlEFSm3Fudj/Q3iVAiWUQqFtgA+mg9QJEpNXpsxwE2iMm3M5TIlOIzNy3G1Y0Ooz5yJreUKfoqgnBRsU4UOO/sBXPToDOJfg6MMkUby8t7mPCFIAZXrn/BIIJgQ03WB1I/ifOVgyw9KtzSYIENf69KrQy0VFpTXUZUKGDedEVdp1QHUiVM+5mXQYWqBe6hRD7dTH7MYNL26hm8= pavlom@manjaro";
        let cert: Result<SshCertificate, SshCertificateError> = SshParser::decode(cert.to_vec().as_slice());
        println!("{:?}", &cert);
        assert!(cert.is_ok());
    }

    #[test]
    fn test_encode() {
        let cert = b"ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgRask7lW3wv86YhfVWBdm0wJ0T6AFIdoXqlQdqAK6JXgAAAADAQABAAABgQCl1TxqXj4BMygs00pZtfrsThPvA6WB9Wyi/UKTkifxhecPC2/8HoJBbqoSlm4CVPt/hLkdSbJERUCA97d4OA3Tz3uwRrQinrEC0g6eYJXhKNUHMsDd3JvNa4emI/WAp46iP4aJ/UW9lGW1YA3fgN3/dmYHBVDL7QKp/oHyZbO0JNbhhDCG7Fwp7txaWkASW4GMDBJJiQtpLe/tGYW6JMCAvrO/3Y37rXeIetvMcw1LecmWwVbRjSULqmScPKYa+n4UnwFgisdmyzNuRIZHDHXCkQIIB2K8b5wJhEQUAPvs+8gWTw00MYycAFPdgjv/CRJj7M1ZdcFydMTJlw9IoO2HNNyqo3l9SiqvrzdICrGJ5PmaakQpZMecosVW/refJMKybCOigr/11yuG2soKy7+Nbxz8AHYPhcpDCUV/6VRFmRV0CYt8qWwETqE9npWFUAal01rMqvVsDHhg6anc5wrmd9tp2k6aUMfZ135nbVmlQtZylkVyLkNvYAICZWBmJ/kAAAAAAAAAAAAAAAIAAAAHcWthdGlvbgAAABQAAAAQbWFpbi5xa2F0aW9uLmNvbQAAAABhWzTwAAAAAGGJWbAAAAAAAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQCpDY4gkD/TAvfZdSGlymgc1njCh3/Tcyoe3t5O4m32dRo54d3w4nuP4/p7UzeXMOXIoyA576CjFzbg/fBwHhxooRcXquSA5Low0W6231q0Gv2iJ0AnXIK9Xycmf4LZ8BmVukjHONH2qKBXcbIwqozAmNt50Sx2s+0EFWE8cIDu+k9pA1qeRSQijjBnaDu6xER1DgYFJa7np7kYsAusk738RiOuhjlLAFSBgJu3z5y/iiuz7fq0ZKFczmzvuokIT1c1ClaXtOfKvnjqJUewqEnkSHStt4Jg+8SZoR3w68vdgkdBjhtgYl62OcTBS9XtgDn+Tqfeu8uTAEBab2XTDWTx/TEWCV0qNp8y09DGDE/JTFSi/hrhVLAvZaUBIq3ZCwbC4xa/obTJumNV8dgWxg/yZ/hTRrza2dPoEpbmo13ekuKpXao0ecw26fGCLyLIA7wBYBqrg6/AdMzsC5efFZa2zqHET9CdXopzlHxzhvtdrUumtpIOy6LYp07uEbZNbLMAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYCaoAufe/4j7ULdd5819Xi8tYooFniH0L59WkQQPk7lL/qM4m4RIolx7ZNeUB7G2zEG95S99R6JfkgOiTUqMbrU2YUAi/lNjQv5ZIEx2hBrBFRciuUAuuUXJ6DVvqAf80R4+rs/7hgruEwm8cgbf490Ylu1tapoldvD9BtZopJL2hrKmoZdFtNfKWaVctvodT3u+3WS72Nlw375dBz7VhgzL2r50V6YGkhqMKqI0ym7V3bIld3PxO94pVYLwKX417+5CU6wzCceKgTrwDCgHMJlQqFZv/VrlxHpD+HIi4ND0oq5566aQAlEFSm3Fudj/Q3iVAiWUQqFtgA+mg9QJEpNXpsxwE2iMm3M5TIlOIzNy3G1Y0Ooz5yJreUKfoqgnBRsU4UOO/sBXPToDOJfg6MMkUby8t7mPCFIAZXrn/BIIJgQ03WB1I/ifOVgyw9KtzSYIENf69KrQy0VFpTXUZUKGDedEVdp1QHUiVM+5mXQYWqBe6hRD7dTH7MYNL26hm8= pavlom@manjaro";
        let cert: SshCertificate = SshParser::decode(cert.to_vec().as_slice()).unwrap();
        println!("{:?}", cert);
        let mut result_cert = Vec::new();
        let res = cert.encode(&mut result_cert);
        println!("{:?}", res);
        println!("{:?}", String::from_utf8(result_cert).unwrap());
        assert!(res.is_ok());
    }
}
