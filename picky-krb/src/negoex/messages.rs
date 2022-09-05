use std::io::{self, Read, Write};

use byteorder::{ReadBytesExt, BigEndian, WriteBytesExt};

use super::{data_types::{MessageHeader, AuthScheme, AuthSchemeVector, ExtensionVector, ByteVector, Checksum, Guid}, NegoexMessage};

/// [2.2.4 Random array](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// UCHAR Random[32];
/// ```
pub const RANDOM_ARRAY_SIZE: usize = 32;

/// [2.2.6.3 NEGO_MESSAGE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     MESSAGE_HEADER Header;
///     UCHAR Random[32];
///     ULONG64 ProtocolVersion;
///     AUTH_SCHEME_VECTOR AuthSchemes;
///     EXTENSION_VECTOR Extensions;
/// } NEGO_MESSAGE;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Nego {
    pub header: MessageHeader,
    pub random: [u8; RANDOM_ARRAY_SIZE],
    pub protocol_version: u64,
    pub auth_schemes: AuthSchemeVector,
    pub extensions: ExtensionVector,
}

impl NegoexMessage for Nego {
    type Error = io::Error;

    fn size(&self) -> usize {
        self.header.size() + RANDOM_ARRAY_SIZE + 8 + self.auth_schemes.size() + self.extensions.size()
    }

    fn decode(offset: &mut usize, mut from: impl Read, _message: &[u8]) -> Result<Self, Self::Error> {
        let header: MessageHeader = NegoexMessage::decode(offset, &mut from, &[])?;

        let mut data = vec![0; header.message_len as usize];
        from.read_exact(&mut data[header.size()..])?;

        let mut random = [0; RANDOM_ARRAY_SIZE];
        from.read_exact(&mut random)?;
        *offset += 32;

        let protocol_version = from.read_u64::<BigEndian>()?;

        let auth_schemes = NegoexMessage::decode(offset, &mut from, &data)?;

        let extensions = NegoexMessage::decode(offset, &mut from, &data)?;

        Ok(Self {
            header,
            random,
            protocol_version,
            auth_schemes,
            extensions,
        })
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        self.header.encode(offset, &mut to)?;

        to.write_all(&self.random)?;

        to.write_u64::<BigEndian>(self.protocol_version)?;

        self.auth_schemes.encode_with_data(offset, &mut to, &mut data)?;

        self.extensions.encode_with_data(offset, &mut to, &mut data)?;
        
        Ok(())
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut message_header = Vec::new();
        let mut message_data = Vec::new();

        self.encode_with_data(offset, &mut message_header, &mut message_data)?;

        to.write_all(&message_header)?;
        to.write_all(&message_data)?;

        Ok(())
    }
}

/// [2.2.6.4 EXCHANGE_MESSAGE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     MESSAGE_HEADER Header;
///     AUTH_SCHEME AuthScheme;
///     BYTE_VECTOR Exchange;
/// } EXCHANGE_MESSAGE;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Exchange {
    pub header: MessageHeader,
    pub auth_scheme: AuthScheme,
    pub exchange: ByteVector,
}

impl NegoexMessage for Exchange {
    type Error = io::Error;

    fn size(&self) -> usize {
        self.header.size() + self.auth_scheme.size() + self.exchange.size()
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            header: NegoexMessage::decode(offset, &mut from, message)?,
            auth_scheme: NegoexMessage::decode(offset, &mut from, message)?,
            exchange: NegoexMessage::decode(offset, &mut from, message)?,
        })
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut message_header = Vec::new();
        let mut message_data = Vec::new();

        self.encode_with_data(offset, &mut message_header, &mut message_data)?;

        to.write_all(&message_header)?;
        to.write_all(&message_data)?;

        Ok(())
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        self.header.encode(offset, &mut to)?;

        self.auth_scheme.encode(offset, &mut to)?;

        self.exchange.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }
}

/// [2.2.6.5 VERIFY_MESSAGE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     MESSAGE_HEADER Header;
///     AUTH_SCHEME AuthScheme;
///     CHECKSUM Checksum;
/// } VERIFY_MESSAGE;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Verify {
    pub header: MessageHeader,
    pub auth_scheme: AuthScheme,
    pub checksum: Checksum,
}

impl NegoexMessage for Verify {
    type Error = io::Error;

    fn size(&self) -> usize {
        self.header.size() + self.auth_scheme.size() + self.checksum.size()
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            header: NegoexMessage::decode(offset, &mut from, message)?,
            auth_scheme: NegoexMessage::decode(offset, &mut from, message)?,
            checksum: NegoexMessage::decode(offset, &mut from, message)?,
        })
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut message_header = Vec::new();
        let mut message_data = Vec::new();

        self.encode_with_data(offset, &mut message_header, &mut message_data)?;

        to.write_all(&message_header)?;
        to.write_all(&message_data)?;

        Ok(())
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        self.header.encode(offset, &mut to)?;

        self.auth_scheme.encode(offset, &mut to)?;

        self.checksum.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }
}
