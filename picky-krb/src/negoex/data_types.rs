use std::io::{self, Read, Write};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{de, ser, Deserialize, Serialize, Serializer};
use uuid::Uuid;

use super::NegoexMessage;

/// [2.2.3 Constants](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// #define MESSAGE_SIGNATURE 0x535458454f47454ei64 // "NEGOEXTS"
/// ```
pub const SIGNATURE: u64 = 0x535458454f47454e;

/// [2.2.3 Constants](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)3 Constants
/// ```not_rust
/// #define CHECKSUM_SCHEME_RFC3961 1
/// ```
pub const CHECKSUM_SCHEME_RFC3961: u32 = 0x1;

#[derive(Debug, Clone, PartialEq)]
pub struct Guid(pub Uuid);

impl NegoexMessage for Guid {
    type Error = io::Error;

    fn size(&self) -> usize {
        16
    }

    fn decode(offset: &mut usize, mut from: impl Read, _message: &[u8]) -> Result<Self, Self::Error> {
        let mut id_bytes = [0; 16];
        from.read_exact(&mut id_bytes)?;
        *offset += 16;

        Ok(Self(Uuid::from_bytes_le(id_bytes)))
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, _data: impl Write) -> Result<(), Self::Error> {
        *offset += 16;

        to.write_all(&self.0.to_bytes_le())?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error> {
        self.encode_with_data(offset, to, &mut [] as &mut [u8])
    }
}

/// [2.2.2 GUID typedefs](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// typedef GUID CONVERSATION_ID;
/// ```
pub type ConversationId = Guid;

/// [2.2.2 GUID typedefs](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// typedef GUID AUTH_SCHEME;
/// ```
pub type AuthScheme = Guid;

/// [2.2.6.1 MESSAGE_TYPE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// enum
/// {
///     MESSAGE_TYPE_INITIATOR_NEGO = 0,
///     MESSAGE_TYPE_ACCEPTOR_NEGO,
///     MESSAGE_TYPE_INITIATOR_META_DATA,
///     MESSAGE_TYPE_ACCEPTOR_META_DATA,
///     MESSAGE_TYPE_CHALLENGE,
///     MESSAGE_TYPE_AP_REQUEST,
///     MESSAGE_TYPE_VERIFY,
///     MESSAGE_TYPE_ALERT
/// } MESSAGE_TYPE;
/// ```
#[derive(Debug, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum MessageType {
    InitiatorNego = 0,
    AcceptorNego = 1,
    InitiatorMetaData = 2,
    AcceptorMetaData = 3,
    Challenge = 4,
    ApRequest = 5,
    Verify = 6,
    Alert = 7,
}

impl NegoexMessage for MessageType {
    type Error = io::Error;

    fn size(&self) -> usize {
        4
    }

    fn decode(offset: &mut usize, mut from: impl Read, _message: &[u8]) -> Result<Self, Self::Error> {
        *offset += 4;

        Ok(MessageType::from_u32(from.read_u32::<LittleEndian>()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid MessageType"))?)
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, _data: impl Write) -> Result<(), Self::Error> {
        *offset += 4;
        to.write_u32::<LittleEndian>(
            self.to_u32()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "can not encode MessageType as u32"))?,
        )?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error> {
        self.encode_with_data(offset, to, &mut [] as &mut [u8])
    }
}

/// [2.2.6.2 MESSAGE_HEADER](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG64 Signature;
///     MESSAGE_TYPE MessageType;
///     ULONG SequenceNum;
///     ULONG cbHeaderLength;
///     ULONG cbMessageLength;
///     CONVERSATION_ID ConversationId;
/// } MESSAGE_HEADER;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub signature: u64,
    pub message_type: MessageType,
    pub sequence_num: u32,
    pub header_len: u32,
    pub message_len: u32,
    pub conversation_id: ConversationId,
}

impl NegoexMessage for MessageHeader {
    type Error = io::Error;

    fn size(&self) -> usize {
        8 + self.message_type.size() + 3 + 3 + 3 + self.conversation_id.size()
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        let signature = from.read_u64::<LittleEndian>()?;
        *offset += 8;

        if signature != SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid message signature: {:x?}. expected: {:x?}",
                    signature, SIGNATURE
                ),
            ));
        }

        let message_type = MessageType::decode(offset, &mut from, message)?;

        let sequence_num = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let header_len = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let message_len = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let conversation_id = ConversationId::decode(offset, &mut from, message)?;

        Ok(Self {
            signature,
            message_type,
            sequence_num,
            header_len,
            message_len,
            conversation_id,
        })
    }

    fn encode_with_data(
        &self,
        offset: &mut usize,
        mut to: impl Write,
        mut data: impl Write,
    ) -> Result<(), Self::Error> {
        to.write_u64::<LittleEndian>(self.signature)?;
        *offset += 8;

        self.message_type.encode_with_data(offset, &mut to, &mut data)?;

        to.write_u32::<LittleEndian>(self.sequence_num)?;
        *offset += 4;

        to.write_u32::<LittleEndian>(self.header_len)?;
        *offset += 4;

        to.write_u32::<LittleEndian>(self.message_len)?;
        *offset += 4;

        self.conversation_id.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error> {
        self.encode_with_data(offset, to, &mut [] as &mut [u8])
    }
}

/// [2.2.5.1.4 EXTENSION](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG ExtensionType;
///     BYTE_VECTOR ExtensionValue;
/// } EXTENSION;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    pub extension_type: u32,
    pub extension_value: ByteVector,
}

impl NegoexMessage for Extension {
    type Error = io::Error;

    fn size(&self) -> usize {
        4 + self.extension_value.len()
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        let extension_type = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let extension_value = ByteVector::decode(offset, &mut from, message)?;

        Ok(Self {
            extension_type,
            extension_value,
        })
    }

    fn encode_with_data(
        &self,
        offset: &mut usize,
        mut to: impl Write,
        mut data: impl Write,
    ) -> Result<(), Self::Error> {
        to.write_u32::<LittleEndian>(self.extension_type)?;
        *offset += 4;

        self.extension_value.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut header = Vec::new();
        let mut data = Vec::new();

        self.encode_with_data(offset, &mut header, &mut data)?;

        to.write_all(&mut header)?;
        to.write_all(&mut data)?;

        Ok(())
    }
}

/// [2.2.5.2.3 BYTE_VECTOR](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG ByteArrayOffset;
///     ULONG ByteArrayLength;
/// } BYTE_VECTOR;
/// ```
pub type ByteVector = Vec<u8>;

/// [2.2.5.2.2 AUTH_SCHEME_VECTOR](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG AuthSchemeArrayOffset;
///     USHORT AuthSchemeCount;
/// } AUTH_SCHEME_VECTOR;
/// ```
pub type AuthSchemeVector = Vec<AuthScheme>;

/// [2.2.5.2.4 EXTENSION_VECTOR](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG ExtensionArrayOffset;
///     USHORT ExtensionCount;
/// } EXTENSION_VECTOR;
/// ```
pub type ExtensionVector = Vec<Extension>;

// #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// pub struct ChecksumVector {
//     offset: u32,
//     count: u16,
//     pad: u16,
//     checksum: Vec<u8>,
// }

/// [2.2.5.1.3 CHECKSUM](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// struct
/// {
///     ULONG cbHeaderLength;
///     ULONG ChecksumScheme;
///     ULONG ChecksumType;
///     BYTE_VECTOR ChecksumValue;
/// } CHECKSUM;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Checksum {
    pub header_len: u32,
    pub checksum_scheme: u32,
    pub checksum_type: u32,
    pub checksum_value: Vec<u8>,
}

impl NegoexMessage for Checksum {
    type Error = io::Error;

    fn size(&self) -> usize {
        4 + 4 + 4 + self.checksum_value.size()
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        let header_len = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let checksum_scheme = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        if checksum_scheme != CHECKSUM_SCHEME_RFC3961 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid checksum scheme: {}. Expected: {}",
                    checksum_scheme, CHECKSUM_SCHEME_RFC3961
                ),
            ));
        }

        let checksum_type = from.read_u32::<LittleEndian>()?;
        *offset += 4;

        let checksum_value = Vec::decode(offset, &mut from, message)?;

        Ok(Self {
            header_len,
            checksum_scheme,
            checksum_type,
            checksum_value,
        })
    }

    fn encode_with_data(
        &self,
        offset: &mut usize,
        mut to: impl Write,
        mut data: impl Write,
    ) -> Result<(), Self::Error> {
        to.write_u32::<LittleEndian>(self.header_len)?;
        *offset += 4;

        to.write_u32::<LittleEndian>(self.checksum_scheme)?;
        *offset += 4;

        to.write_u32::<LittleEndian>(self.checksum_type)?;
        *offset += 4;

        self.checksum_value.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut header = Vec::new();
        let mut data = Vec::new();

        self.encode_with_data(offset, &mut header, &mut data)?;

        to.write_all(&mut header)?;
        to.write_all(&mut data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use crate::constants::cksum_types::HMAC_SHA1_96_AES256;
    use crate::negoex::data_types::Guid;
    use crate::negoex::NegoexMessage;

    use super::{Checksum, Extension, MessageHeader, MessageType, CHECKSUM_SCHEME_RFC3961, SIGNATURE};

    #[test]
    fn guid_encode() {
        let guid = Guid(Uuid::from_str("0d53335c-f9ea-4d0d-b2ec-4ae3786ec308").unwrap());

        let mut encoded = Vec::new();
        guid.encode(&mut 0, &mut encoded).unwrap();

        assert_eq!(
            &[92, 51, 83, 13, 234, 249, 13, 77, 178, 236, 74, 227, 120, 110, 195, 8],
            encoded.as_slice()
        );
    }

    #[test]
    fn guid_decode() {
        let encoded_guid = [90, 7, 41, 59, 145, 243, 51, 175, 161, 180, 162, 18, 36, 157, 124, 180];

        let guid = Guid::decode(&mut 0, &encoded_guid as &[u8], &encoded_guid).unwrap();

        assert_eq!(Uuid::from_str("3b29075a-f391-af33-a1b4-a212249d7cb4").unwrap(), guid.0);
    }

    #[test]
    fn message_type_decode() {
        let encoded = [1, 0, 0, 0];

        let message_type = MessageType::decode(&mut 0, &encoded as &[u8], &encoded).unwrap();

        assert_eq!(MessageType::AcceptorNego, message_type);
    }

    #[test]
    fn message_type_encode() {
        let message_type = MessageType::ApRequest;

        let mut encoded = Vec::new();
        message_type.encode(&mut 0, &mut encoded).unwrap();

        assert_eq!(&[5, 0, 0, 0], encoded.as_slice());
    }

    #[test]
    fn message_header_encode() {
        let message_header = MessageHeader {
            signature: SIGNATURE,
            message_type: MessageType::AcceptorNego,
            sequence_num: 2,
            header_len: 96,
            message_len: 112,
            conversation_id: Guid(Uuid::from_str("3b29075a-f391-af33-a1b4-a212249d7cb4").unwrap()),
        };

        let mut encoded = Vec::new();
        message_header.encode(&mut 0, &mut encoded).unwrap();

        assert_eq!(
            &[
                78, 69, 71, 79, 69, 88, 84, 83, 1, 0, 0, 0, 2, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 90, 7, 41, 59, 145,
                243, 51, 175, 161, 180, 162, 18, 36, 157, 124, 180
            ],
            encoded.as_slice(),
        );
    }

    #[test]
    fn message_header_decode() {
        let encoded = [
            78, 69, 71, 79, 69, 88, 84, 83, 1, 0, 0, 0, 2, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 90, 7, 41, 59, 145, 243,
            51, 175, 161, 180, 162, 18, 36, 157, 124, 180,
        ];

        let message_header = MessageHeader::decode(&mut 0, &encoded as &[u8], &encoded).unwrap();

        assert_eq!(
            MessageHeader {
                signature: SIGNATURE,
                message_type: MessageType::AcceptorNego,
                sequence_num: 2,
                header_len: 96,
                message_len: 112,
                conversation_id: Guid(Uuid::from_str("3b29075a-f391-af33-a1b4-a212249d7cb4").unwrap()),
            },
            message_header,
        );
    }

    #[test]
    fn extension_encode() {
        let extension = Extension {
            extension_type: 3,
            extension_value: vec![1, 2, 3, 4, 5, 6],
        };

        let mut encoded = Vec::new();
        extension.encode(&mut 0, &mut encoded).unwrap();

        assert_eq!(
            &[3, 0, 0, 0, 12, 0, 0, 0, 6, 0, 0, 0, 1, 2, 3, 4, 5, 6],
            encoded.as_slice()
        );
    }

    #[test]
    fn extension_decode() {
        let encoded = [3, 0, 0, 0, 12, 0, 0, 0, 6, 0, 0, 0, 1, 2, 3, 4, 5, 6];

        let extension = Extension::decode(&mut 0, &encoded as &[u8], &encoded).unwrap();

        assert_eq!(
            Extension {
                extension_type: 3,
                extension_value: vec![1, 2, 3, 4, 5, 6],
            },
            extension
        );
    }

    #[test]
    fn checksum_decode() {
        // NEGOEX VERIFY message that contains the checksum
        let negoex_verify = [
            78, 69, 71, 79, 69, 88, 84, 83, 6, 0, 0, 0, 7, 0, 0, 0, 80, 0, 0, 0, 92, 0, 0, 0, 90, 7, 41, 59, 145, 243,
            51, 175, 161, 180, 162, 18, 36, 157, 124, 180, 92, 51, 83, 13, 234, 249, 13, 77, 178, 236, 74, 227, 120,
            110, 195, 8, 20, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0, 80, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 228, 167, 112,
            148, 23, 131, 204, 12, 13, 36, 58, 87,
        ];

        // 56 - start of the Checksum struct
        let checksum = Checksum::decode(&mut 0, &negoex_verify[56..], &negoex_verify).unwrap();

        assert_eq!(
            Checksum {
                header_len: 20,
                checksum_scheme: CHECKSUM_SCHEME_RFC3961,
                checksum_type: HMAC_SHA1_96_AES256 as u32,
                checksum_value: vec![228, 167, 112, 148, 23, 131, 204, 12, 13, 36, 58, 87],
            },
            checksum
        );
    }

    #[test]
    fn checksum_encode() {
        let checksum = Checksum {
            header_len: 20,
            checksum_scheme: CHECKSUM_SCHEME_RFC3961,
            checksum_type: HMAC_SHA1_96_AES256 as u32,
            checksum_value: vec![228, 167, 112, 148, 23, 131, 204, 12, 13, 36, 58, 87],
        };

        let mut encoded = Vec::new();
        checksum.encode(&mut 0, &mut encoded).unwrap();

        assert_eq!(
            &[
                20, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0, 20, 0, 0, 0, 12, 0, 0, 0, 228, 167, 112, 148, 23, 131, 204, 12,
                13, 36, 58, 87
            ],
            encoded.as_slice(),
        )
    }
}
