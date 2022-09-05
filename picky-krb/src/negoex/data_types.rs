use std::io::{self, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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
        self.encode_with_data(offset, to, &mut[] as &mut [u8])
    }
}

// impl<'de> de::Deserialize<'de> for Guid {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: de::Deserializer<'de>,
//     {
//         struct Visitor;

//         impl<'de> de::Visitor<'de> for Visitor {
//             type Value = Guid;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("a valid Guid identifier")
//             }

//             fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
//             where
//                 E: de::Error,
//             {
//                 Ok(Guid(Uuid::from_bytes_le(v.to_le_bytes())))
//             }
//         }

//         deserializer.deserialize_u128(Visitor)
//     }
// }

// impl ser::Serialize for Guid {
//     fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
//     where
//         S: ser::Serializer,
//     {
//         serializer.serialize_u128(u128::from_le_bytes(self.0.to_bytes_le()))
//     }
// }

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

        Ok(MessageType::from_u32(from.read_u32::<BigEndian>()?).unwrap())
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, _data: impl Write) -> Result<(), Self::Error> {
        *offset += 4;
        to.write_u32::<BigEndian>(self.to_u32().unwrap())?;

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
        let signature = from.read_u64::<BigEndian>()?;
        *offset += 8;

        if signature != SIGNATURE {
            panic!("bad signature");
        }

        let message_type = MessageType::decode(offset, &mut from, message)?;

        let sequence_num = from.read_u32::<BigEndian>()?;
        *offset += 4;

        let header_len = from.read_u32::<BigEndian>()?;
        *offset += 4;

        let message_len = from.read_u32::<BigEndian>()?;
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

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        to.write_u64::<BigEndian>(self.signature)?;
        *offset += 8;

        self.message_type.encode_with_data(offset, &mut to, &mut data)?;

        to.write_u32::<BigEndian>(self.sequence_num)?;
        *offset += 4;

        to.write_u32::<BigEndian>(self.header_len)?;
        *offset += 4;

        to.write_u32::<BigEndian>(self.message_len)?;
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
        let extension_type = from.read_u32::<BigEndian>()?;
        *offset += 4;

        let extension_value = ByteVector::decode(offset, &mut from, message)?;

        Ok(Self {
            extension_type,
            extension_value,
        })
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        to.write_u32::<BigEndian>(self.extension_type)?;
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
        let header_len = from.read_u32::<BigEndian>()?;
        *offset += 4;

        let checksum_scheme = from.read_u32::<BigEndian>()?;
        *offset += 4;

        if checksum_scheme != CHECKSUM_SCHEME_RFC3961 {
            panic!("bad checksum_scheme");
        }

        let checksum_type = from.read_u32::<BigEndian>()?;
        *offset += 4;

        let checksum_value = Vec::decode(offset, &mut from, message)?;

        Ok(Self {
            header_len,
            checksum_scheme,
            checksum_type,
            checksum_value,
        })
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        to.write_u32::<BigEndian>(self.header_len)?;
        *offset += 4;

        to.write_u32::<BigEndian>(self.checksum_scheme)?;
        *offset += 4;

        to.write_u32::<BigEndian>(self.checksum_type)?;
        *offset += 4;

        self.checksum_value.encode_with_data(offset, &mut to, &mut data)?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use crate::constants::cksum_types::HMAC_SHA1_96_AES256;
    use crate::negoex::data_types::Guid;

    use super::{ByteVector, Checksum, MessageHeader, MessageType, CHECKSUM_SCHEME_RFC3961, SIGNATURE};

    #[test]
    fn message_header_encode() {
        // let message_header = MessageHeader {
        //     signature: SIGNATURE,
        //     message_type: MessageType::AcceptorNego,
        //     sequence_num: 2,
        //     header_len: 96,
        //     message_len: 112,
        //     conversation_id: Guid(Uuid::from_str("3b29075a-f391-af33-a1b4-a212249d7cb4").unwrap()),
        // };

        // let encoded = bincode::serialize(&message_header).unwrap();

        // assert_eq!(
        //     &[
        //         78, 69, 71, 79, 69, 88, 84, 83, 1, 0, 0, 0, 2, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 90, 7, 41, 59, 145,
        //         243, 51, 175, 161, 180, 162, 18, 36, 157, 124, 180
        //     ],
        //     encoded.as_slice(),
        // );
    }

    #[test]
    fn message_header_decode() {
        // let encoded = [
        //     78, 69, 71, 79, 69, 88, 84, 83, 1, 0, 0, 0, 2, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 90, 7, 41, 59, 145, 243,
        //     51, 175, 161, 180, 162, 18, 36, 157, 124, 180,
        // ];

        // let message_header: MessageHeader = bincode::deserialize(&encoded).unwrap();

        // assert_eq!(
        //     MessageHeader {
        //         signature: SIGNATURE,
        //         message_type: MessageType::AcceptorNego,
        //         sequence_num: 2,
        //         header_len: 96,
        //         message_len: 112,
        //         conversation_id: Guid(Uuid::from_str("3b29075a-f391-af33-a1b4-a212249d7cb4").unwrap()),
        //     },
        //     message_header,
        // );
    }

    #[test]
    fn t() {
        // let a: Vector<u8> = bincode::deserialize(&[1, 2, 3, 4]).unwrap();
    }

    #[test]
    fn checksum_encode() {
        // let checksum = Checksum {
        //     header_len: 20,
        //     checksum_scheme: CHECKSUM_SCHEME_RFC3961,
        //     checksum_type: HMAC_SHA1_96_AES256 as u32,
        //     checksum_value: ChecksumVector {
        //         offset: 80,
        //         count: 12,
        //         pad: 0,
        //         checksum: vec![228, 167, 112, 148, 23, 131, 204, 12, 13, 36, 58, 87],
        //     },
        // };

        // let encoded = bincode::serialize(&checksum).unwrap();

        // assert_eq!(
        //     &[
        //         //
        //     ],
        //     encoded.as_slice(),
        // )
    }
}
