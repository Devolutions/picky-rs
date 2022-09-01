use std::{
    fmt,
    io::{self, Read},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{de, ser, Deserialize, Serialize};
use uuid::Uuid;

use super::{NegoexDecode, NegoexEncode};

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

impl NegoexDecode for Guid {
    type Error = io::Error;

    fn decode(mut from: impl Read) -> Result<Self, Self::Error> {
        let mut id_bytes = [0; 16];
        from.read_exact(&mut id_bytes)?;

        Ok(Self(Uuid::from_bytes(id_bytes)))
    }
}

impl<'de> de::Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Guid;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid Guid identifier")
            }

            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Guid(Uuid::from_bytes_le(v.to_le_bytes())))
            }
        }

        deserializer.deserialize_u128(Visitor)
    }
}

impl ser::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u128(u128::from_le_bytes(self.0.to_bytes_le()))
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    InitiatorNego,
    AcceptorNego,
    InitiatorMetaData,
    AcceptorMetaData,
    Challenge,
    ApRequest,
    Verify,
    Alert,
}

// impl NegoexDecode for MessageType {
//     type Error = io::Error;

//     fn decode(mut from: impl Read) -> Result<Self, Self::Error> {
//         match from.read_u32::<BigEndian>()? {
//             0 => Ok(MessageType::InitiatorNego),
//             1 => Ok(MessageType::AcceptorNego),
//             2 => Ok(MessageType::InitiatorMetaData),
//             3 => Ok(MessageType::AcceptorMetaData),
//             4 => Ok(MessageType::Challenge),
//             5 => Ok(MessageType::ApRequest),
//             6 => Ok(MessageType::Verify),
//             7 => Ok(MessageType::Alert),
//             unknown_type => Err(io::Error::new(
//                 io::ErrorKind::InvalidInput,
//                 format!("Invalid MessageType value: {}", unknown_type),
//             )),
//         }
//     }
// }

// impl NegoexEncode for MessageType {
//     type Error = io::Error;

//     fn encode(&self, mut to: impl io::Write) -> Result<(), Self::Error> {
//         match self {
//             MessageType::InitiatorNego => to.write_u32::<BigEndian>(0),
//             MessageType::AcceptorNego => to.write_u32::<BigEndian>(1),
//             MessageType::InitiatorMetaData => to.write_u32::<BigEndian>(2),
//             MessageType::AcceptorMetaData => to.write_u32::<BigEndian>(3),
//             MessageType::Challenge => to.write_u32::<BigEndian>(4),
//             MessageType::ApRequest => to.write_u32::<BigEndian>(5),
//             MessageType::Verify => to.write_u32::<BigEndian>(6),
//             MessageType::Alert => to.write_u32::<BigEndian>(7),
//         }
//     }
// }

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageHeader {
    pub signature: u64,
    pub message_type: MessageType,
    pub sequence_num: u32,
    pub header_len: u32,
    pub message_len: u32,
    pub conversation_id: ConversationId,
}

// impl NegoexDecode for MessageHeader {
//     type Error = io::Error;

//     fn decode(from: impl Read) -> Result<Self, Self::Error> {
//         let header: MessageHeader = bincode::deserialize_from(from).unwrap();

//         Ok(header)
//     }
// }

// impl NegoexEncode for MessageHeader {
//     type Error = io::Error;

//     fn encode(&self, to: impl io::Write) -> Result<(), Self::Error> {
//         bincode::serialize_into(to, self).unwrap();

//         Ok(())
//     }
// }

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checksum {
    pub header_len: u32,
    pub checksum_scheme: u32,
    pub checksum_type: u32,
    pub checksum_value: ByteVector,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use crate::negoex::data_types::Guid;

    use super::{MessageHeader, MessageType, SIGNATURE, Checksum, CHECKSUM_SCHEME_RFC3961};

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

        let encoded = bincode::serialize(&message_header).unwrap();

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

        let message_header: MessageHeader = bincode::deserialize(&encoded).unwrap();

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
    fn checksum_encode() {
        let checksum = Checksum {
            header_len: 20,
            checksum_scheme: CHECKSUM_SCHEME_RFC3961,
            checksum_type: todo!(),
            checksum_value: todo!(),
        };
    }
}
